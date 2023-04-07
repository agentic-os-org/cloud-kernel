// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */
#include "internal.h"
#include <linux/prefetch.h>
#include <linux/iomap.h>
#include <linux/uio.h>
#include <linux/dax.h>
#include <trace/events/erofs.h>
#include <linux/sched/mm.h>

void erofs_unmap_metabuf(struct erofs_buf *buf)
{
	if (buf->kmap_type == EROFS_KMAP)
		kunmap(buf->page);
	else if (buf->kmap_type == EROFS_KMAP_ATOMIC)
		kunmap_atomic(buf->base);
	buf->base = NULL;
	buf->kmap_type = EROFS_NO_KMAP;
}

void erofs_put_metabuf(struct erofs_buf *buf)
{
	pgoff_t index;

	if (!buf->page)
		return;
	erofs_unmap_metabuf(buf);

	index = buf->page->index;
	put_page(buf->page);
	buf->page = NULL;

#ifdef CONFIG_EROFS_FS_RAFS_V6
	if (buf->mapping) {
		buf->mapping->a_ops->endpfn(buf->mapping, index,
				&buf->iomap, 0);
		buf->mapping = NULL;
		memset(&buf->iomap, 0, sizeof(buf->iomap));
	}
#endif
}

/*
 * Derive the block size from inode->i_blkbits to make compatible with
 * anonymous inode in fscache mode.
 */
void *__erofs_bread(struct super_block *sb, struct erofs_buf *buf,
		    erofs_blk_t blkaddr, enum erofs_kmap_type type)
{
	struct inode *inode = buf->inode;
	erofs_off_t offset = (erofs_off_t)blkaddr << inode->i_blkbits;
	struct address_space *const mapping = inode->i_mapping;
	pgoff_t index = offset >> PAGE_SHIFT;
	struct page *page = buf->page;

	if (!page || page->index != index) {
		erofs_put_metabuf(buf);
#ifdef CONFIG_EROFS_FS_RAFS_V6
		if (sb && erofs_is_rafsv6_mode(sb)) {
			unsigned int nofs_flag;

			nofs_flag = memalloc_nofs_save();
			if (IS_DAX(inode)) {
				page = mapping->a_ops->startpfn(mapping, index,
								&buf->iomap);
				if (!IS_ERR(page))
					buf->mapping = mapping;
			} else {
				page = read_cache_page(mapping, index,
					       (filler_t *)mapping->a_ops->readpage,
					       EROFS_SB(sb)->bootstrap);
			}
			memalloc_nofs_restore(nofs_flag);
		} else
#endif
		{
			page = read_cache_page_gfp(mapping, index,
				   mapping_gfp_constraint(mapping, ~__GFP_FS));
		}

		if (IS_ERR(page))
			return page;
		/* should already be PageUptodate, no need to lock page */
		buf->page = page;
	}
	if (buf->kmap_type == EROFS_NO_KMAP) {
		if (type == EROFS_KMAP)
			buf->base = kmap(page);
		else if (type == EROFS_KMAP_ATOMIC)
			buf->base = kmap_atomic(page);
		buf->kmap_type = type;
	} else if (buf->kmap_type != type) {
		DBG_BUGON(1);
		return ERR_PTR(-EFAULT);
	}
	if (type == EROFS_NO_KMAP)
		return NULL;
	return buf->base + (offset & ~PAGE_MASK);
}

void *erofs_bread(struct erofs_buf *buf, erofs_blk_t blkaddr,
		  enum erofs_kmap_type type)
{
	return __erofs_bread(NULL, buf, blkaddr, type);
}

void erofs_init_metabuf(struct erofs_buf *buf, struct super_block *sb)
{
	if (erofs_is_fscache_mode(sb))
		buf->inode = EROFS_SB(sb)->s_fscache->inode;
#ifdef CONFIG_EROFS_FS_RAFS_V6
	else if (erofs_is_rafsv6_mode(sb))
		buf->inode = EROFS_SB(sb)->bootstrap->f_inode;
#endif
	else
		buf->inode = sb->s_bdev->bd_inode;

}

void *erofs_read_metabuf(struct erofs_buf *buf, struct super_block *sb,
			 erofs_blk_t blkaddr, enum erofs_kmap_type type)
{
	erofs_init_metabuf(buf, sb);
#ifdef CONFIG_EROFS_FS_RAFS_V6
	if (erofs_is_rafsv6_mode(sb))
		return __erofs_bread(sb, buf, blkaddr, type);
#endif
	return erofs_bread(buf, blkaddr, type);
}

int erofs_map_blocks(struct inode *inode, struct erofs_map_blocks *map)
{
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	struct super_block *sb = inode->i_sb;
	unsigned int unit, blksz = sb->s_blocksize;
	struct erofs_inode *vi = EROFS_I(inode);
	struct erofs_inode_chunk_index *idx;
	erofs_blk_t startblk, addrmask;
	bool tailpacking;
	erofs_off_t pos;
	u64 chunknr;
	void *kaddr;
	int err = 0;

	trace_erofs_map_blocks_enter(inode, map, 0);
	map->m_deviceid = 0;
	map->m_flags = 0;
	if (map->m_la >= inode->i_size)
		goto out;

	if (vi->datalayout != EROFS_INODE_CHUNK_BASED) {
		tailpacking = (vi->datalayout == EROFS_INODE_FLAT_INLINE);
		if (!tailpacking && vi->startblk == EROFS_NULL_ADDR)
			goto out;
		pos = erofs_pos(sb, erofs_iblks(inode) - tailpacking);

		map->m_flags = EROFS_MAP_MAPPED;
		if (map->m_la < pos) {
			map->m_pa = erofs_pos(sb, vi->startblk) + map->m_la;
			map->m_llen = pos - map->m_la;
		} else {
			map->m_pa = erofs_iloc(inode) + vi->inode_isize +
				vi->xattr_isize + erofs_blkoff(sb, map->m_la);
			map->m_llen = inode->i_size - map->m_la;
			map->m_flags |= EROFS_MAP_META;
		}
		goto out;
	}

	if (vi->chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(*idx);			/* chunk index */
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;	/* block map */

	chunknr = map->m_la >> vi->chunkbits;
	pos = ALIGN(erofs_iloc(inode) + vi->inode_isize +
		    vi->xattr_isize, unit) + unit * chunknr;

	kaddr = erofs_read_metabuf(&buf, sb, erofs_blknr(sb, pos), EROFS_KMAP);
	if (IS_ERR(kaddr)) {
		err = PTR_ERR(kaddr);
		goto out;
	}

	idx = kaddr + erofs_blkoff(sb, pos);
	map->m_la = chunknr << vi->chunkbits;
	map->m_llen = min_t(erofs_off_t, 1UL << vi->chunkbits,
			    round_up(inode->i_size - map->m_la, blksz));
	if (vi->chunkformat & EROFS_CHUNK_FORMAT_INDEXES) {
		addrmask = (vi->chunkformat & EROFS_CHUNK_FORMAT_48BIT) ?
			BIT_ULL(48) - 1 : BIT_ULL(32) - 1;
		startblk = (((u64)le16_to_cpu(idx->startblk_hi) << 32) |
			    le32_to_cpu(idx->startblk_lo)) & addrmask;
		if ((startblk ^ EROFS_NULL_ADDR) & addrmask) {
			map->m_deviceid = le16_to_cpu(idx->device_id) &
				EROFS_SB(sb)->device_id_mask;
			map->m_pa = erofs_pos(sb, startblk);
			map->m_flags = EROFS_MAP_MAPPED;
		}
	} else {
		startblk = le32_to_cpu(*(__le32 *)idx);
		if (startblk != (u32)EROFS_NULL_ADDR) {
			map->m_pa = erofs_pos(sb, startblk);
			map->m_flags = EROFS_MAP_MAPPED;
		}
	}
	erofs_put_metabuf(&buf);
out:
	if (!err) {
		map->m_plen = map->m_llen;
		/* inline data should be located in the same meta block */
		if ((map->m_flags & EROFS_MAP_META) &&
		    erofs_blkoff(sb, map->m_pa) + map->m_plen > blksz) {
			erofs_err(sb, "inline data across blocks @ nid %llu", vi->nid);
			DBG_BUGON(1);
			return -EFSCORRUPTED;
		}
	}
	trace_erofs_map_blocks_exit(inode, map, 0, err);
	return err;
}

int erofs_map_dev(struct super_block *sb, struct erofs_map_dev *map)
{
	struct erofs_dev_context *devs = EROFS_SB(sb)->devs;
	struct erofs_device_info *dif;
	int id;

	map->m_bdev = sb->s_bdev;
	map->m_daxdev = EROFS_SB(sb)->dax_dev;
#ifdef CONFIG_EROFS_FS_RAFS_V6
	map->m_fp = EROFS_SB(sb)->bootstrap;
#endif
	map->m_fscache = EROFS_SB(sb)->s_fscache;

	if (map->m_deviceid) {
		down_read(&devs->rwsem);
		dif = idr_find(&devs->tree, map->m_deviceid - 1);
		if (!dif) {
			up_read(&devs->rwsem);
			return -ENODEV;
		}
		if (devs->flatdev) {
			map->m_pa += erofs_pos(sb, dif->uniaddr);
			up_read(&devs->rwsem);
			return 0;
		}
		map->m_bdev = dif->bdev;
		map->m_daxdev = dif->dax_dev;
#ifdef CONFIG_EROFS_FS_RAFS_V6
		map->m_fp = dif->blobfile;
#endif
		map->m_fscache = dif->fscache;
		up_read(&devs->rwsem);
	} else if (devs->extra_devices && !devs->flatdev) {
		down_read(&devs->rwsem);
		idr_for_each_entry(&devs->tree, dif, id) {
			erofs_off_t startoff, length;

			if (!dif->uniaddr)
				continue;
			startoff = erofs_pos(sb, dif->uniaddr);
			length = erofs_pos(sb, dif->blocks);

			if (map->m_pa >= startoff &&
			    map->m_pa < startoff + erofs_pos(sb, dif->blocks)) {
				map->m_pa -= startoff;
				map->m_bdev = dif->bdev;
				map->m_daxdev = dif->dax_dev;
#ifdef CONFIG_EROFS_FS_RAFS_V6
				map->m_fp = dif->blobfile;
#endif
				map->m_fscache = dif->fscache;
				break;
			}
		}
		up_read(&devs->rwsem);
	}
	return 0;
}

static int erofs_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
		unsigned int flags, struct iomap *iomap, struct iomap *srcmap)
{
	int ret;
	struct super_block *sb = inode->i_sb;
	struct erofs_map_blocks map;
	struct erofs_map_dev mdev;

	map.m_la = offset;
	map.m_llen = length;

	ret = erofs_map_blocks(inode, &map);
	if (ret < 0)
		return ret;

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};
	ret = erofs_map_dev(sb, &mdev);
	if (ret)
		return ret;

	iomap->offset = map.m_la;
	iomap->bdev = mdev.m_bdev;
	iomap->dax_dev = mdev.m_daxdev;
	iomap->length = map.m_llen;
	iomap->flags = 0;
	iomap->private = NULL;

	if (!(map.m_flags & EROFS_MAP_MAPPED)) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
		if (!iomap->length)
			iomap->length = length;
		return 0;
	}

	if (map.m_flags & EROFS_MAP_META) {
		void *ptr;
		struct erofs_buf buf = __EROFS_BUF_INITIALIZER;

		iomap->type = IOMAP_INLINE;
		ptr = erofs_read_metabuf(&buf, sb,
				erofs_blknr(sb, mdev.m_pa), EROFS_KMAP);
		if (IS_ERR(ptr))
			return PTR_ERR(ptr);
		iomap->inline_data = ptr + erofs_blkoff(sb, mdev.m_pa);
		iomap->private = buf.base;
	} else {
		iomap->type = IOMAP_MAPPED;
		iomap->addr = mdev.m_pa;
	}
	return 0;
}

static int erofs_iomap_end(struct inode *inode, loff_t pos, loff_t length,
		ssize_t written, unsigned int flags, struct iomap *iomap)
{
	void *ptr = iomap->private;

	if (ptr) {
		struct erofs_buf buf = {
			.page = kmap_to_page(ptr),
			.base = ptr,
			.kmap_type = EROFS_KMAP,
		};

		DBG_BUGON(iomap->type != IOMAP_INLINE);
		erofs_put_metabuf(&buf);
	} else {
		DBG_BUGON(iomap->type == IOMAP_INLINE);
	}
	return written;
}

static const struct iomap_ops erofs_iomap_ops = {
	.iomap_begin = erofs_iomap_begin,
	.iomap_end = erofs_iomap_end,
};

/*
 * since we dont have write or truncate flows, so no inode
 * locking needs to be held at the moment.
 */
static int erofs_readpage(struct file *file, struct page *page)
{
	return iomap_readpage(page, &erofs_iomap_ops, NULL);
}

static void erofs_readahead(struct readahead_control *rac)
{
	return iomap_readahead(rac, &erofs_iomap_ops, NULL);
}

static sector_t erofs_bmap(struct address_space *mapping, sector_t block)
{
	return iomap_bmap(mapping, block, &erofs_iomap_ops);
}

static int erofs_prepare_dio(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	loff_t align = iocb->ki_pos | iov_iter_count(to) |
		iov_iter_alignment(to);
	struct block_device *bdev = inode->i_sb->s_bdev;
	unsigned int blksize_mask;

	if (bdev)
		blksize_mask = (1 << ilog2(bdev_logical_block_size(bdev))) - 1;
	else
		blksize_mask = (1 << inode->i_blkbits) - 1;

	if (align & blksize_mask)
		return -EINVAL;
	return 0;
}

static ssize_t erofs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	/* no need taking (shared) inode lock since it's a ro filesystem */
	if (!iov_iter_count(to))
		return 0;

#ifdef CONFIG_FS_DAX
	if (IS_DAX(iocb->ki_filp->f_mapping->host))
		return dax_iomap_rw(iocb, to, &erofs_iomap_ops);
#endif
	if (iocb->ki_flags & IOCB_DIRECT) {
		int err = erofs_prepare_dio(iocb, to);

		if (!err)
			return iomap_dio_rw(iocb, to, &erofs_iomap_ops,
					    NULL, 0, NULL);
		if (err < 0)
			return err;
	}
	return generic_file_read_iter(iocb, to);
}

/* for uncompressed (aligned) files and raw access for other files */
const struct address_space_operations erofs_raw_access_aops = {
	.readpage = erofs_readpage,
	.readahead = erofs_readahead,
	.bmap = erofs_bmap,
	.direct_IO = noop_direct_IO,
	.invalidatepage = iomap_invalidatepage,
	.releasepage = iomap_releasepage,
};

#ifdef CONFIG_FS_DAX
static vm_fault_t erofs_dax_huge_fault(struct vm_fault *vmf,
		enum page_entry_size pe_size)
{
	return dax_iomap_fault(vmf, pe_size, NULL, NULL, &erofs_iomap_ops);
}

static vm_fault_t erofs_dax_fault(struct vm_fault *vmf)
{
	return erofs_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct erofs_dax_vm_ops = {
	.fault		= erofs_dax_fault,
	.huge_fault	= erofs_dax_huge_fault,
};

static int erofs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	if (!IS_DAX(file_inode(file)))
		return generic_file_readonly_mmap(file, vma);

	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		return -EINVAL;

	vma->vm_ops = &erofs_dax_vm_ops;
	vma->vm_flags |= VM_HUGEPAGE;
	return 0;
}
#else
#define erofs_file_mmap	generic_file_readonly_mmap
#endif

const struct file_operations erofs_file_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= erofs_file_read_iter,
	.mmap		= erofs_file_mmap,
	.get_unmapped_area = thp_get_unmapped_area,
	.splice_read	= generic_file_splice_read,
};
