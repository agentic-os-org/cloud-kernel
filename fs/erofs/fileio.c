// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024, Alibaba Cloud
 */
#include "internal.h"
#include <linux/uio.h>
#include <trace/events/erofs.h>

struct erofs_fileio_rq {
	struct bio_vec bvecs[BIO_MAX_PAGES];
	struct bio bio;
	struct kiocb iocb;
	struct super_block *sb;
};

struct erofs_fileio {
	struct erofs_map_blocks map;
	struct erofs_map_dev dev;
	struct erofs_fileio_rq *rq;
};

static void erofs_fileio_ki_complete(struct kiocb *iocb, long ret, long res2)
{
	struct erofs_fileio_rq *rq =
			container_of(iocb, struct erofs_fileio_rq, iocb);
	struct bio_vec *bvec;
	struct bvec_iter_all iter_all;

	DBG_BUGON(rq->bio.bi_end_io);
	if (ret > 0) {
		if (ret != rq->bio.bi_iter.bi_size) {
			bio_advance(&rq->bio, ret);
			zero_fill_bio(&rq->bio);
		}
		ret = 0;
	}
	bio_for_each_segment_all(bvec, &rq->bio, iter_all) {
		struct page *page = bvec->bv_page;

		DBG_BUGON(PageUptodate(page));
		erofs_onlinepage_end(page, ret);
	}
	bio_uninit(&rq->bio);
	kfree(rq);
}

static void erofs_fileio_rq_submit(struct erofs_fileio_rq *rq)
{
	struct iov_iter iter;
	int ret;

	if (!rq)
		return;
	rq->iocb.ki_pos = rq->bio.bi_iter.bi_sector << SECTOR_SHIFT;
	rq->iocb.ki_ioprio = get_current_ioprio();
	rq->iocb.ki_complete = erofs_fileio_ki_complete;
	if (test_opt(&EROFS_SB(rq->sb)->opt, DIRECT_IO) &&
	    rq->iocb.ki_filp->f_mapping->a_ops->direct_IO)
		rq->iocb.ki_flags = IOCB_DIRECT;
	iov_iter_bvec(&iter, READ, rq->bvecs, rq->bio.bi_vcnt,
		      rq->bio.bi_iter.bi_size);
	ret = vfs_iocb_iter_read(rq->iocb.ki_filp, &rq->iocb, &iter);
	if (ret != -EIOCBQUEUED)
		erofs_fileio_ki_complete(&rq->iocb, ret, 0);
}

static struct erofs_fileio_rq *erofs_fileio_rq_alloc(struct super_block *sb,
						     struct erofs_map_dev *mdev)
{
	struct erofs_fileio_rq *rq = kzalloc(sizeof(*rq),
					     GFP_KERNEL | __GFP_NOFAIL);

	bio_init(&rq->bio, rq->bvecs, BIO_MAX_PAGES);
	rq->bio.bi_opf = REQ_OP_READ;
	rq->iocb.ki_filp = mdev->m_fp;
	rq->sb = sb;
	return rq;
}

static int erofs_fileio_scan_folio(struct erofs_fileio *io, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct erofs_map_blocks *map = &io->map;
	unsigned int cur = 0, end = PAGE_SIZE, len, attached = 0;
	loff_t pos = page->index << PAGE_SHIFT, ofs;
	int err = 0;

	erofs_onlinepage_init(page);
	while (cur < end) {
		if (pos + cur < map->m_la ||
		    pos + cur >= map->m_la + map->m_llen) {
			map->m_la = pos + cur;
			map->m_llen = end - cur;
			err = erofs_map_blocks(inode, map);
			if (err)
				break;
		}

		ofs = (page->index << PAGE_SHIFT) + cur - map->m_la;
		len = min_t(loff_t, map->m_llen - ofs, end - cur);
		if (map->m_flags & EROFS_MAP_META) {
			struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
			void *src;

			src = erofs_read_metabuf(&buf, inode->i_sb,
						 erofs_blknr(inode->i_sb, map->m_pa + ofs),
						 EROFS_KMAP);
			if (IS_ERR(src)) {
				err = PTR_ERR(src);
				break;
			}
			memcpy_to_page(page, cur,
				src + erofs_blkoff(inode->i_sb, map->m_pa + ofs), len);
			erofs_put_metabuf(&buf);
		} else if (!(map->m_flags & EROFS_MAP_MAPPED)) {
			zero_user_segment(page, cur, cur + len);
			attached = 0;
		} else {
			if (io->rq && (map->m_pa + ofs != io->dev.m_pa ||
				       map->m_deviceid != io->dev.m_deviceid)) {
io_retry:
				erofs_fileio_rq_submit(io->rq);
				io->rq = NULL;
			}

			if (!io->rq) {
				io->dev = (struct erofs_map_dev) {
					.m_pa = io->map.m_pa + ofs,
					.m_deviceid = io->map.m_deviceid,
				};
				err = erofs_map_dev(inode->i_sb, &io->dev);
				if (err)
					break;
				io->rq = erofs_fileio_rq_alloc(inode->i_sb, &io->dev);
				io->rq->bio.bi_iter.bi_sector = io->dev.m_pa >> 9;
				attached = 0;
			}
			if (!attached++)
				erofs_onlinepage_split(page);
			if (!bio_add_page(&io->rq->bio, page, len, cur))
				goto io_retry;
			io->dev.m_pa += len;
		}
		cur += len;
	}
	erofs_onlinepage_end(page, err);
	return err;
}

static int erofs_fileio_readpage(struct file *file, struct page *page)
{
	struct erofs_fileio io = {};
	int err;

	trace_erofs_readpage(page, true);
	err = erofs_fileio_scan_folio(&io, page);
	erofs_fileio_rq_submit(io.rq);
	return err;
}

static void erofs_fileio_readahead(struct readahead_control *rac)
{
	struct inode *inode = rac->mapping->host;
	struct erofs_fileio io = {};
	struct page *page;
	int err;

	trace_erofs_readpages(inode, readahead_index(rac),
			      readahead_count(rac), true);
	while ((page = readahead_page(rac))) {
		err = erofs_fileio_scan_folio(&io, page);
		if (err && err != -EINTR)
			erofs_err(inode->i_sb, "readahead error at page %lu @ nid %llu",
				  page->index, EROFS_I(inode)->nid);
	}
	erofs_fileio_rq_submit(io.rq);
}

const struct address_space_operations erofs_fileio_aops = {
	.readpage = erofs_fileio_readpage,
	.readahead = erofs_fileio_readahead,
};
