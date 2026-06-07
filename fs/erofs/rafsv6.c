// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021-2023, Alibaba Cloud
 */
#include <linux/cred.h>
#include <linux/uio.h>
#include <linux/file.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include "internal.h"

static ssize_t rafs_v6_read_chunk(struct super_block *sb,
				  struct iov_iter *to, u64 off, u64 size,
				  unsigned int device_id)
{
	struct iov_iter titer;
	ssize_t read = 0;
	struct erofs_map_dev mdev = {
		.m_deviceid = device_id,
		.m_pa = off,
	};
	int err;

	err = erofs_map_dev(sb, &mdev);
	if (err) {
		erofs_err(sb, "read_chunk: failed to map_dev err %d",
			  err);
		return err;
	}
	off = mdev.m_pa;
	do {
		ssize_t ret;

		if (iov_iter_is_pipe(to)) {
			iov_iter_pipe(&titer, READ, to->pipe, size - read);

			ret = vfs_iter_read(mdev.m_fp, &titer, &off, 0);
			pr_debug("pipe ret %ld off %llu size %llu read %ld\n",
				 ret, off, size, read);
			if (ret <= 0) {
				erofs_err(sb, "failed to read blob ret %ld (pipe off %llu size %llu read %ld device_id %u mdev m_deviceid %u m_pa %llu m_fp %p m_fscache %p)",
				       ret, off, size, read, device_id,
				       mdev.m_deviceid, mdev.m_pa, mdev.m_fp,
				       mdev.m_fscache);
				return ret;
			}
		} else if (iov_iter_is_kvec(to)) {
			if (!to->kvec->iov_len) {
				iov_iter_advance(to, 0);
				continue;
			}

			iov_iter_kvec(&titer, READ, to->kvec, 1, size - read);

			ret = vfs_iter_read(mdev.m_fp, &titer, &off, 0);
			pr_debug("kvec ret %ld off %llu size %llu read %ld\n",
				 ret, off, size, read);
			if (ret <= 0) {
				erofs_err(sb, "failed to read blob ret %ld (kvec off %llu size %llu read %ld device_id %u mdev m_deviceid %u m_pa %llu m_fp %p m_fscache %p)",
				       ret, off, size, read, device_id,
				       mdev.m_deviceid, mdev.m_pa, mdev.m_fp,
				       mdev.m_fscache);
				return ret;
			}
		} else {
			struct iovec iovec = iov_iter_iovec(to);

			if (!to->iov->iov_len) {
				iov_iter_advance(to, 0);
				continue;
			}

			if (iovec.iov_len > size - read)
				iovec.iov_len = size - read;

			pr_debug("read_chunk: off %llu size %llu iov_len %lu blob_index %u\n",
				 off, size, iovec.iov_len, device_id);

			/* TODO async */
			iov_iter_init(&titer, READ, &iovec, 1, iovec.iov_len);
			ret = vfs_iter_read(mdev.m_fp, &titer, &off, 0);
			if (ret <= 0) {
				erofs_err(sb, "failed to read blob ret %ld (iovec off %llu size %llu read %ld device_id %u mdev m_deviceid %u m_pa %llu m_fp %p m_fscache %p)",
				       ret, off, size, read, device_id,
				       mdev.m_deviceid, mdev.m_pa, mdev.m_fp,
				       mdev.m_fscache);
				return ret;
			} else if (ret < iovec.iov_len) {
				return read;
			}
		}
		iov_iter_advance(to, ret);
		read += ret;
	} while (read < size);

	return read;
}

static ssize_t rafs_v6_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct erofs_map_blocks map = { 0 };
	ssize_t bytes = 0;
	u64 total = min_t(u64, iov_iter_count(to),
			  inode->i_size - iocb->ki_pos);

	while (total) {
		erofs_off_t pos = iocb->ki_pos;
		u64 delta, size;
		ssize_t read;

		if (map.m_la < pos || map.m_la + map.m_llen >= pos) {
			int err;

			map.m_la = pos;
			err = erofs_map_blocks(inode, &map);
			if (err) {
				erofs_err(inode->i_sb,
					  "rafs_v6_read: failed to map_blocks err %d",
					  err);
				return err;
			}
			if (map.m_la >= inode->i_size)
				break;
		}
		delta = pos - map.m_la;
		size = min_t(u64, map.m_llen - delta, total);
		pr_debug("inode i_size %llu pa %llu delta %llu size %llu\n",
			 inode->i_size, map.m_pa, delta, size);
		read = rafs_v6_read_chunk(inode->i_sb, to, map.m_pa + delta,
					  size, map.m_deviceid);
		if (read <= 0 || read < size) {
			erofs_err(inode->i_sb,
				  "rafs_v6_read: short read %ld pos %llu size %llu @ nid %llu",
				  read, pos, size, EROFS_I(inode)->nid);
			return read < 0 ? read : -EIO;
		}
		iocb->ki_pos += read;
		bytes += read;
		total -= read;
	}
	return bytes;
}

static vm_fault_t rafs_v6_filemap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	pgoff_t npages, orig_pgoff = vmf->pgoff;
	erofs_off_t pos;
	struct erofs_map_blocks map = {0};
	struct erofs_map_dev mdev;
	struct vm_area_struct lower_vma;
	int err;
	vm_fault_t ret;

	npages = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	if (unlikely(orig_pgoff >= npages))
		return VM_FAULT_SIGBUS;

	memcpy(&lower_vma, vmf->vma, sizeof(lower_vma));
	WARN_ON_ONCE(lower_vma.vm_private_data != vma->vm_private_data);

	/* TODO: check if chunk is available for us to read. */
	map.m_la = orig_pgoff << PAGE_SHIFT;
	pos = map.m_la;
	err = erofs_map_blocks(inode, &map);
	if (err)
		return vmf_error(err);

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};
	err = erofs_map_dev(inode->i_sb, &mdev);
	if (err)
		return vmf_error(err);

	lower_vma.vm_file = mdev.m_fp;
	vmf->pgoff = (mdev.m_pa + (pos - map.m_la)) >> PAGE_SHIFT;
	vmf->vma = &lower_vma; /* override vma temporarily */
	ret = EROFS_I(inode)->lower_vm_ops->fault(vmf);
	vmf->vma = vma;
	vmf->pgoff = orig_pgoff;
	return ret;
}

static void rafs_v6_vm_close(struct vm_area_struct *vma)
{
	struct inode *inode;

	if (!vma || !vma->vm_file) {
		WARN_ON_ONCE(1);
		return;
	}

	inode = file_inode(vma->vm_file);
	if (EROFS_I(inode)->lower_vm_ops && EROFS_I(inode)->lower_vm_ops->close)
		EROFS_I(inode)->lower_vm_ops->close(vma);

	WARN_ON(vma->vm_private_data);
}

static void rafs_v6_vm_open(struct vm_area_struct *vma)
{
	struct inode *inode;

	if (!vma || !vma->vm_file) {
		WARN_ON_ONCE(1);
		return;
	}

	inode = file_inode(vma->vm_file);
	if (EROFS_I(inode)->lower_vm_ops && EROFS_I(inode)->lower_vm_ops->open)
		EROFS_I(inode)->lower_vm_ops->open(vma);
}

static const struct vm_operations_struct rafs_v6_vm_ops = {
	.fault	= rafs_v6_filemap_fault,
	.close	= rafs_v6_vm_close,
	.open	= rafs_v6_vm_open,
};

static int __rafs_v6_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	struct erofs_inode *vi = EROFS_I(inode);
	const struct vm_operations_struct *lower_vm_ops;
	struct file *realfile = EROFS_I_SB(inode)->bootstrap;
	int ret;

	if (!realfile || !realfile->f_op->mmap) {
		erofs_err(inode->i_sb, "nondirect_mmap: no bootstrap or mmap\n");
		return -EOPNOTSUPP;
	}

	ret = call_mmap(EROFS_I_SB(inode)->bootstrap, vma);
	if (ret) {
		erofs_err(inode->i_sb,
			  "nondirect_mmap: call_mmap failed ret %d\n", ret);
		return ret;
	}

	/* set fs's vm_ops which is used in fault(). */
	lower_vm_ops = vma->vm_ops;

	if (vi->lower_vm_ops && vi->lower_vm_ops != lower_vm_ops) {
		WARN_ON_ONCE(1);
		return -EOPNOTSUPP;
	}
	/* fault() must exist in order to proceed. */
	if (!lower_vm_ops || !lower_vm_ops->fault) {
		WARN_ON_ONCE(1);
		return -EOPNOTSUPP;
	}
	vi->lower_vm_ops = lower_vm_ops;
	vma->vm_flags &= ~VM_HUGEPAGE;	/* dont use huge page */
	vma->vm_ops = &rafs_v6_vm_ops;
	return 0;
}

static int __rafs_v6_file_direct_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	struct erofs_map_blocks map = { 0 };
	struct erofs_map_dev mdev;
	struct file *blobfile;
	int err;

	if (file != vma->vm_file) {
		WARN_ON_ONCE(1);
		return -EIO;
	}

	err = erofs_map_blocks(inode, &map);
	if (err) {
		erofs_err(inode->i_sb, "direct_mmap: failed to map_blocks err %d",
			  err);
		return err;
	}

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};
	err = erofs_map_dev(inode->i_sb, &mdev);
	if (err) {
		erofs_err(inode->i_sb, "direct_mmap: failed to map_dev err %d",
			  err);
		return err;
	}

	if (!mdev.m_fp || !mdev.m_fp->f_op->mmap) {
		erofs_err(inode->i_sb, "direct_mmap: mdev.m_fp %p",
			  mdev.m_fp);
		return -EOPNOTSUPP;
	}

	blobfile = open_with_fake_path(&file->f_path, mdev.m_fp->f_flags,
					mdev.m_fp->f_inode, current_cred());
	if (IS_ERR(blobfile)) {
		erofs_err(inode->i_sb, "failed to open the blobfile: %s deviceid: %u nid: %llu, err %ld",
			  mdev.m_fp->f_path.dentry->d_name.name, mdev.m_deviceid,
			  EROFS_I(inode)->nid, PTR_ERR(blobfile));
		return PTR_ERR(blobfile);
	}

	vma->vm_file = blobfile;
	vma->vm_pgoff += mdev.m_pa >> PAGE_SHIFT;
	err = call_mmap(vma->vm_file, vma);
	if (err) {
		erofs_err(inode->i_sb,
			  "direct_mmap: call_mmap failed with err %d, deviceid: %u, nid: %llu, name: %s\n",
			  err, mdev.m_deviceid, EROFS_I(inode)->nid,
			  mdev.m_fp->f_path.dentry->d_name.name);
		vma->vm_file = file;
		vma->vm_pgoff -= mdev.m_pa >> PAGE_SHIFT;
		fput(blobfile);
	} else {
		fput(file);
	}

	return err;
}

static int rafs_v6_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);

	if (test_opt(&EROFS_I_SB(inode)->opt, BLOB_MMAP_PIN))
		return __rafs_v6_file_mmap(file, vma);

	return __rafs_v6_file_direct_mmap(file, vma);
}

const struct file_operations rafs_v6_file_ro_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= rafs_v6_file_read_iter,
	.mmap		= rafs_v6_file_mmap,
	.splice_read	= generic_file_splice_read,
};

// Fops for regular files with multiple non-contiguous chunks
static const struct file_operations rafs_v6_chunk_ro_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= rafs_v6_file_read_iter,
	.mmap		= generic_file_readonly_mmap,
	.splice_read	= generic_file_splice_read,
};

static int rafs_v6_readpage(struct file *file, struct page *page)
{
	struct kvec iov = {
		.iov_base	= page_address(page),
	};
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	erofs_off_t pos = page->index << PAGE_SHIFT;
	struct erofs_map_blocks map = { .m_la = pos };
	struct erofs_map_dev mdev;
	struct kiocb kiocb;
	struct iov_iter iter;
	int err;

	err = erofs_map_blocks(inode, &map);
	if (err) {
		erofs_err(inode->i_sb, "readpage: failed to map_blocks err %d",
			  err);
		goto err_out;
	}

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};
	err = erofs_map_dev(sb, &mdev);
	if (err) {
		erofs_err(inode->i_sb, "readpage: failed to map_dev err %d",
			  err);
		goto err_out;
	}

	/*
	 * mdev.m_fp should be bootstrap file if m_deviceid == 0, but
	 * it could change in the future.
	 */
	WARN_ON_ONCE(!map.m_deviceid && mdev.m_fp != EROFS_SB(sb)->bootstrap);

	iov.iov_len = min_t(u64, PAGE_SIZE, map.m_plen - (pos - map.m_la));
	init_sync_kiocb(&kiocb, mdev.m_fp);
	kiocb.ki_pos = map.m_pa + (pos - map.m_la);
	iov_iter_kvec(&iter, READ, &iov, 1, iov.iov_len);

	err = call_read_iter(mdev.m_fp, &kiocb, &iter);
	if (err < iov.iov_len) {
		if (err < 0)
			erofs_err(inode->i_sb, "readpage: failed to read blob ret %d",
				  err);
		goto err_out;
	}
	if (iov.iov_len < PAGE_SIZE)
		memset(iov.iov_base + iov.iov_len, 0,
		       PAGE_SIZE - iov.iov_len);
	SetPageUptodate(page);
	unlock_page(page);
	return 0;
err_out:
	SetPageError(page);
	unlock_page(page);
	return err;
}

const struct address_space_operations rafs_v6_access_aops = {
	.readpage = rafs_v6_readpage,
};

void erofs_rafsv6_set_fops(struct inode *inode)
{
	struct erofs_inode *vi = EROFS_I(inode);

	if (vi->datalayout == EROFS_INODE_FLAT_PLAIN) {
		inode->i_fop = &rafs_v6_file_ro_fops;
	} else if (vi->datalayout == EROFS_INODE_CHUNK_BASED &&
		   (1 << vi->chunkbits) >= inode->i_size) {
		inode->i_fop = &rafs_v6_file_ro_fops;
	} else {
		inode->i_fop = &rafs_v6_chunk_ro_fops;
	}
}

const struct address_space_operations *erofs_rafsv6_get_aops(struct inode *inode)
{
	if (!S_ISREG(inode->i_mode))
		inode_nohighmem(inode);

	return &rafs_v6_access_aops;
}
