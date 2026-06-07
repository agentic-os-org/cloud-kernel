// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024, Alibaba Cloud
 */
#include <linux/xxhash.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/uio.h>
#include "internal.h"
#include "xattr.h"

#include "../internal.h"

static struct vfsmount *erofs_ishare_mnt;
static const struct file_operations erofs_pcs_fops = {};

static inline bool erofs_is_ishare_inode(struct inode *inode)
{
	return inode->i_fop == &erofs_pcs_fops;
}

static int erofs_ishare_iget5_eq(struct inode *inode, void *data)
{
	struct erofs_inode_fingerprint *fp1 = &EROFS_I(inode)->fingerprint;
	struct erofs_inode_fingerprint *fp2 = data;

	return fp1->size == fp2->size &&
		!memcmp(fp1->opaque, fp2->opaque, fp2->size);
}

static int erofs_ishare_iget5_set(struct inode *inode, void *data)
{
	struct erofs_inode *vi = EROFS_I(inode);

	vi->fingerprint = *(struct erofs_inode_fingerprint *)data;
	INIT_LIST_HEAD(&vi->ishare_list);
	spin_lock_init(&vi->ishare_lock);
	return 0;
}

bool erofs_ishare_fill_inode(struct inode *inode)
{
	struct erofs_sb_info *sbi = EROFS_SB(inode->i_sb);
	struct erofs_inode *vi = EROFS_I(inode);
	const struct address_space_operations *aops;
	struct erofs_inode_fingerprint fp;
	struct inode *sharedinode;
	unsigned long hash;

	aops = erofs_get_aops(inode, true);
	if (IS_ERR(aops))
		return false;
	if (erofs_xattr_fill_inode_fingerprint(&fp, inode, sbi->domain_id))
		return false;
	hash = xxh32(fp.opaque, fp.size, 0);
	sharedinode = iget5_locked(erofs_ishare_mnt->mnt_sb, hash,
				   erofs_ishare_iget5_eq, erofs_ishare_iget5_set,
				   &fp);
	if (!sharedinode) {
		kfree(fp.opaque);
		return false;
	}

	if (sharedinode->i_state & I_NEW) {
		sharedinode->i_fop = &erofs_pcs_fops;
		sharedinode->i_mapping->a_ops = aops;
		sharedinode->i_size = vi->vfs_inode.i_size;
		unlock_new_inode(sharedinode);
	} else {
		kfree(fp.opaque);
		if (aops != sharedinode->i_mapping->a_ops) {
			iput(sharedinode);
			return false;
		}
		if (sharedinode->i_size != vi->vfs_inode.i_size) {
			pr_warn_ratelimited("erofs: size(%lld:%lld) not matches for the same fingerprint\n",
					    vi->vfs_inode.i_size, sharedinode->i_size);
			iput(sharedinode);
			return false;
		}
	}
	vi->sharedinode = sharedinode;
	INIT_LIST_HEAD(&vi->ishare_list);
	spin_lock(&EROFS_I(sharedinode)->ishare_lock);
	list_add(&vi->ishare_list, &EROFS_I(sharedinode)->ishare_list);
	spin_unlock(&EROFS_I(sharedinode)->ishare_lock);
	return true;
}

void erofs_ishare_free_inode(struct inode *inode)
{
	struct erofs_inode *vi = EROFS_I(inode);
	struct inode *sharedinode = vi->sharedinode;

	if (!sharedinode)
		return;
	spin_lock(&EROFS_I(sharedinode)->ishare_lock);
	list_del(&vi->ishare_list);
	spin_unlock(&EROFS_I(sharedinode)->ishare_lock);
	iput(sharedinode);
	vi->sharedinode = NULL;
}

static int erofs_ishare_file_open(struct inode *inode, struct file *file)
{
	struct inode *sharedinode = EROFS_I(inode)->sharedinode;
	struct file *realfile;

	if (file->f_flags & O_DIRECT)
		return -EINVAL;

	realfile = open_with_fake_path(&file->f_path,
				       file->f_flags | O_NOATIME | FMODE_NONOTIFY,
				       sharedinode, current_cred());
	if (IS_ERR(realfile))
		return PTR_ERR(realfile);
	file->private_data = realfile;
	return 0;
}

static int erofs_ishare_file_release(struct inode *inode, struct file *file)
{
	struct file *realfile = file->private_data;

	fput(realfile);
	file->private_data = NULL;
	return 0;
}

static ssize_t erofs_ishare_file_read_iter(struct kiocb *iocb,
					   struct iov_iter *to)
{
	struct file *realfile = iocb->ki_filp->private_data;
	struct kiocb dedup_iocb;
	ssize_t nread;

	if (!iov_iter_count(to))
		return 0;
	kiocb_clone(&dedup_iocb, iocb, realfile);
	nread = generic_file_read_iter(&dedup_iocb, to);
	iocb->ki_pos = dedup_iocb.ki_pos;
	return nread;
}

static int erofs_ishare_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file *file2 = file->private_data;

	/* no vma_set_file() in kernel 5.10 */
	get_file(file2);
	swap(vma->vm_file, file2);
	fput(file2);
	return generic_file_readonly_mmap(vma->vm_file, vma);
}

static int erofs_ishare_fadvise(struct file *file, loff_t offset,
				loff_t len, int advice)
{
	return vfs_fadvise(file->private_data, offset, len, advice);
}

const struct file_operations erofs_ishare_fops = {
	.open		= erofs_ishare_file_open,
	.llseek		= generic_file_llseek,
	.read_iter	= erofs_ishare_file_read_iter,
	.mmap		= erofs_ishare_mmap,
	.release	= erofs_ishare_file_release,
	.get_unmapped_area = thp_get_unmapped_area,
	.splice_read	= generic_file_splice_read,
	.fadvise	= erofs_ishare_fadvise,
};

struct inode *erofs_real_inode(struct inode *inode, bool *need_iput)
{
	struct erofs_inode *vi, *vi_share;
	struct inode *realinode = NULL;

	*need_iput = false;
	if (!erofs_is_ishare_inode(inode))
		return inode;

	vi_share = EROFS_I(inode);
	spin_lock(&vi_share->ishare_lock);
	/* fetch any one as real inode */
	DBG_BUGON(list_empty(&vi_share->ishare_list));
	list_for_each_entry(vi, &vi_share->ishare_list, ishare_list) {
		realinode = igrab(&vi->vfs_inode);
		if (realinode) {
			*need_iput = true;
			break;
		}
	}
	spin_unlock(&vi_share->ishare_lock);

	DBG_BUGON(!realinode);
	return realinode;
}

int __init erofs_init_ishare(void)
{
	struct vfsmount *mnt;
	int ret;

	mnt = kern_mount(&erofs_anon_fs_type);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);
	/* generic_fadvise() doesn't work if s_bdi == &noop_backing_dev_info */
	ret = super_setup_bdi(mnt->mnt_sb);
	if (ret)
		kern_unmount(mnt);
	else
		erofs_ishare_mnt = mnt;
	return ret;
}

void erofs_exit_ishare(void)
{
	kern_unmount(erofs_ishare_mnt);
}
