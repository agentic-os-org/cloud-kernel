// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2026, Google LLC
 * Author: Samiullah Khawaja <skhawaja@google.com>
 */

#define pr_fmt(fmt) "iommufd: " fmt

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/iommufd.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/iommufd.h>
#include <linux/liveupdate.h>
#include <linux/iommu-liveupdate.h>
#include <linux/mm.h>
#include <linux/pci.h>

#include "iommufd_private.h"
#include "io_pagetable.h"

static void ioas_set_immutable(struct iommufd_ioas *ioas, bool immutable)
{
	down_write(&ioas->iopt.domains_rwsem);
	ioas->iopt.liveupdate_immutable = immutable;
	up_write(&ioas->iopt.domains_rwsem);
}

int iommufd_hwpt_liveupdate_mark_preserve(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_liveupdate_mark_preserve *cmd = ucmd->cmd;
	struct iommufd_hwpt_paging *hwpt_target;
	struct iommufd_hwpt_paging *hwpt_paging;
	struct iommufd_ctx *ictx = ucmd->ictx;
	struct iommufd_object *obj;
	unsigned long index;
	int rc = 0;

	hwpt_target = iommufd_get_hwpt_paging(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt_target))
		return PTR_ERR(hwpt_target);

	mutex_lock(&ictx->liveupdate_mutex);

	xa_lock(&ictx->objects);
	xa_for_each_marked(&ictx->objects, index, obj, IOMMUFD_OBJ_LIVEUPDATE_MARK) {
		if (WARN_ON_ONCE(obj->type != IOMMUFD_OBJ_HWPT_PAGING))
			continue;

		hwpt_paging = to_hwpt_paging(container_of(obj, struct iommufd_hw_pagetable, obj));
		if (hwpt_paging->liveupdate_token == cmd->hwpt_token) {
			rc = -EADDRINUSE;
			goto out_unlock;
		}
	}

	__xa_set_mark(&ictx->objects, hwpt_target->common.obj.id, IOMMUFD_OBJ_LIVEUPDATE_MARK);
	hwpt_target->liveupdate_token = cmd->hwpt_token;

out_unlock:
	xa_unlock(&ictx->objects);
	mutex_unlock(&ictx->liveupdate_mutex);
	iommufd_put_object(ictx, &hwpt_target->common.obj);
	return rc;
}

static int check_iopt_pages_preserved(struct liveupdate_session *s,
				      struct iommufd_hwpt_paging *hwpt)
{
	u32 req_seals = F_SEAL_SEAL | F_SEAL_GROW | F_SEAL_SHRINK;
	struct iopt_area *area;
	int ret = 0;

	down_read(&hwpt->ioas->iopt.iova_rwsem);
	for (area = iopt_area_iter_first(&hwpt->ioas->iopt, 0, ULONG_MAX); area;
	     area = iopt_area_iter_next(area, 0, ULONG_MAX)) {
		struct iopt_pages *pages = area->pages;

		/* Only allow file based mapping */
		if (pages->type != IOPT_ADDRESS_FILE) {
			ret = -EINVAL;
			break;
		}

		/*
		 * When this memory file was mapped it should be sealed and seal
		 * should be sealed. This means that since mapping was done the
		 * memory file was not grown or shrink and the pages being used
		 * until now remain pinned and preserved.
		 */
		if ((pages->seals & req_seals) != req_seals) {
			ret = -EINVAL;
			break;
		}

		/* Make sure that the file was preserved. */
		ret = liveupdate_get_token_outgoing(s, pages->file, NULL);
		if (ret)
			break;
	}
	up_read(&hwpt->ioas->iopt.iova_rwsem);

	return ret;
}

static int iommufd_preserve_hwpt(struct iommufd_hwpt_paging *hwpt,
				 struct iommufd_hwpt_ser *hwpt_ser,
				 struct liveupdate_session *session)
{
	struct iommu_domain_ser *domain_ser;
	bool ioas_made_immutable = false;
	int rc;

	if (!hwpt->ioas->iopt.liveupdate_immutable) {
		/*
		 * Make IOAS immutable so the DMA mappings do not change while
		 * the HWPT is preserved. Since one IOAS can have multiple
		 * HWPTs, if an error occurs this call needs to make the IOAS
		 * mutable again if it was the one that made it immutable.
		 */
		ioas_made_immutable = true;
		ioas_set_immutable(hwpt->ioas, true);

		rc = check_iopt_pages_preserved(session, hwpt);
		if (rc)
			goto err;
	}

	hwpt_ser->token = hwpt->liveupdate_token;
	hwpt_ser->reclaimed = false;

	rc = iommu_domain_preserve(hwpt->common.domain, &domain_ser);
	if (rc < 0)
		goto err;

	hwpt_ser->domain_data = virt_to_phys(domain_ser);
	return 0;

err:
	if (ioas_made_immutable)
		ioas_set_immutable(hwpt->ioas, false);

	return rc;
}

static void _iommufd_unpreserve(struct iommufd_ctx *ictx,
				struct iommufd_ser *ser)
{
	struct iommufd_hwpt_paging *hwpt;
	struct iommufd_object *obj;
	unsigned long index;

	xa_lock(&ictx->objects);
	xa_for_each_marked(&ictx->objects, index, obj, IOMMUFD_OBJ_LIVEUPDATE_MARK) {
		if (obj->type != IOMMUFD_OBJ_HWPT_PAGING)
			continue;

		hwpt = to_hwpt_paging(container_of(obj, struct iommufd_hw_pagetable, obj));
		if (!hwpt->liveupdate_preserved)
			continue;

		xa_unlock(&ictx->objects);

		iommu_domain_unpreserve(hwpt->common.domain);
		if (hwpt->ioas->iopt.liveupdate_immutable)
			ioas_set_immutable(hwpt->ioas, false);

		hwpt->liveupdate_preserved = false;
		iommufd_put_object(ictx, obj);

		xa_lock(&ictx->objects);
	}
	xa_unlock(&ictx->objects);

	kho_unpreserve_free(ser);
}

static int iommufd_liveupdate_preserve(struct liveupdate_file_op_args *args)
{
	struct iommufd_ctx *ictx = iommufd_ctx_from_file(args->file);
	struct iommufd_hwpt_paging *hwpt;
	struct iommufd_ser *iommufd_ser;
	struct iommufd_object *obj;
	unsigned int nr_hwpts;
	unsigned long index;
	unsigned int i;
	void *mem;
	int rc;

	if (IS_ERR(ictx))
		return PTR_ERR(ictx);

	mutex_lock(&ictx->liveupdate_mutex);

	/* Count the number of HWPTs to preserve */
	nr_hwpts = 0;
	xa_lock(&ictx->objects);
	xa_for_each_marked(&ictx->objects, index, obj, IOMMUFD_OBJ_LIVEUPDATE_MARK) {
		if (obj->type != IOMMUFD_OBJ_HWPT_PAGING)
			continue;

		hwpt = to_hwpt_paging(container_of(obj, struct iommufd_hw_pagetable, obj));
		if (!hwpt->common.domain) {
			rc = -EINVAL;
			xa_unlock(&ictx->objects);
			goto out_unlock;
		}
		nr_hwpts++;
	}
	xa_unlock(&ictx->objects);

	mem = kho_alloc_preserve(struct_size(iommufd_ser,
					     hwpt_array, nr_hwpts));
	if (!mem) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	iommufd_ser = mem;
	iommufd_ser->nr_hwpts = nr_hwpts;

	/* Preserve HWPTs */
	i = 0;
	xa_lock(&ictx->objects);
	xa_for_each_marked(&ictx->objects, index, obj, IOMMUFD_OBJ_LIVEUPDATE_MARK) {
		if (obj->type != IOMMUFD_OBJ_HWPT_PAGING)
			continue;

		if (!iommufd_lock_obj(obj)) {
			rc = -ENOENT;
			xa_unlock(&ictx->objects);
			goto out_unpreserve;
		}

		/*
		 * HWPT is locked so it will not be destroyed. The xarray lock
		 * can be released here before preserving the HWPT.
		 */
		xa_unlock(&ictx->objects);
		hwpt = to_hwpt_paging(container_of(obj, struct iommufd_hw_pagetable, obj));
		rc = iommufd_preserve_hwpt(hwpt, &iommufd_ser->hwpt_array[i++], args->session);
		if (rc) {
			iommufd_put_object(ictx, obj);
			goto out_unpreserve;
		}

		/* Mark as preserved */
		hwpt->liveupdate_preserved = true;
		xa_lock(&ictx->objects);
	}
	xa_unlock(&ictx->objects);

	args->serialized_data = virt_to_phys(iommufd_ser);
	mutex_unlock(&ictx->liveupdate_mutex);
	iommufd_ctx_put(ictx);
	return 0;

out_unpreserve:
	_iommufd_unpreserve(ictx, iommufd_ser);
out_unlock:
	mutex_unlock(&ictx->liveupdate_mutex);
	iommufd_ctx_put(ictx);
	return rc;
}

static void iommufd_liveupdate_unpreserve(struct liveupdate_file_op_args *args)
{
	struct iommufd_ctx *ictx = iommufd_ctx_from_file(args->file);

	if (WARN_ON(IS_ERR(ictx)))
		return;

	mutex_lock(&ictx->liveupdate_mutex);
	_iommufd_unpreserve(ictx, phys_to_virt(args->serialized_data));
	mutex_unlock(&ictx->liveupdate_mutex);

	iommufd_ctx_put(ictx);
}

static int iommufd_liveupdate_retrieve(struct liveupdate_file_op_args *args)
{
	struct iommufd_ser *iommufd_ser;
	struct iommufd_ctx *ictx;
	struct folio *folio_ser;
	struct file *file;
	int rc;

	folio_ser = kho_restore_folio(args->serialized_data);
	if (IS_ERR_OR_NULL(folio_ser))
		return -EFAULT;

	iommufd_ser = folio_address(folio_ser);

	file = anon_inode_create_getfile("iommufd", &iommufd_fops,
					 NULL, O_RDWR, NULL);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);
		goto err_folio_put;
	}

	rc = iommufd_fops.open(file->f_inode, file);
	if (rc)
		goto err_fput;

	ictx = iommufd_ctx_from_file(file);
	if (WARN_ON(IS_ERR(ictx))) {
		rc = PTR_ERR(ictx);
		goto err_fput;
	}

	if (WARN_ON(ictx->ser)) {
		rc = -EEXIST;
		goto err_ctx_put;
	}
	ictx->ser = iommufd_ser;

	iommufd_ctx_put(ictx);

	args->file = file;

	return 0;

err_ctx_put:
	iommufd_ctx_put(ictx);
err_fput:
	fput(file);
err_folio_put:
	folio_put(folio_ser);
	return rc;
}

int iommufd_hwpt_liveupdate_restore(struct iommufd_ucmd *ucmd)
{
	struct iommu_hwpt_liveupdate_restore *cmd = ucmd->cmd;
	struct iommufd_hwpt_paging *hwpt = NULL;
	struct iommufd_ctx *ictx = ucmd->ictx;
	struct iommu_domain_ser *domain_ser;
	struct iommufd_hwpt_ser *hwpt_ser;
	struct iommufd_ser *iommufd_ser;
	struct iommu_domain *domain;
	unsigned int i;
	int rc;

	iommufd_ser = ictx->ser;
	if (!iommufd_ser)
		return -ENOTTY;

	for (i = 0; i < iommufd_ser->nr_hwpts; i++) {
		hwpt_ser = &iommufd_ser->hwpt_array[i];

		if (hwpt_ser->reclaimed)
			continue;

		if (hwpt_ser->token == cmd->hwpt_token)
			goto hwpt_found;
	}

	return -ENOENT;

hwpt_found:
	hwpt = _iommufd_hwpt_paging_alloc(ictx);
	if (IS_ERR(hwpt))
		return PTR_ERR(hwpt);

	domain_ser = __va(hwpt_ser->domain_data);
	domain = domain_ser->restored_domain;
	if (!domain) {
		rc = -ENOENT;
		goto err_destroy;
	}

	iommufd_hwpt_init_from_domain(&hwpt->common, domain);
	iommufd_object_finalize(ictx, &hwpt->common.obj);

	hwpt_ser->reclaimed = true;
	hwpt->liveupdate_restored = true;
	cmd->pt_id = hwpt->common.obj.id;
	return 0;

err_destroy:
	iommufd_object_abort_and_destroy(ictx, &hwpt->common.obj);
	return rc;
}

static bool iommufd_liveupdate_can_finish(struct liveupdate_file_op_args *args)
{
	if (args->retrieve_status <= 0 || !args->file) {
		pr_warn("%s: fd not reclaimed\n", __func__);
		return false;
	}

	return true;
}

static void iommufd_liveupdate_finish(struct liveupdate_file_op_args *args)
{
}

static bool iommufd_liveupdate_can_preserve(struct liveupdate_file_handler *handler,
					    struct file *file)
{
	struct iommufd_ctx *ictx = iommufd_ctx_from_file(file);

	if (IS_ERR(ictx))
		return false;

	iommufd_ctx_put(ictx);
	return true;
}

static struct liveupdate_file_ops iommufd_ser_file_ops = {
	.can_preserve = iommufd_liveupdate_can_preserve,
	.preserve = iommufd_liveupdate_preserve,
	.unpreserve = iommufd_liveupdate_unpreserve,
	.retrieve = iommufd_liveupdate_retrieve,
	.can_finish = iommufd_liveupdate_can_finish,
	.finish = iommufd_liveupdate_finish,
};

static struct liveupdate_file_handler iommufd_ser_handler = {
	.compatible = IOMMUFD_LUO_COMPATIBLE,
	.ops = &iommufd_ser_file_ops,
};

int iommufd_liveupdate_register(void)
{
	int ret;

	ret = liveupdate_register_file_handler(&iommufd_ser_handler);
	if (ret)
		return ret;

	ret = iommu_liveupdate_register_flb(&iommufd_ser_handler);
	if (ret)
		liveupdate_unregister_file_handler(&iommufd_ser_handler);

	return ret;
}

void iommufd_liveupdate_unregister(void)
{
	iommu_liveupdate_unregister_flb(&iommufd_ser_handler);
	liveupdate_unregister_file_handler(&iommufd_ser_handler);
}
