// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - MPAM MDEV
 * Author: Shawn Wang <shawnwang@linux.alibaba.com>
 */

#define dev_fmt(fmt)	"MPAM MDEV: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cpuhotplug.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitfield.h>
#include <linux/sysfs.h>
#include <linux/vfio.h>
#include <linux/platform_device.h>
#include <linux/mdev.h>

#include <asm/sysreg.h>
#include <asm/mpam.h>

#include "mpam_internal.h"

extern struct list_head mpam_all_msc;
extern struct mutex mpam_list_lock;

extern u16 mpam_partid_max;
extern spinlock_t partid_max_lock;

extern int yitian710_ddrc_freq;

#define MPAM_MDEV_NAME "mpam_mdev"
#define MPAM_MDEV_CLASS_NAME "mpam_mdev"

#define MPAM_MDEV_TYPE_1 "small"
#define MPAM_MDEV_TYPE_2 "medium"
#define MPAM_MDEV_TYPE_3 "large"

static u16 mpam_mdev_partid_max = 31;
static u16 physical_partid_offset = 32;

static int mpam_mdev_cpuhp_state;

static const struct mpam_mdev_type {
	const char *name;
	u32 partids;
} mpam_mdev_types[] = {
	{
		.name = MPAM_MDEV_CLASS_NAME "-" MPAM_MDEV_TYPE_1,
		.partids = 4,
	}, {
		.name = MPAM_MDEV_CLASS_NAME "-" MPAM_MDEV_TYPE_2,
		.partids = 8,
	}, {
		.name = MPAM_MDEV_CLASS_NAME "-" MPAM_MDEV_TYPE_3,
		.partids = 16,
	},
};

struct mpam_mdev_saved_regs {
	u32 part_sel;
	u32 mon_sel;
	u32 csu_flt;
	u32 csu_ctl;
	u32 mbwu_flt;
	u32 mbwu_ctl;
};

struct mpam_mdev_state {
	struct mdev_device *mdev;
	const struct mpam_mdev_type *type;
	struct mutex ops_lock;

	int poffset;
	int voffset;
	struct mpam_msc *msc;

	struct mpam_mdev_saved_regs regs;

	u32 custom_reg_base_addr;
};

static void handle_mmr_write(struct mpam_mdev_state *mpam_mdev_state,
			     u16 offset, char *buf, u32 count)
{
	struct mpam_msc *msc;
	u16 vpartid, ris_idx;
	u32 reg32;

	msc = mpam_mdev_state->msc;
	reg32 = *(u32 *)buf;

	switch (offset) {
	case MPAMCFG_PART_SEL:
		vpartid = FIELD_GET(MPAMCFG_PART_SEL_PARTID_SEL, reg32);
		ris_idx = FIELD_GET(MPAMCFG_PART_SEL_RIS, reg32);
		if (vpartid >= mpam_mdev_state->type->partids) {
			dev_err(mdev_dev(mpam_mdev_state->mdev),
				"vpartid %d is out of range.\n", vpartid);
			return;
		}
		reg32 = FIELD_PREP(MPAMCFG_PART_SEL_RIS, ris_idx) |
			FIELD_PREP(MPAMCFG_PART_SEL_PARTID_SEL,
				   mpam_mdev_state->poffset + vpartid);
		mpam_mdev_state->regs.part_sel = reg32;
		break;
	case MSMON_CFG_MON_SEL:
		/*
		 * TODO: Split part of the physical monitors to different
		 * guests.
		 * The current design will produce guest-incomprehensible
		 * values of MBWU counters, since different guests may
		 * use the same physical monitor.
		 */
		mpam_mdev_state->regs.mon_sel = reg32;
		break;
	case MSMON_CFG_CSU_CTL:
		mpam_mdev_state->regs.csu_ctl = reg32;
		break;
	case MSMON_CFG_CSU_FLT:
		vpartid = FIELD_GET(MSMON_CFG_CSU_FLT_PARTID, reg32);
		if (vpartid >= mpam_mdev_state->type->partids) {
			dev_err(mdev_dev(mpam_mdev_state->mdev),
				"vpartid %d is out of range.\n", vpartid);
			return;
		}
		reg32 &= ~MSMON_CFG_CSU_FLT_PARTID;
		reg32 |= FIELD_PREP(MSMON_CFG_CSU_FLT_PARTID,
				    mpam_mdev_state->poffset + vpartid);
		mpam_mdev_state->regs.csu_flt = reg32;
		break;
	case MSMON_CFG_MBWU_CTL:
		mpam_mdev_state->regs.mbwu_ctl = reg32;
		break;
	case MSMON_CFG_MBWU_FLT:
		vpartid = FIELD_GET(MSMON_CFG_MBWU_FLT_PARTID, reg32);
		if (vpartid >= mpam_mdev_state->type->partids) {
			dev_err(mdev_dev(mpam_mdev_state->mdev),
				"vpartid %d is out of range.\n", vpartid);
			return;
		}
		reg32 &= ~MSMON_CFG_MBWU_FLT_PARTID;
		reg32 |= FIELD_PREP(MSMON_CFG_MBWU_FLT_PARTID,
				    mpam_mdev_state->poffset + vpartid);
		mpam_mdev_state->regs.mbwu_flt = reg32;
		break;
	/* Registers affected by MPAMCFG_PART_SEL */
	case MPAMCFG_CPBM:
	case MPAMCFG_CMAX:
	case MPAMCFG_MBW_MIN:
	case MPAMCFG_MBW_MAX:
	case MPAMCFG_MBW_WINWD:
	case MPAMCFG_MBW_PBM:
	case MPAMCFG_PRI:
	case MPAMCFG_MBW_PROP:
	case MPAMCFG_INTPARTID:
		spin_lock(&msc->lock);
		__mpam_write_reg(msc, MPAMCFG_PART_SEL,
				 mpam_mdev_state->regs.part_sel);
		__mpam_write_reg(msc, offset, reg32);
		spin_unlock(&msc->lock);
		break;
	/* Registers affected by MSMON_CFG_MON_SEL */
	case MSMON_CSU:
	case MSMON_CSU_CAPTURE:
		spin_lock(&msc->lock);
		__mpam_write_reg(msc, MSMON_CFG_MON_SEL,
				 mpam_mdev_state->regs.mon_sel);
		__mpam_write_reg(msc, MSMON_CFG_CSU_CTL,
				 mpam_mdev_state->regs.csu_ctl);
		__mpam_write_reg(msc, MSMON_CFG_CSU_FLT,
				 mpam_mdev_state->regs.csu_flt);
		__mpam_write_reg(msc, offset, reg32);
		spin_unlock(&msc->lock);
		break;
	case MSMON_MBWU:
	case MSMON_MBWU_CAPTURE:
		spin_lock(&msc->lock);
		__mpam_write_reg(msc, MSMON_CFG_MON_SEL,
				 mpam_mdev_state->regs.mon_sel);
		__mpam_write_reg(msc, MSMON_CFG_MBWU_CTL,
				 mpam_mdev_state->regs.mbwu_ctl);
		__mpam_write_reg(msc, MSMON_CFG_MBWU_FLT,
				 mpam_mdev_state->regs.mbwu_flt);
		__mpam_write_reg(msc, offset, reg32);
		spin_unlock(&msc->lock);
		break;
	default:
		if (mpam_current_machine == MPAM_YITIAN710 &&
		    (offset == mpam_mdev_state->custom_reg_base_addr + MPAMF_CUST_WINDW_OFFSET ||
		     offset == mpam_mdev_state->custom_reg_base_addr + MPAMF_CUST_MBWC_OFFSET)) {
			spin_lock(&msc->lock);
			__mpam_write_reg(msc, MPAMCFG_PART_SEL,
					 mpam_mdev_state->regs.part_sel);
			__mpam_write_reg(msc, offset, reg32);
			spin_unlock(&msc->lock);
			memcpy(buf, &reg32, count);
			return;
		}
		dev_err(mdev_dev(mpam_mdev_state->mdev),
			"invalid mmr addr 0x%x to write.\n", offset);
	}
}

static void handle_mmr_read(struct mpam_mdev_state *mpam_mdev_state, u16 offset,
			    char *buf, u32 count)
{
	struct mpam_msc *msc;
	u16 ppartid;
	u32 reg32;

	msc = mpam_mdev_state->msc;

	switch (offset) {
	case MPAMF_IDR:
		spin_lock(&msc->lock);
		reg32 = __mpam_read_reg(msc, offset);
		spin_unlock(&msc->lock);
		reg32 &= ~MPAMF_IDR_PARTID_MAX;
		reg32 |= FIELD_PREP(MPAMF_IDR_PARTID_MAX,
				    mpam_mdev_state->type->partids - 1);
		memcpy(buf, &reg32, count);
		break;
	case MPAMCFG_PART_SEL:
		reg32 = mpam_mdev_state->regs.part_sel;
		ppartid = FIELD_GET(MPAMCFG_PART_SEL_PARTID_SEL, reg32);
		reg32 &= ~MPAMCFG_PART_SEL_PARTID_SEL;
		reg32 |= FIELD_PREP(MPAMCFG_PART_SEL_PARTID_SEL,
				    ppartid - mpam_mdev_state->poffset);
		memcpy(buf, &reg32, count);
		break;
	case MSMON_CFG_MON_SEL:
		reg32 = mpam_mdev_state->regs.mon_sel;
		memcpy(buf, &reg32, count);
		break;
	case MSMON_CFG_CSU_CTL:
		reg32 = mpam_mdev_state->regs.csu_ctl;
		memcpy(buf, &reg32, count);
		break;
	case MSMON_CFG_CSU_FLT:
		reg32 = mpam_mdev_state->regs.csu_flt;
		ppartid = FIELD_GET(MSMON_CFG_CSU_FLT_PARTID, reg32);
		reg32 &= ~MSMON_CFG_CSU_FLT_PARTID;
		reg32 |= FIELD_PREP(MSMON_CFG_CSU_FLT_PARTID,
				    ppartid - mpam_mdev_state->poffset);
		memcpy(buf, &reg32, count);
		break;
	case MSMON_CFG_MBWU_CTL:
		reg32 = mpam_mdev_state->regs.mbwu_ctl;
		memcpy(buf, &reg32, count);
		break;
	case MSMON_CFG_MBWU_FLT:
		reg32 = mpam_mdev_state->regs.mbwu_flt;
		ppartid = FIELD_GET(MSMON_CFG_MBWU_FLT_PARTID, reg32);
		reg32 &= ~MSMON_CFG_MBWU_FLT_PARTID;
		reg32 |= FIELD_PREP(MSMON_CFG_MBWU_FLT_PARTID,
				    ppartid - mpam_mdev_state->poffset);
		memcpy(buf, &reg32, count);
		break;
	/* Registers affected by MSMON_CFG_MON_SEL */
	case MSMON_CSU:
	case MSMON_CSU_CAPTURE:
		spin_lock(&msc->lock);
		__mpam_write_reg(msc, MSMON_CFG_MON_SEL,
				 mpam_mdev_state->regs.mon_sel);
		__mpam_write_reg(msc, MSMON_CFG_CSU_CTL,
				 mpam_mdev_state->regs.csu_ctl);
		__mpam_write_reg(msc, MSMON_CFG_CSU_FLT,
				 mpam_mdev_state->regs.csu_flt);
		reg32 = __mpam_read_reg(msc, offset);
		spin_unlock(&msc->lock);
		memcpy(buf, &reg32, count);
		break;
	case MSMON_MBWU:
	case MSMON_MBWU_CAPTURE:
		spin_lock(&msc->lock);
		__mpam_write_reg(msc, MSMON_CFG_MON_SEL,
				 mpam_mdev_state->regs.mon_sel);
		__mpam_write_reg(msc, MSMON_CFG_MBWU_CTL,
				 mpam_mdev_state->regs.mbwu_ctl);
		__mpam_write_reg(msc, MSMON_CFG_MBWU_FLT,
				 mpam_mdev_state->regs.mbwu_flt);
		reg32 = __mpam_read_reg(msc, offset);
		spin_unlock(&msc->lock);
		memcpy(buf, &reg32, count);
		break;
	default:
		if (mpam_current_machine == MPAM_YITIAN710 &&
		    (offset == mpam_mdev_state->custom_reg_base_addr + MPAMF_CUST_WINDW_OFFSET ||
		     offset == mpam_mdev_state->custom_reg_base_addr + MPAMF_CUST_MBWC_OFFSET)) {
			spin_lock(&msc->lock);
			__mpam_write_reg(msc, MPAMCFG_PART_SEL,
					 mpam_mdev_state->regs.part_sel);
			reg32 = __mpam_read_reg(msc, offset);
			spin_unlock(&msc->lock);
			memcpy(buf, &reg32, count);
			return;
		}
		spin_lock(&msc->lock);
		reg32 = __mpam_read_reg(msc, offset);
		spin_unlock(&msc->lock);
		memcpy(buf, &reg32, count);
	}
}

static ssize_t mdev_access(struct mpam_mdev_state *mpam_mdev_state, char *buf,
			   size_t count, loff_t pos, bool is_write)
{
	mutex_lock(&mpam_mdev_state->ops_lock);

	if (is_write)
		handle_mmr_write(mpam_mdev_state, pos, buf, count);
	else
		handle_mmr_read(mpam_mdev_state, pos, buf, count);

	mutex_unlock(&mpam_mdev_state->ops_lock);

	return count;
}

static ssize_t mpam_mdev_read(struct mdev_device *mdev, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct mpam_mdev_state *mpam_mdev_state = mdev_get_drvdata(mdev);
	unsigned int done = 0;
	u32 val;
	int ret;

	if (count != 4 || (*ppos % 4) ||
	    *ppos >= mpam_mdev_state->msc->mapped_hwpage_sz) {
		dev_err(mdev_dev(mpam_mdev_state->mdev),
			"%s: %s @0x%llx (unhandled)\n", __func__, "RD", *ppos);
		return -EINVAL;
	}

	while (count) {
		ret = mdev_access(mpam_mdev_state, (char *)&val, sizeof(val),
				  *ppos, false);

		if (ret < 0)
			return ret;

		if (copy_to_user(buf, &val, sizeof(val)))
			return -EFAULT;

		count -= 4;
		done += 4;
		*ppos += 4;
		buf += 4;
	}

	return done;
}

static ssize_t mpam_mdev_write(struct mdev_device *mdev, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct mpam_mdev_state *mpam_mdev_state = mdev_get_drvdata(mdev);
	unsigned int done = 0;
	u32 val;
	int ret;

	if (count != 4 || (*ppos % 4) ||
	    *ppos >= mpam_mdev_state->msc->mapped_hwpage_sz) {
		dev_err(mdev_dev(mpam_mdev_state->mdev),
			"%s: %s @0x%llx (unhandled)\n", __func__, "WR", *ppos);
		return -EINVAL;
	}

	while (count) {
		if (copy_from_user(&val, buf, sizeof(val)))
			return -EFAULT;

		ret = mdev_access(mpam_mdev_state, (char *)&val, sizeof(val),
				  *ppos, true);

		if (ret < 0)
			return ret;

		count -= 4;
		done += 4;
		*ppos += 4;
		buf += 4;
	}

	return done;
}

static long mpam_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd,
			    unsigned long arg)
{
	struct mpam_mdev_state *mpam_mdev_state;
	unsigned long minsz;

	mpam_mdev_state = mdev_get_drvdata(mdev);

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
	{
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.flags = VFIO_DEVICE_FLAGS_PLATFORM;
		info.num_regions = 1;
		info.num_irqs = 0;

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_GET_REGION_INFO:
	{
		struct vfio_region_info info;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		if (info.index > 0)
			return -EINVAL;

		info.offset = 0;
		info.size = mpam_mdev_state->msc->mapped_hwpage_sz;
		info.flags = VFIO_REGION_INFO_FLAG_READ |
			     VFIO_REGION_INFO_FLAG_WRITE;

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}

	default:
		return -EINVAL;
	}

	return -EFAULT;
}

static ssize_t name_show(struct mdev_type *mtype,
			 struct mdev_type_attribute *attr, char *buf)
{
	const struct mpam_mdev_type *type =
		&mpam_mdev_types[mtype_get_type_group_id(mtype)];

	return sprintf(buf, "%s\n", type->name);
}
static MDEV_TYPE_ATTR_RO(name);

static ssize_t description_show(struct mdev_type *mtype,
				struct mdev_type_attribute *attr, char *buf)
{
	const struct mpam_mdev_type *type =
		&mpam_mdev_types[mtype_get_type_group_id(mtype)];

	return sprintf(buf, "virtual mpam msc device with %d partids\n",
		       type ? type->partids  : 0);
}
static MDEV_TYPE_ATTR_RO(description);

static ssize_t device_api_show(struct mdev_type *mtype,
			       struct mdev_type_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PLATFORM_STRING);
}
static MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *mpam_mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_description.attr,
	&mdev_type_attr_device_api.attr,
	NULL,
};

static struct attribute_group mpam_mdev_type_group1 = {
	.name = MPAM_MDEV_TYPE_1,
	.attrs = mpam_mdev_types_attrs,
};

static struct attribute_group mpam_mdev_type_group2 = {
	.name = MPAM_MDEV_TYPE_2,
	.attrs = mpam_mdev_types_attrs,
};

static struct attribute_group mpam_mdev_type_group3 = {
	.name = MPAM_MDEV_TYPE_3,
	.attrs = mpam_mdev_types_attrs,
};

static struct attribute_group *mpam_mdev_type_groups[] = {
	&mpam_mdev_type_group1,
	&mpam_mdev_type_group2,
	&mpam_mdev_type_group3,
	NULL,
};

static int mpam_msc_vpartid_alloc(struct mpam_msc *msc, int type_sz)
{
	bool found = false;
	int i, j;

	for (i = 0; i <= mpam_mdev_partid_max; i += type_sz) {
		found = true;
		for (j = 0; j < type_sz; j++) {
			if (msc->vpartid_free_map & (1UL << (i + j))) {
				found = false;
				break;
			}
		}
		if (found) {
			for (j = 0; j < type_sz; j++)
				msc->vpartid_free_map |= (1UL << (i + j));
			break;
		}
	}

	if (found)
		return i;

	return -EBUSY;
}

static void mpam_vpartid_free(struct mpam_msc *msc, int sindex, int type_sz)
{
	int i;

	for (i = sindex; i < sindex + type_sz; i++)
		msc->vpartid_free_map &= ~(1UL << i);
}

static int mpam_mdev_create(struct mdev_device *mdev)
{
	struct mpam_mdev_state *mpam_mdev_state;
	u32 mpam_impl_idr_val = 0;
	struct mpam_msc *msc;
	u16 poffset, voffset;

	const struct mpam_mdev_type *type =
		&mpam_mdev_types[mdev_get_type_group_id(mdev)];

	msc = (struct mpam_msc *)dev_get_drvdata(mdev->dev.parent);
	if (!msc)
		return -EINVAL;

	spin_lock(&msc->lock);

	voffset = mpam_msc_vpartid_alloc(msc, type->partids);
	if (voffset < 0) {
		spin_unlock(&msc->lock);
		return -EBUSY;
	}

	poffset = physical_partid_offset + voffset;

	mpam_impl_idr_val = __mpam_read_reg(msc, MPAMF_IMPL_IDR);

	spin_unlock(&msc->lock);

	mpam_mdev_state = kzalloc(sizeof(struct mpam_mdev_state), GFP_KERNEL);
	if (!mpam_mdev_state)
		return -ENOMEM;

	mpam_mdev_state->mdev = mdev;
	mpam_mdev_state->msc = msc;
	mpam_mdev_state->type = type;

	mpam_mdev_state->poffset = poffset;
	mpam_mdev_state->voffset = voffset;

	/* Init the saved regs's default PARTID with poffset */
	mpam_mdev_state->regs.part_sel |= FIELD_PREP(MPAMCFG_PART_SEL_PARTID_SEL,
						     poffset);
	mpam_mdev_state->regs.csu_flt |= FIELD_PREP(MSMON_CFG_CSU_FLT_PARTID,
						    poffset);
	mpam_mdev_state->regs.mbwu_flt |= FIELD_PREP(MSMON_CFG_MBWU_FLT_PARTID,
						     poffset);

	if (mpam_current_machine == MPAM_YITIAN710)
		mpam_mdev_state->custom_reg_base_addr = mpam_impl_idr_val;

	mdev_set_drvdata(mdev, mpam_mdev_state);

	return 0;
}

static int mpam_mdev_remove(struct mdev_device *mdev)
{
	struct mpam_mdev_state *mpam_mdev_state = mdev_get_drvdata(mdev);
	struct mpam_msc *msc = mpam_mdev_state->msc;

	spin_lock(&msc->lock);
	mpam_vpartid_free(msc, mpam_mdev_state->voffset,
			  mpam_mdev_state->type->partids);
	spin_unlock(&msc->lock);
	mdev_set_drvdata(mdev, NULL);
	kfree(mpam_mdev_state);
	return 0;
}

static int mpam_mdev_open_device(struct mdev_device *mdev)
{
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	return 0;
}

static void mpam_mdev_close_device(struct mdev_device *mdev)
{
	module_put(THIS_MODULE);
}

static ssize_t
partids_show(struct device *dev, struct device_attribute *attr,
	    char *buf)
{
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct mpam_mdev_state *mpam_mdev_state = mdev_get_drvdata(mdev);

	return sprintf(buf, "%d\n", mpam_mdev_state->type->partids);
}
static DEVICE_ATTR_RO(partids);

static ssize_t
class_type_show(struct device *dev, struct device_attribute *attr,
	   char *buf)
{
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct mpam_mdev_state *mpam_mdev_state = mdev_get_drvdata(mdev);
	struct mpam_msc *msc = mpam_mdev_state->msc;
	bool class_types_found = false;
	enum mpam_class_types type = MPAM_CLASS_UNKNOWN;
	struct mpam_msc_ris *ris;

	mutex_lock(&mpam_list_lock);
	list_for_each_entry(ris, &msc->ris, msc_list) {
		if (!class_types_found) {
			type = ris->comp->class->type;
			class_types_found = true;
		} else {
			if (ris->comp->class->type != type)
				type = MPAM_CLASS_UNKNOWN;
		}
	}
	mutex_unlock(&mpam_list_lock);

	switch (type) {
	case MPAM_CLASS_CACHE:
		return sprintf(buf, "%s\n", "cache");
	case MPAM_CLASS_MEMORY:
		return sprintf(buf, "%s\n", "memory");
	case MPAM_CLASS_UNKNOWN:
		return sprintf(buf, "%s\n", "unknown");
	}

	return sprintf(buf, "%s\n", "unknown");
}
static DEVICE_ATTR_RO(class_type);

static ssize_t
domain_id_show(struct device *dev, struct device_attribute *attr,
	     char *buf)
{
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct mpam_mdev_state *mpam_mdev_state = mdev_get_drvdata(mdev);
	struct mpam_msc *msc = mpam_mdev_state->msc;
	bool domain_found = false;
	int domain_id = -1;
	struct mpam_msc_ris *ris;

	mutex_lock(&mpam_list_lock);
	list_for_each_entry(ris, &msc->ris, msc_list) {
		if (!domain_found) {
			domain_id = ris->comp->comp_id;
			domain_found = true;
		} else {
			if (ris->comp->comp_id != domain_id)
				domain_id = -1;
		}
	}
	mutex_unlock(&mpam_list_lock);

	return sprintf(buf, "%d\n", domain_id);
}
static DEVICE_ATTR_RO(domain_id);

static ssize_t
vpartid_offset_show(struct device *dev, struct device_attribute *attr,
		    char *buf)
{
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct mpam_mdev_state *mpam_mdev_state = mdev_get_drvdata(mdev);

	return sprintf(buf, "%u\n", mpam_mdev_state->voffset);
}
static DEVICE_ATTR_RO(vpartid_offset);

static ssize_t
ddrc_freq_show(struct device *dev, struct device_attribute *attr,
		 char *buf)
{
	return sprintf(buf, "%d\n", READ_ONCE(yitian710_ddrc_freq));
}
static DEVICE_ATTR_RO(ddrc_freq);

static struct attribute *mpam_mdev_dev_attrs[] = {
	&dev_attr_partids.attr,
	&dev_attr_class_type.attr,
	&dev_attr_domain_id.attr,
	&dev_attr_vpartid_offset.attr,
	&dev_attr_ddrc_freq.attr,
	NULL,
};

static const struct attribute_group mpam_mdev_dev_group = {
	.name = "vendor",
	.attrs = mpam_mdev_dev_attrs,
};

static const struct attribute_group *mpam_mdev_dev_groups[] = {
	&mpam_mdev_dev_group,
	NULL,
};

static const struct mdev_parent_ops mpam_mdev_ops = {
	.owner = THIS_MODULE,
	.mdev_attr_groups = mpam_mdev_dev_groups,
	.supported_type_groups = mpam_mdev_type_groups,
	.create = mpam_mdev_create,
	.remove = mpam_mdev_remove,
	.open_device = mpam_mdev_open_device,
	.close_device = mpam_mdev_close_device,
	.read = mpam_mdev_read,
	.write = mpam_mdev_write,
	.ioctl = mpam_mdev_ioctl,
};

#define mpam_write_vpmn_reg(vpmn, vpartid, ppartid)		\
({								\
	u64 __reg64;						\
	u64 __ppartid = ppartid;				\
	u64 __mask = 0xffff;					\
								\
	__reg64 = read_sysreg_s(SYS_MPAM_VPMn_EL2(vpmn));	\
								\
	__reg64 &= ~(__mask << ((vpartid % 4) * 16));		\
	__reg64 |= (__ppartid << ((vpartid % 4) * 16));		\
	write_sysreg_s(__reg64, SYS_MPAM_VPMn_EL2(vpmn));	\
})

static int map_vpartid_to_ppartid(u16 vpartid, u16 ppartid)
{
	switch (vpartid / 4) {
	case 0:
		mpam_write_vpmn_reg(0, vpartid, ppartid);
		break;
	case 1:
		mpam_write_vpmn_reg(1, vpartid, ppartid);
		break;
	case 2:
		mpam_write_vpmn_reg(2, vpartid, ppartid);
		break;
	case 3:
		mpam_write_vpmn_reg(3, vpartid, ppartid);
		break;
	case 4:
		mpam_write_vpmn_reg(4, vpartid, ppartid);
		break;
	case 5:
		mpam_write_vpmn_reg(5, vpartid, ppartid);
		break;
	case 6:
		mpam_write_vpmn_reg(6, vpartid, ppartid);
		break;
	case 7:
		mpam_write_vpmn_reg(7, vpartid, ppartid);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int mpam_mdev_cpu_online(unsigned int cpu)
{
	u16 vpartid;

	write_sysreg_s(GENMASK(mpam_mdev_partid_max, 0), SYS_MPAMVPMV_EL2);

	for (vpartid = 0; vpartid <= mpam_mdev_partid_max; vpartid++)
		map_vpartid_to_ppartid(vpartid,
				       vpartid + physical_partid_offset);

	return 0;
}

static int mpam_mdev_cpu_offline(unsigned int cpu)
{
	u16 vpartid;

	write_sysreg_s(0, SYS_MPAMVPMV_EL2);

	for (vpartid = 0; vpartid <= mpam_mdev_partid_max; vpartid++)
		map_vpartid_to_ppartid(vpartid, 0);

	return 0;
}

static int mpam_mdev_register_all_msc(void)
{
	struct platform_device *pdev;
	struct mpam_msc *msc;
	int ret = 0;

	mutex_lock(&mpam_list_lock);
	list_for_each_entry(msc, &mpam_all_msc, glbl_list) {
		pdev = msc->pdev;
		ret = mdev_register_device(&pdev->dev, &mpam_mdev_ops);
		if (ret)
			break;
	}

	mutex_unlock(&mpam_list_lock);

	return ret;
}

static void mpam_mdev_unregister_all_msc(void)
{
	struct platform_device *pdev;
	struct mpam_msc *msc;

	mutex_lock(&mpam_list_lock);
	list_for_each_entry(msc, &mpam_all_msc, glbl_list) {
		pdev = msc->pdev;
		mdev_unregister_device(&pdev->dev);
	}
	mutex_unlock(&mpam_list_lock);
}

static int __init mpam_mdev_init(void)
{
	u16 mpam_mdev_partid_num;
	u64 mpamidr;
	int ret = 0;

	if (!mpam_is_enabled()) {
		pr_err("MPAM is not enabled.\n");
		return -EOPNOTSUPP;
	}

	mpamidr = read_sysreg_s(SYS_MPAMIDR_EL1);
	if (!(mpamidr & MPAMIDR_HAS_HCR)) {
		pr_err("MPAM does not support virtualization.\n");
		return -EOPNOTSUPP;
	}

	/* Split part of the physical partids for guests. */
	spin_lock(&partid_max_lock);
	mpam_mdev_partid_num = min((mpam_partid_max+1) / 2, 32);
	mpam_mdev_partid_max = mpam_mdev_partid_num - 1;
	mpam_partid_max -= mpam_mdev_partid_num;
	physical_partid_offset = mpam_partid_max + 1;
	spin_unlock(&partid_max_lock);

	ret = mpam_mdev_register_all_msc();
	if (ret) {
		mpam_mdev_unregister_all_msc();
		return ret;
	}

	enable_mpam_hcr();

	mpam_mdev_cpuhp_state = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
						  "mpam_mdev:online",
						  mpam_mdev_cpu_online,
						  mpam_mdev_cpu_offline);

	if (mpam_mdev_cpuhp_state <= 0) {
		pr_err("Failed to register mpam mdev cpuhp callbacks");
		mpam_mdev_cpuhp_state = 0;
	}

	return 0;
}

static void __exit mpam_mdev_exit(void)
{
	if (mpam_mdev_cpuhp_state) {
		cpuhp_remove_state(mpam_mdev_cpuhp_state);
		mpam_mdev_cpuhp_state = 0;
	}

	mpam_mdev_unregister_all_msc();

	disable_mpam_hcr();

	/* Return the partids to the host. */
	spin_lock(&partid_max_lock);
	mpam_partid_max += (mpam_mdev_partid_max + 1);
	spin_unlock(&partid_max_lock);
}

module_init(mpam_mdev_init);
module_exit(mpam_mdev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shawn Wang");
