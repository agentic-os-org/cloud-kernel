// SPDX-License-Identifier: GPL-2.0

#include <linux/string.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_gem_vram_helper.h>
#include <drm/ttm/ttm_bo_driver.h>
#include <drm/ttm/ttm_placement.h>
#include <drm/ttm/ttm_resource.h>

#include "yhgch_drm_drv.h"

static int yhgch_ttm_io_mem_reserve(struct ttm_bo_device *bdev,
				    struct ttm_resource *mem)
{
	struct drm_vram_mm *vmm = drm_vram_mm_of_bdev(bdev);

	switch (mem->mem_type) {
	case TTM_PL_SYSTEM:
		break;
	case TTM_PL_VRAM:
		mem->bus.offset = (mem->start << PAGE_SHIFT) + vmm->vram_base;
		mem->bus.is_iomem = true;
		mem->placement = TTM_PL_FLAG_UNCACHED;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static struct ttm_bo_driver yhgch_vram_driver_override;

void yhgch_ttm_enable_5c01_io_mem_reserve(struct drm_device *dev)
{
	struct drm_vram_mm *vmm = dev->vram_mm;

	if (!vmm || !vmm->bdev.driver)
		return;

	memcpy(&yhgch_vram_driver_override, vmm->bdev.driver,
	       sizeof(yhgch_vram_driver_override));
	yhgch_vram_driver_override.io_mem_reserve = yhgch_ttm_io_mem_reserve;
	vmm->bdev.driver = &yhgch_vram_driver_override;
}

int yhgch_dumb_create(struct drm_file *file, struct drm_device *dev,
		       struct drm_mode_create_dumb *args)
{

	return drm_gem_vram_fill_create_dumb(file, dev, 0, 16, args);
}

const struct drm_mode_config_funcs yhgch_mode_funcs = {
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
	.fb_create = drm_gem_fb_create,
	.mode_valid = drm_vram_helper_mode_valid,
};
