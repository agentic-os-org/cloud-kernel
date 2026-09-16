// SPDX-License-Identifier: GPL-2.0

#include <linux/console.h>
#include <linux/module.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_probe_helper.h>

#include "yhgch_drm_drv.h"
#include "yhgch_drm_regs.h"

#define MEM_SIZE_RESERVE4KVM 0x400000

#define DRM_YHGCH_VRAM_TYPE_DEVICE 0x0
#define DRM_IOCTL_YHGCH_VRAM_TYPE_DEVICE \
	DRM_IO(DRM_COMMAND_BASE + DRM_YHGCH_VRAM_TYPE_DEVICE)

static int yhgch_ioctl_check_5c01_device(struct drm_device *dev, void *data,
					 struct drm_file *file_priv)
{
	struct yhgch_drm_private *priv = dev->dev_private;

	(void)data;
	(void)file_priv;
	return priv->is_5c01_device ? 1 : 0;
}

static const struct drm_ioctl_desc yhgch_ioctls[] = {
	DRM_IOCTL_DEF_DRV(YHGCH_VRAM_TYPE_DEVICE,
			  yhgch_ioctl_check_5c01_device,
			  DRM_AUTH | DRM_UNLOCKED),
};

DEFINE_DRM_GEM_FOPS(yhgch_fops);
irqreturn_t yhgch_drm_interrupt(int irq, void *arg)
{
	struct drm_device *dev = (struct drm_device *)arg;
	struct yhgch_drm_private *priv =
	    (struct yhgch_drm_private *)dev->dev_private;
	u32 status;

	status = readl(priv->mmio + YHGCH_RAW_INTERRUPT);

	if (status & YHGCH_RAW_INTERRUPT_VBLANK(1)) {
		writel(YHGCH_RAW_INTERRUPT_VBLANK(1),
		       priv->mmio + YHGCH_RAW_INTERRUPT);
		drm_handle_vblank(dev, 0);
	}

	return IRQ_HANDLED;
}

static struct drm_driver yhgch_driver = {
	.driver_features = DRIVER_GEM | DRIVER_MODESET |
	    DRIVER_ATOMIC | DRIVER_HAVE_IRQ,

	.fops = &yhgch_fops,
	.ioctls = yhgch_ioctls,
	.num_ioctls = ARRAY_SIZE(yhgch_ioctls),
	.name = "yhgch",
	.date = "20251014",
	.desc = "yhgch drm driver",
	.major = 3,
	.minor = 6,
	.dumb_create = yhgch_dumb_create,
	.dumb_map_offset = drm_gem_vram_driver_dumb_mmap_offset,
};

static bool yhgch_check_pci_host_5c01(struct pci_bus *bus)
{
	struct pci_bus *root_bus;
	struct pci_dev *root;

	if (!bus)
		return false;

	root_bus = bus;
	while (root_bus->parent && root_bus->parent->parent)
		root_bus = root_bus->parent;

	root = root_bus->self;
	if (!root)
		return false;

	return root->vendor == 0x1db7 && root->device == 0x5c01;
}

static void yhgch_remove_framebuffers(struct pci_dev *pdev)
{
	struct apertures_struct *ap;

	ap = alloc_apertures(1);
	if (!ap)
		return;

	ap->ranges[0].base = pci_resource_start(pdev, 0);
	ap->ranges[0].size = pci_resource_len(pdev, 0);

	drm_fb_helper_remove_conflicting_pci_framebuffers(pdev, "yhgchdrmfb");

	kfree(ap);
}

static int __maybe_unused yhgch_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	struct yhgch_drm_private *priv = drm_dev->dev_private;

	drm_kms_helper_poll_disable(drm_dev);
	priv->suspend_state = drm_atomic_helper_suspend(drm_dev);
	if (IS_ERR(priv->suspend_state)) {
		DRM_ERROR("drm_atomic_helper_suspend failed: %ld\n",
			  PTR_ERR(priv->suspend_state));
		drm_kms_helper_poll_enable(drm_dev);
		return PTR_ERR(priv->suspend_state);
	}

	return 0;
}

static int __maybe_unused yhgch_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);
	struct yhgch_drm_private *priv = drm_dev->dev_private;

	drm_atomic_helper_resume(drm_dev, priv->suspend_state);
	drm_kms_helper_poll_enable(drm_dev);

	return 0;
}

static const struct dev_pm_ops yhgch_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(yhgch_pm_suspend,
				yhgch_pm_resume)
};

static int yhgch_kms_init(struct yhgch_drm_private *priv)
{
	int ret;

	drm_mode_config_init(priv->dev);
	priv->mode_config_initialized = true;

	priv->dev->mode_config.min_width = 0;
	priv->dev->mode_config.min_height = 0;
	priv->dev->mode_config.max_width = 1920;
	priv->dev->mode_config.max_height = 1200;
	priv->dev->mode_config.fb_base = priv->fb_base;
	priv->dev->mode_config.preferred_depth = 32;
	priv->dev->mode_config.prefer_shadow = 1;
	priv->dev->mode_config.funcs = (void *)&yhgch_mode_funcs;

	ret = yhgch_de_init(priv);
	if (ret) {
		DRM_ERROR("failed to init de: %d\n", ret);
		return ret;
	}

	ret = yhgch_vdac_init(priv);
	if (ret) {
		DRM_ERROR("failed to init vdac: %d\n", ret);
		return ret;
	}

	return 0;
}

static void yhgch_kms_fini(struct yhgch_drm_private *priv)
{
	if (priv->mode_config_initialized) {
		drm_mode_config_cleanup(priv->dev);
		priv->mode_config_initialized = false;
	}
}

/*
 * It can operate in one of three modes: 0, 1 or Sleep.
 */
void yhgch_set_power_mode(struct yhgch_drm_private *priv,
			   unsigned int power_mode)
{
	unsigned int control_value = 0;
	void __iomem *mmio = priv->mmio;
	unsigned int input = 1;

	if (power_mode > YHGCH_PW_MODE_CTL_MODE_SLEEP)
		return;

	if (power_mode == YHGCH_PW_MODE_CTL_MODE_SLEEP)
		input = 0;

	control_value = readl(mmio + YHGCH_POWER_MODE_CTRL);
	control_value &= ~(YHGCH_PW_MODE_CTL_MODE_MASK |
			   YHGCH_PW_MODE_CTL_OSC_INPUT_MASK);
	control_value |= YHGCH_FIELD(YHGCH_PW_MODE_CTL_MODE, power_mode);
	control_value |= YHGCH_FIELD(YHGCH_PW_MODE_CTL_OSC_INPUT, input);
	writel(control_value, mmio + YHGCH_POWER_MODE_CTRL);
}

void yhgch_set_current_gate(struct yhgch_drm_private *priv, unsigned int gate)
{
	unsigned int gate_reg;
	unsigned int mode;
	void __iomem *mmio = priv->mmio;

	/* Get current power mode. */
	mode = (readl(mmio + YHGCH_POWER_MODE_CTRL) &
		YHGCH_PW_MODE_CTL_MODE_MASK) >> YHGCH_PW_MODE_CTL_MODE_SHIFT;

	switch (mode) {
	case YHGCH_PW_MODE_CTL_MODE_MODE0:
		gate_reg = YHGCH_MODE0_GATE;
		break;

	case YHGCH_PW_MODE_CTL_MODE_MODE1:
		gate_reg = YHGCH_MODE1_GATE;
		break;

	default:
		gate_reg = YHGCH_MODE0_GATE;
		break;
	}
	writel(gate, mmio + gate_reg);
}

static void yhgch_hw_config(struct yhgch_drm_private *priv)
{
	unsigned int reg;

	/* On hardware reset, power mode 0 is default. */
	yhgch_set_power_mode(priv, YHGCH_PW_MODE_CTL_MODE_MODE0);

	/* Enable display power gate & LOCALMEM power gate */
	reg = readl(priv->mmio + YHGCH_CURRENT_GATE);
	reg &= ~YHGCH_CURR_GATE_DISPLAY_MASK;
	reg &= ~YHGCH_CURR_GATE_LOCALMEM_MASK;
	reg |= YHGCH_CURR_GATE_DISPLAY(1);
	reg |= YHGCH_CURR_GATE_LOCALMEM(1);

	yhgch_set_current_gate(priv, reg);

	/*
	 * Reset the memory controller. If the memory controller
	 * is not reset in chip,the system might hang when sw accesses
	 * the memory.The memory should be resetted after
	 * changing the MXCLK.
	 */
	reg = readl(priv->mmio + YHGCH_MISC_CTRL);
	reg &= ~YHGCH_MSCCTL_LOCALMEM_RESET_MASK;
	reg |= YHGCH_MSCCTL_LOCALMEM_RESET(0);
	writel(reg, priv->mmio + YHGCH_MISC_CTRL);

	reg &= ~YHGCH_MSCCTL_LOCALMEM_RESET_MASK;
	reg |= YHGCH_MSCCTL_LOCALMEM_RESET(1);

	writel(reg, priv->mmio + YHGCH_MISC_CTRL);
}

static int yhgch_hw_map(struct yhgch_drm_private *priv)
{
	struct drm_device *dev = priv->dev;
	struct pci_dev *pdev = to_pci_dev(dev->dev);
	resource_size_t addr, size, ioaddr, iosize;

	ioaddr = pci_resource_start(pdev, 1);
	iosize = pci_resource_len(pdev, 1);
	priv->mmio = devm_ioremap(dev->dev, ioaddr, iosize);
	if (!priv->mmio) {
		DRM_ERROR("Cannot map mmio region\n");
		return -ENOMEM;
	}

	addr = pci_resource_start(pdev, 0);
	size = pci_resource_len(pdev, 0);
	if (priv->is_5c01_device) {
		priv->fb_map = devm_ioremap(dev->dev, addr, size);
	} else {
		arch_io_reserve_memtype_wc(addr, size);
		arch_phys_wc_add(addr, size);
		priv->fb_map = devm_ioremap_wc(dev->dev, addr, size);
	}
	if (!priv->fb_map) {
		DRM_ERROR("Cannot map framebuffer\n");
		return -ENOMEM;
	}
#ifdef CONFIG_X86
	if (!priv->is_5c01_device)
		set_memory_wc((unsigned long)addr, size >> PAGE_SHIFT);
#endif
	priv->fb_base = addr;
	priv->fb_size = size - MEM_SIZE_RESERVE4KVM;

	return 0;
}

static void yhgch_hw_unmap(struct yhgch_drm_private *priv)
{
	struct drm_device *dev = priv->dev;
	if (priv->mmio) {
		devm_iounmap(dev->dev, priv->mmio);
		priv->mmio = NULL;
	}
	if (priv->fb_map) {
		devm_iounmap(dev->dev, priv->fb_map);
		priv->fb_map = NULL;
	}
}

static int yhgch_hw_init(struct yhgch_drm_private *priv)
{
	int ret;

	ret = yhgch_hw_map(priv);
	if (ret)
		return ret;

	yhgch_hw_config(priv);

	return 0;
}

void yhgch_unload(struct drm_device *dev)
{
	struct yhgch_drm_private *priv = dev->dev_private;
	drm_atomic_helper_shutdown(dev);
	yhgch_kms_fini(priv);
    yhgch_hw_unmap(priv);
	dev->dev_private = NULL;
}

int yhgch_load(struct drm_device *dev, unsigned long flags)
{
	struct yhgch_drm_private *priv;
	struct pci_dev *pdev = to_pci_dev(dev->dev);
	int ret;

	priv = devm_kzalloc(dev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		DRM_ERROR("no memory to allocate for yhgch_drm_private\n");
		return -ENOMEM;
	}
	dev->dev_private = priv;
	priv->dev = dev;
	priv->is_5c01_device = yhgch_check_pci_host_5c01(pdev->bus);

	ret = yhgch_hw_init(priv);
	if (ret)
		goto err;

	ret =
	    drmm_vram_helper_init(dev, pci_resource_start(pdev, 0),
				  priv->fb_size);
	if (ret) {
		drm_err(dev, "Error initializing VRAM MM; %d\n", ret);
		goto err;
	}
	if (priv->is_5c01_device)
		yhgch_ttm_enable_5c01_io_mem_reserve(dev);

	ret = yhgch_kms_init(priv);
	if (ret)
		goto err;

	/* reset all the states of crtc/plane/encoder/connector */
	drm_mode_config_reset(dev);

	return 0;

err:
	yhgch_unload(dev);
	DRM_ERROR("failed to initialize drm driver: %d\n", ret);
	return ret;
}

static int yhgch_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *ent)
{
	int ret = 0;
	struct drm_device *dev;

	yhgch_remove_framebuffers(pdev);

	dev = drm_dev_alloc(&yhgch_driver, &pdev->dev);
	if (IS_ERR(dev)) {
		DRM_ERROR("failed to allocate drm_device\n");
		return PTR_ERR(dev);
	}

	dev->pdev = pdev;
	pci_set_drvdata(pdev, dev);
	ret = pci_enable_device(pdev);
	if (ret) {
		drm_err(dev, "failed to enable pci device: %d\n", ret);
		return ret;
	}
	ret = yhgch_load(dev, ent->driver_data);
	if (ret)
		goto err_return;

	ret = drm_dev_register(dev, ent->driver_data);
	if (ret)
		goto err_yhgch_driver_unload;

	drm_fbdev_generic_setup(dev, dev->mode_config.preferred_depth);

	return 0;
err_yhgch_driver_unload:
	yhgch_unload(dev);
err_return:
	return ret;
}






static void yhgch_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);

	drm_dev_unregister(dev);
	yhgch_unload(dev);
}

static void yhgch_pci_shutdown(struct pci_dev *pdev)
{
	yhgch_pci_remove(pdev);
}

static struct pci_device_id yhgch_pci_table[] = {
	{ 0x1bd4, 0x0750, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ 0, }
};

static struct pci_driver yhgch_pci_driver = {
	.name = "yhgch-drm",
	.id_table = yhgch_pci_table,
	.probe = yhgch_pci_probe,
	.remove = yhgch_pci_remove,
	.shutdown = yhgch_pci_shutdown,
	.driver.pm = &yhgch_pm_ops,
};

static int __init yhgch_init(void)
{
	if (vgacon_text_force())
		return -ENODEV;
	return pci_register_driver(&yhgch_pci_driver);
}

static void __exit yhgch_exit(void)
{
	return pci_unregister_driver(&yhgch_pci_driver);
}

module_init(yhgch_init);
module_exit(yhgch_exit);

MODULE_DEVICE_TABLE(pci, yhgch_pci_table);
MODULE_AUTHOR("");
MODULE_DESCRIPTION("DRM Driver for YHGCHBMC");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("3.6");
