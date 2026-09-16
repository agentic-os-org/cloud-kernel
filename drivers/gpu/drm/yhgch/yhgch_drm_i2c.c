// SPDX-License-Identifier: GPL-2.0

#include <linux/delay.h>
#include <linux/pci.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_probe_helper.h>

#include "yhgch_drm_drv.h"

#define GPIO_DATA		0x0802A0
#define GPIO_DATA_DIRECTION	0x0802A4	//Currently, the 0x802a4 use high for input and low for output

#define I2C_SCL_MASK		BIT(0)
#define I2C_SDA_MASK		BIT(1)

static void yhgch_set_i2c_signal(void *data, u32 mask, int value)
{
	struct yhgch_connector *yhgch_connector = data;
	struct yhgch_drm_private *priv =
	    to_yhgch_drm_private(yhgch_connector->base.dev);
	u32 tmp_dir = readl(priv->mmio + GPIO_DATA_DIRECTION);

	if (value) {
		tmp_dir |= mask;
		writel(tmp_dir, priv->mmio + GPIO_DATA_DIRECTION);
	} else {
		u32 tmp_data = readl(priv->mmio + GPIO_DATA);

		tmp_data &= ~mask;
		writel(tmp_data, priv->mmio + GPIO_DATA);

		tmp_dir &= ~mask;
		writel(tmp_dir, priv->mmio + GPIO_DATA_DIRECTION);
	}
}

static int yhgch_get_i2c_signal(void *data, u32 mask)
{
	struct yhgch_connector *yhgch_connector = data;
	struct yhgch_drm_private *priv =
	    to_yhgch_drm_private(yhgch_connector->base.dev);
	u32 tmp_dir = readl(priv->mmio + GPIO_DATA_DIRECTION);

	if (((~tmp_dir) & mask) != mask) {
		tmp_dir |= mask;
		writel(tmp_dir, priv->mmio + GPIO_DATA_DIRECTION);
	}
	return (readl(priv->mmio + GPIO_DATA) & mask) ? 1 : 0;
}

static void yhgch_ddc_setsda(void *data, int state)
{
	yhgch_set_i2c_signal(data, I2C_SDA_MASK, state);
}

static void yhgch_ddc_setscl(void *data, int state)
{
	yhgch_set_i2c_signal(data, I2C_SCL_MASK, state);
}

static int yhgch_ddc_getsda(void *data)
{
	return yhgch_get_i2c_signal(data, I2C_SDA_MASK);
}

static int yhgch_ddc_getscl(void *data)
{
	return yhgch_get_i2c_signal(data, I2C_SCL_MASK);
}

int yhgch_ddc_create(struct drm_device *drm_dev,
		      struct yhgch_connector *connector)
{
	connector->adapter.owner = THIS_MODULE;
	connector->adapter.class = I2C_CLASS_DDC;
	snprintf(connector->adapter.name, I2C_NAME_SIZE, "YHGCH i2c bit bus");
	connector->adapter.dev.parent = &drm_dev->pdev->dev;
	i2c_set_adapdata(&connector->adapter, connector);
	connector->adapter.algo_data = &connector->bit_data;

	connector->bit_data.udelay = 20;
	connector->bit_data.timeout = usecs_to_jiffies(2000);
	connector->bit_data.data = connector;
	connector->bit_data.setsda = yhgch_ddc_setsda;
	connector->bit_data.setscl = yhgch_ddc_setscl;
	connector->bit_data.getsda = yhgch_ddc_getsda;
	connector->bit_data.getscl = yhgch_ddc_getscl;

	return i2c_bit_add_bus(&connector->adapter);
}
