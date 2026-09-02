// SPDX-License-Identifier: GPL-2.0-only

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>

#include "xuantie_ntrace.h"

#define IOMMU_DMA_BUF_SIZE (64 * SZ_1M)

static int xuantie_ntrace_sink_probe(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	struct xuantie_ntrace_component *component;
	struct device_node *child_node, *port_node;
	struct xuantie_io_port *io_port;
	struct resource resv_mem;
	struct resource *res;
	resource_size_t base, size;
	dma_addr_t dma_addr;
	u32 reg[4];
	int port_nr = 0;
	int nr;
	int ret;
	static char *default_work_mode = "circulating buffer";
	static char *default_format = "original";

	component = kzalloc(sizeof(*component), GFP_KERNEL);
	if (!component)
		return -ENOMEM;
	component->type = NTRACE_TYPE_SINK_SMEM;
	component->pdev = pdev;

	// Get register base and size
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get 'reg' resource\n");
		goto err_free_component;
	}
	base = res->start;
	size = resource_size(res);
	dev_info(&pdev->dev, "base=0x%llx size=0x%llx\n", (u64)base, (u64)size);

	// Map registers
	component->reg_base = (unsigned long)ioremap(base, size);
	if (!component->reg_base) {
		dev_err(&pdev->dev, "Failed to ioremap registers\n");
		ret = -ENXIO;
		goto err_free_component;
	}
	component->reg_size = size;
	dev_info(&pdev->dev, "reg_base=0x%llx reg_size=0x%llx\n",
		 (u64)component->reg_base, (u64)component->reg_size);

	ret = of_property_read_string(node, "working_mode", &component->sink.working_mode);
	if (ret)
		component->sink.working_mode = default_work_mode;
	dev_info(&pdev->dev, "working_mode=%s\n", component->sink.working_mode);

	ret = of_property_read_string(node, "format", &component->sink.format);
	if (ret)
		component->sink.format = default_format;
	dev_info(&pdev->dev, "format=%s\n", component->sink.format);

	child_node = of_parse_phandle(node, "memory-region", 0);
	if (!child_node) {
		u32 dma_buf_size = IOMMU_DMA_BUF_SIZE;

		component->sink.is_resv_mem = false;

		of_property_read_u32(node, "iommu-trace-buffer-size", &dma_buf_size);
		if (!dma_buf_size)
			dma_buf_size = IOMMU_DMA_BUF_SIZE;

		ret = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(48)); // ntrace sink max-width is 48
		if (ret)
			dev_warn(&pdev->dev,
				 "Failed to set 48-bit coherent DMA mask (%d), keeping the default mask\n",
				 ret);
		component->sink.vaddr = dma_alloc_coherent(&pdev->dev, dma_buf_size, &dma_addr, GFP_KERNEL);
		if (!component->sink.vaddr) {
			dev_err(&pdev->dev, "dma_alloc_coherent failed (size=0x%x)\n", dma_buf_size);
			ret = -ENOMEM;
			goto err_unmap;
		}
		component->sink.start_addr = dma_addr;
		component->sink.limit_addr = dma_addr + dma_buf_size;
		dev_info(&pdev->dev, "dma_alloc_coherent vaddr=%px dma_addr=%llx size=%x\n",
			 component->sink.vaddr, component->sink.start_addr, dma_buf_size);
	} else {
		ret = of_address_to_resource(child_node, 0, &resv_mem);
		of_node_put(child_node);
		if (ret) {
			dev_err(&pdev->dev, "Failed to find 'reserved-memory'\n");
			goto err_unmap;
		}
		component->sink.vaddr = memremap(resv_mem.start, resv_mem.end - resv_mem.start + 1, MEMREMAP_WB);
		if (!component->sink.vaddr) {
			dev_err(&pdev->dev, "Failed to memremap reserved-memory\n");
			ret = -ENOMEM;
			goto err_unmap;
		}
		component->sink.start_addr = resv_mem.start;
		component->sink.limit_addr = resv_mem.end;
		component->sink.is_resv_mem = true;
		dev_info(&pdev->dev, "reserved-memory {0x%llx-0x%llx}@0x%px\n",
			 (u64)component->sink.start_addr, (u64)component->sink.limit_addr, component->sink.vaddr);
	}

	child_node = of_get_child_by_name(node, "input_port");
	if (!child_node) {
		dev_err(&pdev->dev, "Failed to find 'input_port'\n");
		ret = -ENODEV;
		goto err_free_sink_buf;
	}
	nr = count_device_node_child(child_node);
	if (nr) {
		component->in = kmalloc_array(nr, sizeof(*component->in), GFP_KERNEL);
		if (!component->in) {
			ret = -ENOMEM;
			goto err_put_child;
		}

		for_each_child_of_node(child_node, port_node) {
			const struct device_node *endpoint_node;

			if (!of_device_is_available(port_node))
				continue;
			dev_info(&pdev->dev, "Found input_port: %pOF\n", port_node);
			endpoint_node = of_parse_phandle(port_node, "endpoint", 0);
			if (!endpoint_node) {
				dev_err(&pdev->dev, "Missing endpoint phandle in %pOF\n",
					port_node);
				ret = -ENODEV;
				goto err_put_port;
			}
			dev_info(&pdev->dev, "\t endpoint: %pOF\n", endpoint_node);

			ret = of_property_read_u32_array(
				(struct device_node *)endpoint_node,
				"reg", &reg[0], 4);
			of_node_put((struct device_node *)endpoint_node);
			if (ret) {
				dev_err(&pdev->dev, "Failed to read endpoint 'reg' in %pOF\n",
					port_node);
				goto err_put_port;
			}

			io_port = kmalloc(sizeof(struct xuantie_io_port), GFP_KERNEL);
			if (!io_port) {
				ret = -ENOMEM;
				goto err_put_port;
			}
			io_port->is_input = true;
			io_port->endpoint_num = port_nr;
			io_port->type = NTRACE_TYPE_FUNNEL;
			io_port->base_addr = ((u64)reg[0] << 32) | reg[1];
			component->in[component->in_num] = io_port;
			component->in_num++;
			port_nr++;
		}
	}
	of_node_put(child_node);

	ret = xuantie_ntrace_add_device_node(pdev, NTRACE_TYPE_SINK_SMEM, component);
	if (ret)
		goto err_free_ports;

	return 0;

err_put_port:
	of_node_put(port_node);
err_put_child:
	of_node_put(child_node);
err_free_ports:
	while (component->in_num) {
		component->in_num--;
		kfree(component->in[component->in_num]);
	}
	kfree(component->in);
err_free_sink_buf:
	if (component->sink.is_resv_mem)
		memunmap(component->sink.vaddr);
	else
		dma_free_coherent(&pdev->dev,
				  component->sink.limit_addr - component->sink.start_addr,
				  component->sink.vaddr,
				  component->sink.start_addr);
err_unmap:
	iounmap((void __iomem *)(unsigned long)component->reg_base);
err_free_component:
	kfree(component);
	return ret;
}

static int xuantie_ntrace_sink_remove(struct platform_device *pdev)
{
	struct ntrace_dev_node *node = platform_get_drvdata(pdev);
	struct xuantie_ntrace_sink_smem sink = node->component->sink;
	int ret = xuantie_ntrace_remove_device_node(pdev);

	if (sink.vaddr) {
		if (sink.is_resv_mem)
			memunmap(sink.vaddr);
		else
			dma_free_coherent(&pdev->dev,
					  sink.limit_addr - sink.start_addr,
					  sink.vaddr, sink.start_addr);
	}

	return ret;
}

static const struct of_device_id xuantie_ntrace_sink_of_match[] = {
	{ .compatible = "xuantie_ntrace,sink-controller" },
	{ }
};
MODULE_DEVICE_TABLE(of, xuantie_ntrace_sink_of_match);

struct platform_driver xuantie_ntrace_sink_driver = {
	.probe	= xuantie_ntrace_sink_probe,
	.remove	= xuantie_ntrace_sink_remove,
	.driver	= {
		.name = "xuantie-ntrace-sink",
		.of_match_table = xuantie_ntrace_sink_of_match,
	},
};
