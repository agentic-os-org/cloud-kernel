// SPDX-License-Identifier: GPL-2.0-only

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include "xuantie_ntrace.h"

static int xuantie_ntrace_funnel_probe(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	struct xuantie_ntrace_component *component;
	struct device_node *child_node, *port_node;
	struct xuantie_io_port *io_port;
	struct resource *res;
	resource_size_t base, size;
	u32 reg[4];
	int port_nr;
	int nr;
	int ret;

	component = kzalloc(sizeof(*component), GFP_KERNEL);
	if (!component)
		return -ENOMEM;
	component->type = NTRACE_TYPE_FUNNEL;
	component->pdev = pdev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get 'reg' resource\n");
		goto err_free_component;
	}
	base = res->start;
	size = resource_size(res);
	dev_info(&pdev->dev, "base=0x%llx size=0x%llx\n", (u64)base, (u64)size);
	component->reg_base = (unsigned long)ioremap(base, size);
	if (!component->reg_base) {
		dev_err(&pdev->dev, "Failed to ioremap registers\n");
		ret = -ENXIO;
		goto err_free_component;
	}
	component->reg_size = size;
	dev_info(&pdev->dev, "reg_base=0x%llx reg_size=0x%llx\n",
		 (u64)component->reg_base, (u64)component->reg_size);

	ret = of_property_read_u32(node, "level", &component->funnel.level);
	if (ret)
		component->funnel.level = LEVEL1_FUNNEL;
	dev_info(&pdev->dev, "funnel level=%d\n", component->funnel.level);

	child_node = of_get_child_by_name(node, "input_port");
	if (!child_node) {
		dev_err(&pdev->dev, "Failed to find 'input_port'\n");
		ret = -ENODEV;
		goto err_unmap;
	}
	nr = count_device_node_child(child_node);
	if (nr) {
		component->in = kmalloc_array(nr, sizeof(*component->in), GFP_KERNEL);
		if (!component->in) {
			ret = -ENOMEM;
			goto err_put_child;
		}
		port_nr = 0;

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
			io_port->type = NTRACE_TYPE_ENCODER;
			io_port->base_addr = ((u64)reg[0] << 32) | reg[1];
			component->in[component->in_num] = io_port;
			component->in_num++;
			port_nr++;
		}
	}
	of_node_put(child_node);

	child_node = of_get_child_by_name(node, "output_port");
	if (!child_node) {
		dev_err(&pdev->dev, "Failed to find 'output_port'\n");
		ret = -ENODEV;
		goto err_free_in_ports;
	}
	nr = count_device_node_child(child_node);
	if (nr) {
		component->out = kmalloc_array(nr, sizeof(*component->out), GFP_KERNEL);
		if (!component->out) {
			ret = -ENOMEM;
			goto err_put_child;
		}
		port_nr = 0;

		for_each_child_of_node(child_node, port_node) {
			const struct device_node *endpoint_node;

			if (!of_device_is_available(port_node))
				continue;
			dev_info(&pdev->dev, "Found output_port: %pOF\n", port_node);
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
			io_port->is_input = false;
			io_port->endpoint_num = port_nr;
			io_port->type = NTRACE_TYPE_SINK_SMEM;
			io_port->base_addr = ((u64)reg[0] << 32) | reg[1];
			component->out[component->out_num] = io_port;
			component->out_num++;
			port_nr++;
		}
	}
	of_node_put(child_node);

	for (int i = 0; i < component->in_num; i++) {
		dev_info(&pdev->dev, "\t in[%d]is_input=%d endpoint_num=%d\n", i,
			component->in[i]->is_input,
			component->in[i]->endpoint_num);
	}
	for (int j = 0; j < component->out_num; j++) {
		dev_info(&pdev->dev, "\t out[%d]is_input=%d endpoint_num=%d\n", j,
			component->out[j]->is_input,
			component->out[j]->endpoint_num);
	}

	ret = xuantie_ntrace_add_device_node(pdev, NTRACE_TYPE_FUNNEL, component);
	if (ret)
		goto err_free_out_ports;

	return 0;

err_put_port:
	of_node_put(port_node);
err_put_child:
	of_node_put(child_node);
err_free_out_ports:
	while (component->out_num) {
		component->out_num--;
		kfree(component->out[component->out_num]);
	}
	kfree(component->out);
err_free_in_ports:
	while (component->in_num) {
		component->in_num--;
		kfree(component->in[component->in_num]);
	}
	kfree(component->in);
err_unmap:
	iounmap((void __iomem *)(unsigned long)component->reg_base);
err_free_component:
	kfree(component);
	return ret;
}

static int xuantie_ntrace_funnel_remove(struct platform_device *pdev)
{
	return xuantie_ntrace_remove_device_node(pdev);
}

static const struct of_device_id xuantie_ntrace_funnel_of_match[] = {
	{ .compatible = "xuantie_ntrace,funnel-controller" },
	{ }
};
MODULE_DEVICE_TABLE(of, xuantie_ntrace_funnel_of_match);

struct platform_driver xuantie_ntrace_funnel_driver = {
	.probe	= xuantie_ntrace_funnel_probe,
	.remove	= xuantie_ntrace_funnel_remove,
	.driver	= {
		.name = "xuantie-ntrace-funnel",
		.of_match_table = xuantie_ntrace_funnel_of_match,
	},
};
