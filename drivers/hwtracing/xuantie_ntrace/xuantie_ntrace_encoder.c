// SPDX-License-Identifier: GPL-2.0-only

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include "xuantie_ntrace.h"

static int xuantie_ntrace_encoder_probe(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	struct xuantie_ntrace_component *component;
	struct device_node *child_node, *port_node;
	struct xuantie_io_port *io_port;
	struct resource *res;
	resource_size_t base, size;
	u32 reg[4];
	const char *str_tmp;
	int port_nr;
	int nr;
	int ret;
	static const char * const trace_format[] = {"E-trace", "N-Trace", "Reserved2",
		"Reserved2", "Reserved2", "Reserved2", "Reserved2", "Reserved2", "Vendor-Specific"};
	static const char * const inst_sync_mode[] = {"Off", "Count Trace Messages/packets",
		"Count Hart Clock Cycles", "Count Instruction 16-bit half-words"};
	static const char * const insn_mode[] = {"INST Trace disable", "Protocol defined1",
		"Protocol defined2", "Branch Trace",	"Protocol defined4", "Protocol defined5",
		"Branch History Trace", "Vendor-defined"};
	static const char * const timestamp_mode[] = {"None", "External", "Internal System",
		"Internal Core", "Shared", "Vendor-Specific5", "Vendor-Specific6",
		"Vendor-Specific7"};

	component = kzalloc(sizeof(*component), GFP_KERNEL);
	if (!component)
		return -ENOMEM;
	component->type = NTRACE_TYPE_ENCODER;
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

	ret = of_property_read_u32(node, "cpu", &component->encoder.cpu);
	if (ret) {
		dev_err(&pdev->dev, "Failed to read 'cpu'\n");
		goto err_unmap;
	}
	dev_info(&pdev->dev, "cpu=%d\n", component->encoder.cpu);

	ret = of_property_read_u32(node, "trace_encoder_format",
					&component->encoder.trace_format);
	if (ret)
		component->encoder.trace_format = 1; //default N-Trace
	else
		component->encoder.trace_format &= 0x7;
	dev_info(&pdev->dev, "trace_encoder_format=%d(%s)\n", component->encoder.trace_format,
			trace_format[component->encoder.trace_format]);

	ret = of_property_read_u32(node, "trace_encoder_inst_mode",
					&component->encoder.inst_mode);
	if (ret)
		component->encoder.inst_mode = 6; //default Branch History Trace
	else
		component->encoder.inst_mode &= 7;
	dev_info(&pdev->dev, "trace_encoder_inst_mode=%d(%s)\n", component->encoder.inst_mode,
			insn_mode[component->encoder.inst_mode]);

	ret = of_property_read_string(node, "trace_encoder_context", &str_tmp);
	if (ret)
		component->encoder.send_context = true; //default Send Context
	else
		component->encoder.send_context = strcmp(str_tmp, "true") == 0;
	dev_info(&pdev->dev, "trace_encoder_context=%d\n", component->encoder.send_context);

	ret = of_property_read_string(node, "trace_encoder_inst_stall_enable", &str_tmp);
	if (ret)
		component->encoder.stall_enable = true; //default Stall Enable
	else
		component->encoder.stall_enable = strcmp(str_tmp, "true") == 0;
	dev_info(&pdev->dev, "trace_encoder_inst_stall_enable=%d\n", component->encoder.stall_enable);

	ret = of_property_read_string(node, "trace_encoder_inhibit_src", &str_tmp);
	if (ret)
		component->encoder.inhibit_src = false; //defaut Send Src
	else
		component->encoder.inhibit_src = strcmp(str_tmp, "true") == 0;
	dev_info(&pdev->dev, "trace_encoder_inhibit_src=%d\n", component->encoder.inhibit_src);

	ret = of_property_read_u32(node, "trace_encoder_src_id", &component->encoder.src_id);
	if (ret)
		component->encoder.src_id = component->encoder.cpu; //default using CPU
	dev_info(&pdev->dev, "trace_encoder_src_id=%d\n", component->encoder.src_id);

	ret = of_property_read_u32(node, "trace_encoder_inst_sync_mode",
		&component->encoder.inst_sync_mode);
	if (ret)
		component->encoder.inst_sync_mode = 0; //default No Sync
	else
		component->encoder.inst_sync_mode &= 3;
	dev_info(&pdev->dev, "trace_encoder_inst_sync_mode=%d(%s)\n", component->encoder.inst_sync_mode,
			inst_sync_mode[component->encoder.inst_sync_mode]);

	ret = of_property_read_u32(node, "trace_encoder_inst_sync_max",
					&component->encoder.inst_sync_max);
	if (ret && component->encoder.inst_sync_mode) {
		dev_err(&pdev->dev, "Failed to read 'trace_encoder_inst_sync_max'\n");
		goto err_unmap;
	}
	dev_info(&pdev->dev, "trace_encoder_inst_sync_max=0x%x\n", component->encoder.inst_sync_max);

	ret = of_property_read_string(node, "trace_encoder_inst_trigger_enable", &str_tmp);
	if (ret)
		component->encoder.inst_trigger_enable = true; //default True
	else
		component->encoder.inst_trigger_enable = strcmp(str_tmp, "true") == 0;
	dev_info(&pdev->dev, "trace_encoder_inst_trigger_enable=%d\n", component->encoder.inst_trigger_enable);

	ret = of_property_read_string(node, "trace_timestamp_enable", &str_tmp);
	if (ret)
		component->encoder.enable_timestamp = false; // default Not Enable Timestamp
	else
		component->encoder.enable_timestamp = strcmp(str_tmp, "true") == 0;
	dev_info(&pdev->dev, "trace_timestamp_enable=%d\n", component->encoder.enable_timestamp);

	ret = of_property_read_u32(
		node, "trace_timestamp_mode",
		&component->encoder.timestamp_mode);
	if (ret && component->encoder.enable_timestamp) {
		dev_err(&pdev->dev, "Failed to read 'trace_timestamp_mode'\n");
		goto err_unmap;
	}
	component->encoder.timestamp_mode &= 7;
	dev_info(&pdev->dev, "trace_timestamp_mode=%d(%s)\n", component->encoder.timestamp_mode,
			timestamp_mode[component->encoder.timestamp_mode]);

	ret = of_property_read_u32(node, "trace_timestamp_prescale",
				&component->encoder.timestamp_prescale);
	if (ret)
		component->encoder.timestamp_prescale = 0; //default 0
	dev_info(&pdev->dev, "trace_timestamp_prescale=%d\n", component->encoder.timestamp_prescale);

	child_node = of_get_child_by_name(node, "output_port");
	if (!child_node) {
		dev_err(&pdev->dev, "Failed to find 'output_port'\n");
		ret = -ENODEV;
		goto err_unmap;
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
			io_port->type = NTRACE_TYPE_FUNNEL;
			io_port->base_addr = ((u64)reg[0] << 32) |
							reg[1];
			component->out[component->out_num] = io_port;
			component->out_num++;
			port_nr++;
		}
	}
	of_node_put(child_node);

	ret = xuantie_ntrace_add_device_node(pdev, NTRACE_TYPE_ENCODER, component);
	if (ret)
		goto err_free_ports;

	return 0;

err_put_port:
	of_node_put(port_node);
err_put_child:
	of_node_put(child_node);
err_free_ports:
	while (component->out_num) {
		component->out_num--;
		kfree(component->out[component->out_num]);
	}
	kfree(component->out);
err_unmap:
	iounmap((void __iomem *)(unsigned long)component->reg_base);
err_free_component:
	kfree(component);
	return ret;
}

static int xuantie_ntrace_encoder_remove(struct platform_device *pdev)
{
	return xuantie_ntrace_remove_device_node(pdev);
}

static const struct of_device_id xuantie_ntrace_encoder_of_match[] = {
	{ .compatible = "xuantie_ntrace,encoder-controller" },
	{ }
};
MODULE_DEVICE_TABLE(of, xuantie_ntrace_encoder_of_match);

struct platform_driver xuantie_ntrace_encoder_driver = {
	.probe	= xuantie_ntrace_encoder_probe,
	.remove	= xuantie_ntrace_encoder_remove,
	.driver	= {
		.name = "xuantie-ntrace-encoder",
		.of_match_table = xuantie_ntrace_encoder_of_match,
	},
};
