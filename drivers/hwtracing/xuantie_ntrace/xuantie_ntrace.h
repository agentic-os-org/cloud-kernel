/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __XUANTIE_NTRACE_H__
#define __XUANTIE_NTRACE_H__

#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/types.h>
#include <linux/perf_event.h>
#include <linux/completion.h>

#include "xt_ntrace_control_interface.h"

enum xuantie_ntrace_dev_type {
	NTRACE_TYPE_ENCODER,
	NTRACE_TYPE_FUNNEL,
	NTRACE_TYPE_SINK_SMEM,
	NTRACE_TYPE_MAX
};

struct ntrace_dev_type {
	const char *compatible;
	u32 expected_count;
	u32 probed_count;
	bool probe_complete;
};

struct ntrace_dev_node {
	struct list_head list;
	struct platform_device *pdev;
	struct device *dev;
	enum xuantie_ntrace_dev_type type;
	struct xuantie_ntrace_component *component;
};

struct xuantie_ntrace_drvdata {
	struct mutex lock;
	struct completion all_probed;
	bool pmu_registered;
	struct ntrace_dev_type dev_types[NTRACE_TYPE_MAX];
};

struct xuantie_io_port {
	bool is_input; // input=1, output=0
	u32 endpoint_num;
	enum xuantie_ntrace_dev_type type;
	u64 base_addr;
};

struct xuantie_ntrace_encoder {
	//
	u32 cpu;
	u32 trace_format;
	u32 inst_mode;
	bool send_context;
	//
	bool stall_enable;
	//
	bool inhibit_src;
	u32 src_id;
	//
	u32 inst_sync_mode;
	u32 inst_sync_max;
	bool inst_trigger_enable;
	//
	bool enable_timestamp;
	u32 timestamp_mode;
	u32 timestamp_prescale;
};

enum XT_FUNNEL_LEVEL {
	LEVEL1_FUNNEL = 1,
	LEVEL2_FUNNEL = 2,
};

struct xuantie_ntrace_funnel {
	enum XT_FUNNEL_LEVEL level;
};

struct xuantie_ntrace_sink_smem {
	u64 start_addr;
	u64 limit_addr;
	u64 write_point;
	void __iomem *vaddr;
	bool is_resv_mem;
	const char *working_mode;
	const char *format;
};

struct xuantie_ntrace_component {
	struct platform_device *pdev;
	enum xuantie_ntrace_dev_type type;
	struct list_head list;
	u64 reg_base;
	u64 reg_size;

	union {
		struct xuantie_ntrace_encoder encoder;
		struct xuantie_ntrace_funnel funnel;
		struct xuantie_ntrace_sink_smem sink;
	};

	union {
		struct xt_trace_sink_control_info sink_info;
		struct xt_trace_funnel_control_info funnel_info;
		struct xt_trace_encoder_control_info encoder_info;
	};

	u32 in_num;
	u32 out_num;
	struct xuantie_io_port **in;
	struct xuantie_io_port **out;
};

struct xuantie_saved_config {
	u32 _size;
	u32 inst_mode;
	u32 src_bits;
	u32 timestamp_bits;
	u32 trace_ram_wrap;
	u32 _align;
};

#define XUANTIE_NTRACE_ADDR_MASK GENMASK(63, 0)
enum XUANTIE_NTRACE_MODE_TYPE {
	XUANTIE_NTRACE_PRIV_MODE_EXCL_NONE = 0,
	XUANTIE_NTRACE_PRIV_MODE_EXCL_KERN,
	XUANTIE_NTRACE_PRIV_MODE_EXCL_USER,
};

struct xuantie_ntrace_filter_attr {
	u64 start_addr;
	u64 stop_addr;
	u32 priv_mode; // user&kernel
};

struct xuantie_ntrace_pmu {
	struct pmu		pmu;
	struct perf_output_handle handle;
	struct perf_sample_data data;
	struct xuantie_ntrace_filter_attr filter_attr;
	struct task_struct	*target_task;
	struct perf_event	*aux_owner;
	struct completion	commit_done;
	bool			has_leader_event;
	bool			session_committed;
	bool			hw_configured;
};

/**
 * struct xuantie_ntrace_aux_buf - Descriptor of the AUX buffer of xuantie_ntrace
 * @length:   size of the AUX buffer
 * @nr_pages: number of pages of the AUX buffer
 * @base:     start address of AUX buffer
 * @pos:      position in the AUX buffer to commit traced data
 */
struct xuantie_ntrace_aux_buf {
	unsigned long length;
	unsigned long nr_pages;
	void *base;
	unsigned long pos;
};

static inline const char *xuantie_ntrace_type2str(enum xuantie_ntrace_dev_type type)
{
	switch (type) {
	case NTRACE_TYPE_ENCODER:
		return "encoder";
	case NTRACE_TYPE_FUNNEL:
		return "funnel";
	case NTRACE_TYPE_SINK_SMEM:
		return "sink_smem";
	default:
		return "none";
	}
}

static inline int count_device_node_child(struct device_node *parent)
{
	struct device_node *child;
	int count = 0;

	for_each_child_of_node(parent, child) {
		count++;
	}
	return count;
}

int xuantie_ntrace_add_device_node(struct platform_device *pdev,
				enum xuantie_ntrace_dev_type type,
				struct xuantie_ntrace_component *comp);
int xuantie_ntrace_remove_device_node(struct platform_device *pdev);


#endif /* __XUANTIE_NTRACE_H__ */
