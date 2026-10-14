// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for XUANTIE RISC-V Nexus Trace Device
 *
 * Copyright (c) 2025 Alibaba DAMO Academy.
 * Author: Jiangshuai Li <jiangshuai_li@linux.alibaba.com>
 * Author: Chen Pei <cp0613@linux.alibaba.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/align.h>
#include <linux/sizes.h>
#include <linux/log2.h>
#include <linux/minmax.h>
#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/perf_event.h>
#include <linux/rculist.h>
#include <linux/smp.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/vmalloc.h>

#include "xuantie_ntrace.h"
#include "xt_ntrace_control_interface.h"

#define TEST_LOG_ON	0
#define XUANTIE_NTRACE_PMU_NAME "xuantie_ntrace"

/* Trace data is emitted in 256-bit (32-byte) units; keep partial commits aligned. */
#define XUANTIE_NTRACE_DATA_UNIT 32

static struct xuantie_ntrace_drvdata *ntrace_drvdata;
static LIST_HEAD(xuantie_ntrace_controllers);
static DEFINE_MUTEX(xuantie_ntrace_lock);
static struct xuantie_ntrace_pmu xuantie_ntrace_pmu;
static bool trace_component_detected;

/*
 * Serializes session_committed and all trace component hardware ops.
 * add/del/start/stop of different events (one per cpu/thread) may run
 * concurrently on different CPUs, so a committing event_del can race
 * with another event's start/stop. Raw spinlock: these callbacks run
 * with IRQs disabled and must not sleep.
 */
static DEFINE_RAW_SPINLOCK(xuantie_ntrace_hw_lock);

extern struct platform_driver xuantie_ntrace_encoder_driver;
extern struct platform_driver xuantie_ntrace_funnel_driver;
extern struct platform_driver xuantie_ntrace_sink_driver;

// Function Declaration
static void xuantie_ntrace_event_start(struct perf_event *event, int flags);
static void xuantie_ntrace_event_stop(struct perf_event *event, int flags);
static void xuantie_ntrace_session_commit(struct perf_event *event,
					  bool only_if_started);

PMU_FORMAT_ATTR(start_addr, "config:0-63");
PMU_FORMAT_ATTR(stop_addr,  "config1:0-63");

static struct attribute *xuantie_ntrace_filter_attrs[] = {
	&format_attr_start_addr.attr,
	&format_attr_stop_addr.attr,
	NULL
};

static struct attribute_group xuantie_ntrace_filter_attr_group = {
	.name = "format",
	.attrs = xuantie_ntrace_filter_attrs,
};

/*
 * Explicit commit trigger for the perf tool: writing anything commits the
 * current session (full deferred blob) into the AUX buffer, synchronously,
 * in the writer's process context. The tool invokes it from its auxtrace
 * snapshot-on-exit hook after Ctrl+C, i.e. before its final buffer flush
 * and while it still holds the event fd and the AUX mmap.
 * If the session already committed via the task-exit path, or no event was
 * ever added, this is a no-op (session_committed / hw_configured guards).
 *
 * owner_mutex pins aux_owner for the whole call: free_aux() takes it
 * before clearing the pointer (it always runs in process context, see the
 * WARN_ON_ONCE(in_atomic()) in __rb_free_aux()), so the event cannot be
 * torn down under a concurrent writer even if the tool is already exiting.
 * owner_task detects re-entrance: if this writer's perf_aux_output_end()
 * drops the last aux reference (mapping already gone), __rb_free_aux()
 * invokes free_aux() in this very context, which must not take the mutex
 * it already holds.
 */
static DEFINE_MUTEX(xuantie_ntrace_owner_mutex);
static struct task_struct *xuantie_ntrace_owner_task;

static ssize_t commit_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct perf_event *event;
	unsigned long irqflags;
	ssize_t ret = count;
	bool committed;

	mutex_lock(&xuantie_ntrace_owner_mutex);
	xuantie_ntrace_owner_task = current;

	event = xuantie_ntrace_pmu.aux_owner;
	if (!event) {
		ret = -ENODEV;
		goto out;
	}

	xuantie_ntrace_session_commit(event, true);

	raw_spin_lock_irqsave(&xuantie_ntrace_hw_lock, irqflags);
	committed = xuantie_ntrace_pmu.session_committed;
	raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);

	if (committed) {
		/*
		 * Upper bound: the in-flight committer memcpy()s at most the
		 * whole sink contents through an uncached ioremap mapping.
		 * A fixed 10 s covers the typical sink sizes; if much larger
		 * sinks are deployed, turn this into a dynamic estimate
		 * scaled by the total sink capacity.
		 */
		if (!wait_for_completion_timeout(&xuantie_ntrace_pmu.commit_done,
						 msecs_to_jiffies(10000))) {
			pr_warn("Timed out waiting for the in-flight commit\n");
			ret = -ETIMEDOUT;
		}
	}

out:
	xuantie_ntrace_owner_task = NULL;
	mutex_unlock(&xuantie_ntrace_owner_mutex);
	return ret;
}
/*
 * Owner/group writable only: the kernel forbids world-writable sysfs
 * attributes (VERIFY_OCTAL_PERMISSIONS), so non-root users cannot
 * trigger the session commit directly. Deployments needing non-root
 * access can change the attribute's group via a udev rule (kernfs
 * supports chown/chmod on attribute files), e.g. chgrp it to a
 * tracing group, or allow the write via sudo/polkit.
 */
static DEVICE_ATTR(commit, 0220, NULL, commit_store);

static struct attribute *xuantie_ntrace_ctl_attrs[] = {
	&dev_attr_commit.attr,
	NULL
};

static struct attribute_group xuantie_ntrace_ctl_attr_group = {
	.attrs = xuantie_ntrace_ctl_attrs,
};

static const struct attribute_group *xuantie_ntrace_attr_groups[] = {
	&xuantie_ntrace_filter_attr_group,
	&xuantie_ntrace_ctl_attr_group,
	NULL
};

static void xuantie_ntrace_init_filter_attrs(struct perf_event *event)
{
	xuantie_ntrace_pmu.filter_attr.start_addr = event->attr.config;
	xuantie_ntrace_pmu.filter_attr.stop_addr  = event->attr.config1;

	if (event->attr.exclude_kernel)
		xuantie_ntrace_pmu.filter_attr.priv_mode = XUANTIE_NTRACE_PRIV_MODE_EXCL_KERN;
	else if (event->attr.exclude_user)
		xuantie_ntrace_pmu.filter_attr.priv_mode = XUANTIE_NTRACE_PRIV_MODE_EXCL_USER;
	else
		xuantie_ntrace_pmu.filter_attr.priv_mode = XUANTIE_NTRACE_PRIV_MODE_EXCL_NONE;

	pr_info("start_addr=0x%llx stop_addr=0x%llx priv_mode=%d\n",
		xuantie_ntrace_pmu.filter_attr.start_addr,
		xuantie_ntrace_pmu.filter_attr.stop_addr,
		xuantie_ntrace_pmu.filter_attr.priv_mode);
}

static int console_msg_out(const char *str)
{
	pr_info("%s", str);
	return 0;
}

static void
build_encoder_config_info(struct xuantie_ntrace_component *component,
			  struct xt_trace_encoder_config_info *encoder_config)
{
	memset(encoder_config, 0, sizeof(struct xt_trace_encoder_config_info));

	encoder_config->inst_mode = component->encoder.inst_mode;
	encoder_config->send_context = component->encoder.send_context;
	encoder_config->inst_trigger_enable =
		component->encoder.inst_trigger_enable;
	encoder_config->inst_stall_ena = component->encoder.stall_enable;
	encoder_config->inhibit_src = component->encoder.inhibit_src;
	encoder_config->inst_sync_mode = component->encoder.inst_sync_mode;
	encoder_config->inst_sync_max = component->encoder.inst_sync_max;
	encoder_config->record_format = 1; // 6MDO+2MESO

	// inst feature: all false
	encoder_config->inst_no_addr_diff = false;
	encoder_config->inst_no_trap_addr = false;
	encoder_config->inst_en_sequential_tail_jump = false;
	encoder_config->inst_en_implicit_return = false;
	encoder_config->inst_en_branch_prediction = false;
	encoder_config->inst_en_jump_target_cache = false;
	encoder_config->inst_implicit_return_mode = 0;
	encoder_config->inst_en_repeated_history = false;
	encoder_config->inst_en_all_jumps = false;
	encoder_config->inst_extend_addr_msb = false;

	encoder_config->src_id = component->encoder.src_id;
	encoder_config->src_bits = component->encoder_info.default_src_bits;

	// data trace: disable
	encoder_config->data_trace_enable = false;

	// enable timestamp
	if (component->encoder_info.support_timestamp_enable &&
	    component->encoder.enable_timestamp) {
		encoder_config->timestamp_enable = true;
		encoder_config->timestamp_run_in_debugmode = false;
		encoder_config->timestamp_type = 1; // timestamp_external
		encoder_config->timestamp_prescale =
			component->encoder.timestamp_prescale;
	}
}

static void build_filter_one(struct xt_trace_encoder_filter_config_info *filter_config)
{
	u32 priv_filter_value = FILTER_U_MODE | FILTER_S_HS_MODE; /* only u+s */
	bool comparator_enable = false;
	u32 prim_func = COMPFUNCTION_ALWAYS_TRUE;
	u32 second_func = COMPFUNCTION_ALWAYS_TRUE;

	if (xuantie_ntrace_pmu.filter_attr.start_addr
	|| xuantie_ntrace_pmu.filter_attr.stop_addr) {
		comparator_enable = true;

		if (xuantie_ntrace_pmu.filter_attr.start_addr == 0
		&& xuantie_ntrace_pmu.filter_attr.stop_addr != 0) {
			// equal to comparator_enable = true
			prim_func = COMPFUNCTION_ALWAYS_TRUE;
			second_func = COMPFUNCTION_EQUAL;
		} else if (xuantie_ntrace_pmu.filter_attr.start_addr != 0
		&& xuantie_ntrace_pmu.filter_attr.stop_addr == 0) {
			prim_func = COMPFUNCTION_EQUAL;
			second_func = COMPFUNCTION_LESS_THAN;
		} else {
			prim_func = COMPFUNCTION_EQUAL;
			second_func = COMPFUNCTION_EQUAL;
		}
	} else
		comparator_enable = false;

	if (xuantie_ntrace_pmu.filter_attr.priv_mode == XUANTIE_NTRACE_PRIV_MODE_EXCL_KERN)
		priv_filter_value = FILTER_U_MODE;
	else if (xuantie_ntrace_pmu.filter_attr.priv_mode == XUANTIE_NTRACE_PRIV_MODE_EXCL_USER)
		priv_filter_value = FILTER_S_HS_MODE;
	else
		priv_filter_value = FILTER_U_MODE | FILTER_S_HS_MODE;

	memset(filter_config, 0, sizeof(struct xt_trace_encoder_filter_config_info));

	filter_config->filter_i = 0;
	filter_config->filter_match_privilege = true;
	filter_config->filter_match_ecause = false;
	filter_config->filter_match_interrupt = false;
	filter_config->match_privilege_value = priv_filter_value;
	filter_config->match_value_interrupt = 0;
	filter_config->match_choice_ecause = 0;
	filter_config->filter_match_dtype = false;
	filter_config->filter_match_dsize = false;
	filter_config->match_value_dtype = 0;
	filter_config->match_value_dsize = 0;

	// comparator 1
	filter_config->comparator1_enable = comparator_enable;
	filter_config->comp1_filter_number = 0;
	// config
	filter_config->comp1_primary_input = COMPTYPE_IADDR;       // p_iaddr
	filter_config->comp1_primary_function = prim_func;
	filter_config->comp1_primary_notify = false;
	filter_config->comp1_secondary_input = COMPTYPE_IADDR;     // s_iaddr
	filter_config->comp1_secondary_function = second_func;
	filter_config->comp1_secondary_notify = false;
	// start with primary true, end with secondary true
	filter_config->comp1_match_mode = COMPMATCHMODE_PRIMARY_TRUE_UNTIL_SECOND_TRUE;
	filter_config->comp1_primary_match_low_value = xuantie_ntrace_pmu.filter_attr.start_addr;
	filter_config->comp1_primary_match_high_value = 0x0;
	filter_config->comp1_secondary_match_low_value = xuantie_ntrace_pmu.filter_attr.stop_addr;
	filter_config->comp1_secondary_match_high_value = 0x0;

	// comparator 2
	filter_config->comparator2_enable = false;
	// filter_config->comp2_filter_number;
	////config
	// filter_config->comp2_primary_input;
	// filter_config->comp2_primary_function;
	// filter_config->comp2_primary_notify;
	// filter_config->comp2_secondary_input;
	// filter_config->comp2_secondary_function;
	// filter_config->comp2_secondary_notify;
	// filter_config->comp2_match_mode;
	// filter_config->comp2_primary_match_low_value;
	// filter_config->comp2_primary_match_high_value;
	// filter_config->comp2_secondary_match_low_value;
	// filter_config->comp2_secondary_match_high_value;

	// comparator 3
	filter_config->comparator3_enable = false;
	// filter_config->comp3_filter_number;
	////config
	// filter_config->comp3_primary_input;
	// filter_config->comp3_primary_function;
	// filter_config->comp3_primary_notify;
	// filter_config->comp3_secondary_input;
	// filter_config->comp3_secondary_function;
	// filter_config->comp3_secondary_notify;
	// filter_config->comp3_match_mode;
	// filter_config->comp3_primary_match_low_value;
	// filter_config->comp3_primary_match_high_value;
	// filter_config->comp3_secondary_match_low_value;
	// filter_config->comp3_secondary_match_high_value;
}

static void
build_funnel_config_info(struct xuantie_ntrace_component *component,
			 struct xt_trace_funnel_config_info *funnel_config)
{
	funnel_config->disable_input = 0;
}

static void
build_sink_config_info(struct xuantie_ntrace_component *component,
		       struct xt_trace_sink_config_info *sink_config)
{
	memset(sink_config, 0, sizeof(struct xt_trace_sink_config_info));

	sink_config->component_type = TRCOMP_RAMSINK;
	sink_config->type = TRACE_SMEM_SINK;        // configure to SMEM Sink
	sink_config->ram_sink_stop_on_wrap = false; // the circular buffer gets full
	sink_config->ram_sink_mem_format = 0;       // plain bytes
	sink_config->ram_sink_start = component->sink.start_addr;
	sink_config->ram_sink_limit = (component->sink.limit_addr & 0xffffffffffffff00) - 4;
	component->sink.limit_addr = component->sink.limit_addr & 0xffffffffffffff00;
	sink_config->ram_sink_write_point = component->sink.start_addr;

	////for pib sink
	// sink_config->pib_sink_mode;
	// sink_config->pib_sink_clk_center;
	// sink_config->pib_sink_divider;
	//
	////for atb bridge
	// sink_config->atb_bridge_id;
	//
	////common config
	// sink_config->sink_async_freq;
}

static void xuantie_build_saved_config(struct xuantie_saved_config *config,
				struct xuantie_ntrace_component *component,
				int wrap)
{
	memset(config, 0, sizeof(struct xuantie_saved_config));

	/* Save encoder info. */
	config->_size = sizeof(struct xuantie_saved_config);
	config->inst_mode = component->encoder.inst_mode;
	if (!component->encoder.inhibit_src)
		config->src_bits = component->encoder_info.default_src_bits;
	else
		config->src_bits = 0;
	if (component->encoder.enable_timestamp)
		config->timestamp_bits = component->encoder_info.timestamp_width;
	else
		config->timestamp_bits = 0;

	/* Save trRamWrap. */
	config->trace_ram_wrap = wrap;
}

static int trace_register_write(u64 addr, u32 value)
{
	iowrite32(value, (void __iomem *)(unsigned long)addr);
#if TEST_LOG_ON
	pr_info("--->write 0x%llx with 0x%x\n", addr, value);
#endif
	return 0;
}

static int trace_register_read(u64 addr, u32 *value)
{
	*value = ioread32((void __iomem *)(unsigned long)addr);
#if TEST_LOG_ON
	pr_info("--->read 0x%llx get 0x%x\n", addr, *value);
#endif
	return 0;
}

static int xuantie_ntrace_event_init(struct perf_event *event)
{
	if (event->attr.type != xuantie_ntrace_pmu.pmu.type)
		return -ENOENT;

	xuantie_ntrace_init_filter_attrs(event);

	/*
	 * Identify the traced task via event->hw.target, which is fixed at
	 * perf_event_open() time. Do NOT use event->ctx->task in event_add():
	 * the perf ctx-swap optimization (context_equiv()) migrates events
	 * between threads' contexts, so ctx->task does not reliably identify
	 * the traced thread.
	 *
	 * Only directly-created events (!event->parent) are considered;
	 * inherited events (launch mode child threads) are ignored.
	 *
	 * - launch / -p pid: an event targeting the group leader exists
	 *   (leader is enumerated first), so target_task stays unset and a
	 *   single thread exit never commits (scenarios 1a/2a/2b).
	 * - -t tid (non-leader): no leader-targeted event exists, so record
	 *   target_task to commit when that thread exits (scenario 2e).
	 */
	if (!event->parent && event->hw.target) {
		if (thread_group_leader(event->hw.target)) {
			WRITE_ONCE(xuantie_ntrace_pmu.has_leader_event, true);
			WRITE_ONCE(xuantie_ntrace_pmu.target_task, NULL);
		} else if (!READ_ONCE(xuantie_ntrace_pmu.has_leader_event)) {
			WRITE_ONCE(xuantie_ntrace_pmu.target_task, event->hw.target);
		}
	}

	return 0;
}

static int xuantie_ntrace_event_add(struct perf_event *event, int flags)
{
	struct xuantie_ntrace_component *component;
	bool encoder_find = false;
	bool funnel_find = false;
	bool sink_find = false;
	unsigned long irqflags;

	// pr_info("%s:%d flags=%d\n", __func__, __LINE__, flags);

	/* Set interfaces needed for Trace Control Lib. */
	xt_trace_control_init_rw_trace_interface(console_msg_out,
						 trace_register_write,
						 trace_register_read, NULL);

	raw_spin_lock_irqsave(&xuantie_ntrace_hw_lock, irqflags);

	/*
	 * Session already committed (trace data flushed, hardware closed
	 * by event_del): do not restart the hardware. Report the event as
	 * stopped so perf core does not expect any output from it.
	 */
	if (xuantie_ntrace_pmu.session_committed) {
		event->hw.state = PERF_HES_STOPPED;
		raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);
		return 0;
	}

	/* Detect all Trace Components.  */
	if (trace_component_detected == false) {
		list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
			if (component->type == NTRACE_TYPE_ENCODER) {
				xt_init_trace_encoder_control_info(&component->encoder_info, component->reg_base);
				if (xt_trace_detect_trace_encoder(&component->encoder_info)) {
					pr_info("Failed to detect trace encoder with base addr 0x%llx.\n",
						component->encoder_info.base_addr);
					goto error_end2;
				}
				encoder_find = true;
			} else if (component->type == NTRACE_TYPE_FUNNEL) {
				xt_init_trace_funnel_control_info(&component->funnel_info, component->reg_base);
				if (xt_trace_detect_trace_funnel(&component->funnel_info)) {
					pr_info("Failed to detect trace funnel with base addr 0x%llx.\n",
						component->funnel_info.base_addr);
					goto error_end2;
				}
				funnel_find = true;
			} else if (component->type == NTRACE_TYPE_SINK_SMEM) {
				xt_init_trace_sink_control_info(&component->sink_info, component->reg_base);
				if (xt_trace_detect_trace_sink(&component->sink_info)) {
					pr_info("Failed to detect trace sink with base addr 0x%llx.\n",
						component->sink_info.base_addr);
					goto error_end2;
				}
				sink_find = true;
			} else {
				pr_info("Unknown NTrace Component with type %d, base addr 0x%llx.\n",
					component->type, component->reg_base);
				goto error_end2;
			}
		}
		if (!encoder_find || !funnel_find || !sink_find) {
			pr_info("There is no encoder or funnel or sink find, please check DTS file.\n");
			goto error_end2;
		}
	}

	/* Mark all components have been detected.  */
	trace_component_detected = true;

	/*
	 * Configure and enable the trace components only on the first add of
	 * a session: hw_configured is reset per AUX mmap (setup_aux) and set
	 * once the components are up. It must not be derived from
	 * handle.event: the AUX transaction now only lives inside the commit
	 * path, so handle.event is NULL for the whole session.
	 * Notably sink config resets ram_sink_write_point to the buffer
	 * start; redoing it on every sched-in would wipe the trace data
	 * accumulated across context switches. On !is_task_exit event_del
	 * only disables this hart's encoder (event_stop), so no per-add
	 * reconfiguration is needed; event_start re-enables the encoder.
	 */
	if (!xuantie_ntrace_pmu.hw_configured) {
		/* Config components. */
		list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
			if (component->type == NTRACE_TYPE_ENCODER) {
				struct xt_trace_encoder_config_info encoder_config;
				struct xt_trace_encoder_filter_config_info filter_config;

				build_encoder_config_info(component, &encoder_config);
				if (xt_trace_encoder_config(&component->encoder_info,
							    &encoder_config)) {
					pr_info("Failed to config trace encoder with base addr 0x%llx.\n",
						component->encoder_info.base_addr);
					goto error_end;
				}

				//always use filter 0, pass M-mode
				build_filter_one(&filter_config);
				if (xt_trace_filter_config(&component->encoder_info, &filter_config))
					goto error_end;
			} else if (component->type == NTRACE_TYPE_FUNNEL) {
				struct xt_trace_funnel_config_info funnel_config;

				build_funnel_config_info(component, &funnel_config);
				if (xt_trace_funnel_config(&component->funnel_info,
							   &funnel_config)) {
					pr_info("Failed to config trace funnel with base addr 0x%llx.\n",
						component->funnel_info.base_addr);
					goto error_end;
				}
			} else {
				struct xt_trace_sink_config_info sink_config;

				build_sink_config_info(component, &sink_config);
				if (xt_trace_sink_config(&component->sink_info,
							 &sink_config)) {
					pr_info("Failed to config trace sink with base addr 0x%llx.\n",
						component->sink_info.base_addr);
					goto error_end;
				}
			}
		}

		/* Enable the Sink. */
		list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
			if (component->type == NTRACE_TYPE_SINK_SMEM) {
				if (xt_trace_sink_enable(&component->sink_info)) {
					pr_info("Failed to enable trace sink with base addr 0x%llx.\n",
						component->sink_info.base_addr);
					goto error_end;
				}
			}
		}

		/* Enable all Level2 Funnels. */
		list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
			if (component->type == NTRACE_TYPE_FUNNEL
				&& component->funnel.level == LEVEL2_FUNNEL) {
				if (xt_trace_funnel_enable(&component->funnel_info)) {
					pr_info("Failed to enable trace funnel with base addr 0x%llx.\n",
						component->funnel_info.base_addr);
					goto error_end;
				}
			}
		}

		/* Enable all Level1 Funnels. */
		list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
			if (component->type == NTRACE_TYPE_FUNNEL
				&& component->funnel.level == LEVEL1_FUNNEL) {
				if (xt_trace_funnel_enable(&component->funnel_info)) {
					pr_info("Failed to enable trace funnel with base addr 0x%llx.\n",
						component->funnel_info.base_addr);
					goto error_end;
				}
			}
		}

		xuantie_ntrace_pmu.hw_configured = true;
	}

	raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);

	/*
	 * Called outside the lock: event_start takes the lock itself and
	 * re-checks session_committed, so a commit racing in between is
	 * handled there.
	 */
	if (flags & PERF_EF_START)
		xuantie_ntrace_event_start(event, 0);

	return 0;

error_end:
	/* Close all ntrace components. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == NTRACE_TYPE_ENCODER) {
			xt_trace_encoder_close(
				&component->encoder_info,
				component->encoder.enable_timestamp);
		} else if (component->type == NTRACE_TYPE_FUNNEL) {
			xt_trace_funnel_close(&component->funnel_info);
		} else {
			xt_trace_sink_close(&component->sink_info);
		}
	}
	raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);
	return -EIO;

error_end2:
	raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);
	return -ENODEV;
}

/*
 * Close the whole trace path, snapshot the sink write pointer and flush
 * the trace data into the AUX buffer. Each sink is committed as its own
 * short-lived AUX transaction (saved_config + data) so the decoder sees
 * every saved_config at the start of a separate record. Exactly one commit
 * happens per session: the committed check, the hardware close and the
 * publication of session_committed all run under hw_lock, so once the
 * lock drops every other callback
 * (add/start/stop/del/event_unmapped/commit_store) bails out and the
 * data copy can safely run outside the lock.
 *
 * @event: used to open the per-sink AUX transactions; must be alive for
 * the whole call (guaranteed inside pmu::del and pmu::event_unmapped,
 * where the fd is still open, and in commit_store, where the tool holds
 * the fd and the AUX mmap that pin aux_owner).
 *
 * @only_if_started: bail out unless the session actually started
 * tracing (hw_configured). Used by event_unmapped() and commit_store(),
 * which fire per buffer teardown / on the tool's exit path and must not
 * touch the hardware when no event was ever added.
 */
static void xuantie_ntrace_session_commit(struct perf_event *event,
					  bool only_if_started)
{
	struct xuantie_ntrace_component *component;
	struct xuantie_ntrace_component *component_sink = NULL;
	struct xuantie_ntrace_component *component_encoder = NULL;
	struct xuantie_saved_config config;
	struct xuantie_ntrace_aux_buf *buf;
	unsigned long irqflags;
	size_t total_needed = 0;
	bool warned = false;

	raw_spin_lock_irqsave(&xuantie_ntrace_hw_lock, irqflags);

	/* Session already committed (hardware fully closed) or never started. */
	if (xuantie_ntrace_pmu.session_committed ||
	    (only_if_started && !xuantie_ntrace_pmu.hw_configured)) {
		raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);
		return;
	}

	/* Disable and close all funnels and encoders, just disable the sink. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == NTRACE_TYPE_ENCODER) {
			xt_trace_encoder_disable(
				&component->encoder_info,
				component->encoder.enable_timestamp);

			xt_trace_encoder_close(
				&component->encoder_info,
				component->encoder.enable_timestamp);

			component_encoder = component;
		} else if (component->type == NTRACE_TYPE_FUNNEL
				&& component->funnel.level == LEVEL1_FUNNEL) {
			xt_trace_funnel_disable(&component->funnel_info);
			xt_trace_funnel_close(&component->funnel_info);
		} else if (component->type == NTRACE_TYPE_FUNNEL
				&& component->funnel.level == LEVEL2_FUNNEL) {
			xt_trace_funnel_disable(&component->funnel_info);
			xt_trace_funnel_close(&component->funnel_info);
		} else if (component->type == NTRACE_TYPE_SINK_SMEM) {
			component_sink = component;
			xt_trace_sink_disable(&component->sink_info);
			/* Get Trace data size. */
			if (xt_trace_ram_sink_get_data_size(&component->sink_info,
								&component->sink.write_point)) {
				pr_info("Failed to get data size in ram sink with base addr 0x%llx.\n",
					component->sink_info.base_addr);
				/* This sink's data is dropped: mark incomplete */
				component->sink.write_point = component->sink.start_addr;
			}
			xt_trace_sink_close(&component->sink_info);
		}
	}

	/*
	 * Publish session_committed while still holding the lock:
	 * once the lock is released, any concurrent add/start/stop
	 * sees the flag and no longer touches the hardware, so the
	 * data copy below can safely run outside the lock.
	 */
	xuantie_ntrace_pmu.session_committed = true;

	raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);

	rcu_read_lock();

	/*
	 * Pre-compute the total trace data size across all sinks that have
	 * data, so the buffer-insufficient warning reflects the combined
	 * requirement rather than a single sink.
	 */
	list_for_each_entry_rcu(component, &xuantie_ntrace_controllers, list) {
		if (component->type != NTRACE_TYPE_SINK_SMEM)
			continue;

		if (component->sink.write_point & 0x1) {
			total_needed += component->sink.limit_addr -
				component->sink.start_addr +
				sizeof(struct xuantie_saved_config);
		} else if (component->sink.write_point != component->sink.start_addr) {
			total_needed += component->sink.write_point -
				component->sink.start_addr +
				sizeof(struct xuantie_saved_config);
		}
	}

	if (total_needed == 0)
		goto done;

	/*
	 * Commit each sink as a separate AUX segment (saved_config + data)
	 * so the decoder sees every saved_config at the start of its own
	 * record. Using per-sink begin/end pairs means each sink gets its
	 * own PERF_RECORD_AUX, and the decoder can parse each independently.
	 */
	list_for_each_entry_rcu(component, &xuantie_ntrace_controllers, list) {
		u64 trace_data_section0_start = 0;
		u32 trace_data_section0_size = 0;
		u64 trace_data_section1_start = 0;
		u32 trace_data_section1_size = 0;
		u32 sink_data_size;
		size_t space, fits;
		bool truncated = false;

		if (component->type != NTRACE_TYPE_SINK_SMEM)
			continue;
		component_sink = component;

		/* Get Trace data size. */
		if (component_sink->sink.write_point & 0x1) {
			trace_data_section0_start =
				component_sink->sink.write_point & 0xfffffffffffffffc;
			trace_data_section0_size =
				component_sink->sink.limit_addr - trace_data_section0_start;
			trace_data_section1_start = component_sink->sink.start_addr;
			trace_data_section1_size =
				trace_data_section0_start - component_sink->sink.start_addr;
		} else {
			trace_data_section0_start = component_sink->sink.start_addr;
			trace_data_section0_size =
				component_sink->sink.write_point - component_sink->sink.start_addr;
		}

		/* make start to offset */
		trace_data_section0_start -= component_sink->sink.start_addr;
		trace_data_section1_start -= component_sink->sink.start_addr;

		if (trace_data_section0_size + trace_data_section1_size == 0)
			continue;

		/* Build saved config */
		xuantie_build_saved_config(&config, component_encoder,
					   component_sink->sink.write_point & 0x1);

		/*
		 * Open a per-sink AUX transaction so each saved_config +
		 * data pair is committed as its own record.
		 */
		buf = perf_aux_output_begin(&xuantie_ntrace_pmu.handle, event);
		if (!buf) {
			pr_warn("%s:%d perf_aux_output_begin failed, trace data dropped\n",
				__func__, __LINE__);
			break;
		}
		buf->pos = xuantie_ntrace_pmu.handle.head % buf->length;
		space = buf->length - buf->pos;

		/* Warn once if the combined size exceeds the buffer. */
		if (!warned && total_needed > buf->length) {
			unsigned long need_mb = roundup_pow_of_two(
				max_t(unsigned long, DIV_ROUND_UP(total_needed, SZ_1M), 1));

			pr_warn("Insufficient space in aux map buf: need 0x%zx bytes, have 0x%lx bytes; some data may be lost.\n",
				total_needed, buf->length);
			pr_warn("Increase the AUX buffer, e.g. perf record -m,%luM (--mmap-pages size must be a power of 2).\n",
				need_mb);
			warned = true;
		}

		/*
		 * If this sink's data does not fit in the remaining space,
		 * commit as much of the beginning of the trace stream as
		 * fits: the decoder needs the saved config plus at least one
		 * trace unit (256-bit), and sections are copied in stream
		 * order, so the tail is what gets lost.
		 */
		if ((trace_data_section0_size + trace_data_section1_size +
		     sizeof(struct xuantie_saved_config)) > space) {
			if (space < sizeof(struct xuantie_saved_config) +
				    XUANTIE_NTRACE_DATA_UNIT) {
				perf_aux_output_flag(&xuantie_ntrace_pmu.handle,
						     PERF_AUX_FLAG_TRUNCATED);
				perf_aux_output_end(&xuantie_ntrace_pmu.handle, 0);
				break;
			}

			fits = ALIGN_DOWN(space - sizeof(struct xuantie_saved_config),
					  XUANTIE_NTRACE_DATA_UNIT);
			if (trace_data_section0_size >= fits) {
				trace_data_section0_size = fits;
				trace_data_section1_size = 0;
			} else {
				trace_data_section1_size = fits - trace_data_section0_size;
			}
			perf_aux_output_flag(&xuantie_ntrace_pmu.handle,
					     PERF_AUX_FLAG_TRUNCATED);
			truncated = true;
		}

		/* Save trace config and trace data to AUX buffer. */
		memcpy(buf->base + buf->pos, &config,
		       sizeof(struct xuantie_saved_config));
		buf->pos += sizeof(struct xuantie_saved_config);

		if (trace_data_section0_size) {
			memcpy(buf->base + buf->pos,
			       component_sink->sink.vaddr +
					trace_data_section0_start,
			       trace_data_section0_size);
			buf->pos += trace_data_section0_size;
		}
		if (trace_data_section1_size) {
			memcpy(buf->base + buf->pos,
			       component_sink->sink.vaddr +
					trace_data_section1_start,
			       trace_data_section1_size);
			buf->pos += trace_data_section1_size;
		}

		sink_data_size = trace_data_section0_size +
				 trace_data_section1_size +
				 sizeof(struct xuantie_saved_config);

		perf_aux_output_end(&xuantie_ntrace_pmu.handle, sink_data_size);

		if (truncated)
			break;
	}

done:
	rcu_read_unlock();
	complete_all(&xuantie_ntrace_pmu.commit_done);
}

/*
 * event_del() is called in various scenarios. Determine whether to commit
 * trace data to the aux buffer (task exiting) or just stop the hardware:
 *
 * Scenario                                      | Behavior        | Condition
 * ----------------------------------------------|-----------------|------------------------------------------
 * 1a. Direct launch, child thread exits         | stop HW only    | PF_EXITING && !SIGNAL_GROUP_EXIT
 * 1b. Direct launch, main thread pthread_exit() | stop HW only    | PF_EXITING && !SIGNAL_GROUP_EXIT
 * 1c. Direct launch, process exit (exit_group)  | commit          | PF_EXITING && SIGNAL_GROUP_EXIT
 * 1d. Direct launch, Ctrl+C (fatal SIGINT)      | commit          | PF_EXITING && SIGNAL_GROUP_EXIT
 * 2a. -p pid attach, child thread exits         | stop HW only    | PF_EXITING && !SIGNAL_GROUP_EXIT
 * 2b. -p pid attach, main thread pthread_exit() | stop HW only    | PF_EXITING && !SIGNAL_GROUP_EXIT
 * 2c. -p pid attach, process exit (exit_group)  | commit          | PF_EXITING && SIGNAL_GROUP_EXIT
 * 2d. -t tid attach (leader), thread exits      | commit          | PF_EXITING && SIGNAL_GROUP_EXIT
 * 2e. -t tid attach (non-leader), thread exits  | commit          | PF_EXITING && task == target_task
 * 2f. Ctrl+C, target task still alive (-p/-t)   | commit          | via sysfs commit trigger
 * 3.  Context switch (schedule out)             | stop HW only    | no PF_EXITING, no STATE_EXIT
 *
 * SIGNAL_GROUP_EXIT is process-wide: set by do_group_exit() (exit_group
 * syscall) and by complete_signal() for fatal signals (Ctrl+C SIGINT on
 * a launched workload). It is NOT set by pthread_exit(). Because every
 * dying thread of a group exit sees it, the commit must NOT be limited
 * to the group leader: the leader may be blocked (e.g. pthread_join)
 * with its event already OFF (disabled by perf record on Ctrl+C), so
 * its event_del() may never run. Any dying thread may commit instead.
 *
 * Note (2f): event_del() cannot see this case. When perf record is
 * killed while the target keeps running, the tool first disables the
 * events (IOC_DISABLE): that del runs with a live task and an ACTIVE
 * event, so it only stops the encoder. The final remove on fd close
 * then finds the event OFF and event_sched_out() never calls pmu->del
 * again. The "state == PERF_EVENT_STATE_EXIT" checks below are kept
 * only as a safety net: STATE_EXIT is set by perf_event_exit_event()
 * after pmu->del, and pmu->del is only ever invoked on ACTIVE events,
 * so they cannot trigger. Instead, the perf tool arms its auxtrace
 * snapshot-on-exit hook and, after its main loop ends but before its
 * final buffer flush, writes the PMU sysfs "commit" file: commit_store()
 * commits the session synchronously (and waits for a racing task-exit
 * commit to finish flushing via commit_done), so the data is always
 * visible in the AUX ring when the tool reads it. event_unmapped()
 * remains only as a backstop that closes the hardware and the AUX
 * transaction on mapping teardown - by then perf.data is already
 * written, so it cannot save the data.
 *
 * Note (1c/1d): the tool's sysfs trigger fires there too, racing the
 * task-exit commit; whichever wins commits, the other is a no-op
 * (session_committed), and commit_store() returns only after the
 * winning commit has fully landed (commit_done completion).
 *
 * Note: target_task is recorded in event_init() from event->hw.target
 * (fixed at perf_event_open time), only for directly-created events on
 * non-leader threads when no leader-targeted event exists (-t tid mode).
 * It must NOT be derived from event->ctx->task in event_add(): the perf
 * ctx-swap optimization (context_equiv()) migrates events between
 * threads' contexts, so a leader's original event can show up with
 * ctx->task pointing at a child thread, which would falsely mark that
 * thread as the target and commit on its exit.
 *
 * Note: multiple events (one per thread) may qualify for commit in the
 * same session (group exit kills all threads). A session-level flag
 * session_committed guards perf_aux_output_end(): it is reset in
 * setup_aux() (once per AUX mmap, i.e. per perf session) and set after
 * the first commit, so exactly one commit happens per session.
 * A per-event flag cannot provide this cross-event dedupe, and resetting
 * a global flag in event_add() breaks it (add/del cycles on sched-in).
 */
static void xuantie_ntrace_event_del(struct perf_event *event, int flags)
{
	bool is_task_exit = false;
	struct task_struct *task = event->ctx->task;

	// pr_info("%s:%d flags=%d\n", __func__, __LINE__, flags);

	/* Determine if the program has exited */
	if (task) {
		if (task->flags & PF_EXITING) {
			/*
			 * Task is exiting. SIGNAL_GROUP_EXIT is process-wide:
			 * it is set by do_group_exit() (exit_group syscall) and
			 * by complete_signal() for fatal signals (e.g. Ctrl+C
			 * SIGINT kills the launched workload). Any dying thread
			 * may commit - do not require the group leader, whose
			 * event may already be OFF (disabled by perf record)
			 * and thus never reach event_del().
			 */
			is_task_exit = (task->signal->flags & SIGNAL_GROUP_EXIT) ||
					task == READ_ONCE(xuantie_ntrace_pmu.target_task);
		} else {
			/* Safety net only, unreachable: see Note (2f) above */
			is_task_exit = (event->state == PERF_EVENT_STATE_EXIT);
		}
	} else {
		/* per-cpu event: perf record is killed or Ctrl+C */
		is_task_exit = (event->state == PERF_EVENT_STATE_EXIT) ||
					!event->ctx->is_active;
	}

	if (is_task_exit)
		xuantie_ntrace_session_commit(event, false);
	else
		xuantie_ntrace_event_stop(event, flags);
}

static void xuantie_ntrace_event_start(struct perf_event *event, int flags)
{
	struct xuantie_ntrace_component *component;
	int found_encoder = 0;
	/*
	 * Per-thread events (-p/-t) have event->cpu == -1; their pmu
	 * callbacks run on the CPU the traced task is scheduled on, so
	 * use smp_processor_id() there. Indexing cpuid_to_hartid_map()
	 * with -1 would be an out-of-bounds access.
	 */
	u32 hartid = cpuid_to_hartid_map(event->cpu >= 0 ? event->cpu :
					   smp_processor_id());
	unsigned long irqflags;

	//pr_info("%s:%d on_cpu=%d cpu=%d[hart%d] flags=%d\n", __func__, __LINE__,
	//	event->oncpu, event->cpu, hartid, flags);

	raw_spin_lock_irqsave(&xuantie_ntrace_hw_lock, irqflags);

	/* Session committed: hardware already closed by event_del. */
	if (xuantie_ntrace_pmu.session_committed) {
		event->hw.state = PERF_HES_STOPPED;
		raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);
		return;
	}

	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == NTRACE_TYPE_ENCODER) {
			if (component->encoder.cpu == hartid) {
				if (xt_trace_encoder_enable(
					    &component->encoder_info,
					    component->encoder.enable_timestamp))
					pr_info("Failed to enable encoder for hart %d\n", hartid);
				else {
					found_encoder = 1;
					break;
				}
			}
		}
	}

	if (!found_encoder) {
		pr_warn("no trace encoder enabled for hart %u, event on cpu %d produces no trace\n",
			hartid, event->cpu);
		event->hw.state = PERF_HES_STOPPED;
	}

	raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);
}

static void xuantie_ntrace_event_stop(struct perf_event *event, int flags)
{
	struct xuantie_ntrace_component *component;
	u32 hartid = cpuid_to_hartid_map(event->cpu >= 0 ? event->cpu :
					   smp_processor_id());
	unsigned long irqflags;

	//pr_info("%s:%d on_cpu=%d cpu=%d[hart%d] flags=%d\n", __func__, __LINE__,
	//	event->oncpu, event->cpu, hartid, flags);

	raw_spin_lock_irqsave(&xuantie_ntrace_hw_lock, irqflags);

	/* Session committed: hardware already closed by event_del. */
	if (xuantie_ntrace_pmu.session_committed) {
		raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);
		return;
	}

	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == NTRACE_TYPE_ENCODER) {
			if (component->encoder.cpu == hartid) {
				if (xt_trace_encoder_disable(
					    &component->encoder_info,
					    component->encoder.enable_timestamp))
					pr_info("Failed to disable encoder for hart %d\n",
						hartid);
				else
					break;
			}
		}
	}

	raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);
}

/*
 * Called from perf_mmap_close() in the perf tool's context whenever a
 * buffer mapped over one of this PMU's events is torn down (munmap or
 * tool exit; the fds are still open at this point, so @event is alive
 * and perf_aux_output_begin() in the commit path can still succeed -
 * it fails gracefully once the AUX pages are gone).
 *
 * For scenario 2f (perf record killed while the target keeps running)
 * the primary commit point is the sysfs "commit" trigger, which the
 * tool fires from its auxtrace snapshot-on-exit hook before the final
 * buffer flush (see the Note (2f) in event_del()). This hook is only a
 * backstop for the case that the trigger never fired: by buffer
 * teardown time perf.data is already being written, so a commit here
 * may no longer reach the output file, but it still closes the
 * hardware and the AUX transaction instead of leaking the session.
 * Runs in process context; only_if_started makes the calls for
 * sessions that never added an event, or that already committed on
 * task exit, a no-op.
 */
static void xuantie_ntrace_event_unmapped(struct perf_event *event,
					  struct mm_struct *mm)
{
	xuantie_ntrace_session_commit(event, true);
}

/*
 * aux_buffer_setup() - Setup AUX buffer for diagnostic mode sampling
 * @event:	Event the buffer is setup for, event->cpu == -1 means current
 * @pages:	Array of pointers to buffer pages passed from perf core
 * @nr_pages:	Total pages
 * @snapshot:	Flag for snapshot mode
 *
 * This is the callback when setup an event using AUX buffer. Perf tool can
 * trigger this by an additional mmap() call on the event. Unlike the buffer
 * for basic samples, AUX buffer belongs to the event. It is scheduled with
 * the task among online cpus when it is a per-thread event.
 *
 * Return the private AUX buffer structure if success or NULL if fails.
 */
static void *xuantie_ntrace_buffer_setup_aux(struct perf_event *event, void **pages,
					 int nr_pages, bool overwrite)
{
	struct xuantie_ntrace_aux_buf *buf;
	struct page **pagelist;
	unsigned long irqflags;
	int i;

	// pr_info("%s:%d\n", __func__, __LINE__);

	if (overwrite) {
		pr_warn("Overwrite mode is not supported\n");
		return NULL;
	}

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return NULL;

	pagelist = kcalloc(nr_pages, sizeof(*pagelist), GFP_KERNEL);
	if (!pagelist)
		goto err;

	for (i = 0; i < nr_pages; i++)
		pagelist[i] = virt_to_page(pages[i]);

	buf->base = vmap(pagelist, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!buf->base) {
		kfree(pagelist);
		goto err;
	}

	buf->nr_pages = nr_pages;
	buf->length = nr_pages * PAGE_SIZE;
	buf->pos = 0;

	/*
	 * New AUX mmap = new trace session: allow one commit for it and force
	 * the trace components to be configured again on the first add.
	 * (Unlike target_task/has_leader_event, these must be reset here
	 * rather than in free_aux: the previous session's free_aux can be
	 * deferred, and a session that ended without committing must not
	 * leave hw_configured set for the next one.)
	 */
	raw_spin_lock_irqsave(&xuantie_ntrace_hw_lock, irqflags);
	xuantie_ntrace_pmu.session_committed = false;
	xuantie_ntrace_pmu.hw_configured = false;
	reinit_completion(&xuantie_ntrace_pmu.commit_done);
	raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);

	/* aux_owner is owner_mutex-protected: see commit_store()/free_aux() */
	mutex_lock(&xuantie_ntrace_owner_mutex);
	xuantie_ntrace_pmu.aux_owner = event;
	mutex_unlock(&xuantie_ntrace_owner_mutex);

	pr_info("nr_pages=%ld length=%ld\n", buf->nr_pages, buf->length);

	kfree(pagelist);
	return buf;
err:
	kfree(buf);
	return NULL;
}

/*
 * Callback when freeing AUX buffers.
 */
static void xuantie_ntrace_buffer_free_aux(void *aux)
{
	struct xuantie_ntrace_aux_buf *buf = aux;

	// pr_info("%s:%d\n", __func__, __LINE__);

	/*
	 * Session teardown: reset target tracking for the next session.
	 * (setup_aux is too late - it runs at mmap time, after event_init
	 * has already recorded target_task/has_leader_event.)
	 */
	WRITE_ONCE(xuantie_ntrace_pmu.target_task, NULL);
	WRITE_ONCE(xuantie_ntrace_pmu.has_leader_event, false);

	/*
	 * Serialize against commit_store(): it uses aux_owner under
	 * owner_mutex, and blocking here (perf_mmap_close path, always
	 * process context) keeps the vma -> file -> event reference chain
	 * alive until the writer is done. Skip the lock when re-entered
	 * from the writer's own perf_aux_output_end() dropping the last
	 * aux reference.
	 */
	if (xuantie_ntrace_owner_task == current) {
		xuantie_ntrace_pmu.aux_owner = NULL;
	} else {
		mutex_lock(&xuantie_ntrace_owner_mutex);
		xuantie_ntrace_pmu.aux_owner = NULL;
		mutex_unlock(&xuantie_ntrace_owner_mutex);
	}

	vunmap(buf->base);
	kfree(buf);
}

static bool xuantie_ntrace_all_sinks_in_iommu_group(struct xuantie_ntrace_drvdata *drvdata)
{
	struct xuantie_ntrace_component *comp;
	struct iommu_group *group;
	bool all_sinks_ready = true;

	mutex_lock(&xuantie_ntrace_lock);
	list_for_each_entry(comp, &xuantie_ntrace_controllers, list) {
		if (comp->type != NTRACE_TYPE_SINK_SMEM)
			continue;

		if (comp->sink.is_resv_mem)
			continue;

		group = iommu_group_get(&comp->pdev->dev);
		if (!group) {
			dev_warn(&comp->pdev->dev, "Sink not yet in IOMMU group\n");
			all_sinks_ready = false;
		} else {
			iommu_group_put(group);
		}
	}
	mutex_unlock(&xuantie_ntrace_lock);

	return all_sinks_ready;
}

static bool xuantie_ntrace_all_devices_probed(struct xuantie_ntrace_drvdata *drvdata)
{
	int i;

	for (i = 0; i < NTRACE_TYPE_MAX; i++) {
		struct ntrace_dev_type *type = &drvdata->dev_types[i];

		if (!type->probe_complete) {
			pr_err("%s not yet fully probed (%u/%u)\n",
				 type->compatible, type->probed_count,
				 type->expected_count);
			return false;
		}
	}

	// Additional check: all sinks must be in IOMMU groups
	if (!xuantie_ntrace_all_sinks_in_iommu_group(drvdata)) {
		pr_err("Not all sinks in IOMMU groups yet\n");
		return false;
	}

	return true;
}

static void xuantie_ntrace_controllers_dump(void)
{
	struct xuantie_ntrace_component *component;

	mutex_lock(&xuantie_ntrace_lock);
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		pr_info("type=%s in_num=%d out_num=%d\n",
			xuantie_ntrace_type2str(component->type),
			component->in_num, component->out_num);
		for (int i = 0; i < component->in_num; i++) {
			pr_info("\t in[%d] type=%s base_addr=0x%llx\n", i,
				xuantie_ntrace_type2str(component->in[i]->type),
				component->in[i]->base_addr);
		}
		for (int j = 0; j < component->out_num; j++) {
			pr_info("\t out[%d] type=%s base_addr=0x%llx\n", j,
				xuantie_ntrace_type2str(
					component->out[j]->type),
				component->out[j]->base_addr);
		}
	}
	mutex_unlock(&xuantie_ntrace_lock);
}

static void xuantie_ntrace_try_register_pmu(struct xuantie_ntrace_drvdata *drvdata)
{
	int ret;

	if (drvdata->pmu_registered)
		return;

	if (!xuantie_ntrace_all_devices_probed(drvdata))
		return;

	pr_info("All components ready, registering PMU\n");

	xuantie_ntrace_pmu.pmu.module		= THIS_MODULE;
	xuantie_ntrace_pmu.pmu.capabilities	= PERF_PMU_CAP_EXCLUSIVE | PERF_PMU_CAP_ITRACE;
	xuantie_ntrace_pmu.pmu.task_ctx_nr	= perf_sw_context;
	xuantie_ntrace_pmu.pmu.attr_groups	= xuantie_ntrace_attr_groups;
	xuantie_ntrace_pmu.pmu.event_init	= xuantie_ntrace_event_init;
	xuantie_ntrace_pmu.pmu.setup_aux	= xuantie_ntrace_buffer_setup_aux;
	xuantie_ntrace_pmu.pmu.free_aux		= xuantie_ntrace_buffer_free_aux;
	xuantie_ntrace_pmu.pmu.start		= xuantie_ntrace_event_start;
	xuantie_ntrace_pmu.pmu.stop			= xuantie_ntrace_event_stop;
	xuantie_ntrace_pmu.pmu.add			= xuantie_ntrace_event_add;
	xuantie_ntrace_pmu.pmu.del			= xuantie_ntrace_event_del;
	xuantie_ntrace_pmu.pmu.event_unmapped	= xuantie_ntrace_event_unmapped;

	init_completion(&xuantie_ntrace_pmu.commit_done);

	ret = perf_pmu_register(&xuantie_ntrace_pmu.pmu, XUANTIE_NTRACE_PMU_NAME, -1);
	if (ret) {
		pr_err("Failed to register PMU %s: %d\n", XUANTIE_NTRACE_PMU_NAME, ret);
		return;
	}
	pr_info("%s registered.\n", XUANTIE_NTRACE_PMU_NAME);

	xuantie_ntrace_controllers_dump();

	drvdata->pmu_registered = true;
	complete_all(&drvdata->all_probed);
}

static void xuantie_ntrace_count_expected_devices(struct xuantie_ntrace_drvdata *drvdata)
{
	struct device_node *np;
	int i;

	for (i = 0; i < NTRACE_TYPE_MAX; i++) {
		struct ntrace_dev_type *type = &drvdata->dev_types[i];
		u32 count = 0;

		for_each_compatible_node(np, NULL, type->compatible) {
			if (of_device_is_available(np))
				count++;
		}
		type->expected_count = count;
		pr_info("Found %u %s device(s) in DT\n", count, type->compatible);
	}
}

static void xuantie_ntrace_free_component(struct xuantie_ntrace_component *comp)
{
	int i;

	if (!comp)
		return;

	if (comp->reg_base)
		iounmap((void __iomem *)(unsigned long)comp->reg_base);

	for (i = 0; i < comp->in_num; i++)
		kfree(comp->in[i]);
	kfree(comp->in);

	for (i = 0; i < comp->out_num; i++)
		kfree(comp->out[i]);
	kfree(comp->out);

	kfree(comp);
}

int xuantie_ntrace_add_device_node(struct platform_device *pdev,
				enum xuantie_ntrace_dev_type type,
				struct xuantie_ntrace_component *comp)
{
	struct xuantie_ntrace_drvdata *drvdata = ntrace_drvdata;
	struct ntrace_dev_type *dev_type;
	struct ntrace_dev_node *node;

	if (!drvdata) {
		dev_err(&pdev->dev, "Driver data not initialized\n");
		return -ENODEV;
	}

	dev_type = &drvdata->dev_types[type];

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->pdev = pdev;
	node->dev = &pdev->dev;
	node->type = type;
	node->component = comp;

	mutex_lock(&xuantie_ntrace_lock);
	raw_spin_lock_irq(&xuantie_ntrace_hw_lock);
	list_add_tail_rcu(&comp->list, &xuantie_ntrace_controllers);
	raw_spin_unlock_irq(&xuantie_ntrace_hw_lock);
	mutex_unlock(&xuantie_ntrace_lock);

	mutex_lock(&drvdata->lock);
	dev_type->probed_count++;

	dev_info(&pdev->dev, "%s probed (%u/%u)\n",
		 dev_type->compatible, dev_type->probed_count,
		 dev_type->expected_count);

	// Check if this type is now complete
	if (dev_type->probed_count >= dev_type->expected_count)
		dev_type->probe_complete = true;

	// Try to register PMU if all conditions are met
	xuantie_ntrace_try_register_pmu(drvdata);

	mutex_unlock(&drvdata->lock);

	platform_set_drvdata(pdev, node);

	return 0;
}

int xuantie_ntrace_remove_device_node(struct platform_device *pdev)
{
	struct xuantie_ntrace_drvdata *drvdata = ntrace_drvdata;
	struct ntrace_dev_node *node = platform_get_drvdata(pdev);
	struct ntrace_dev_type *dev_type;

	if (!drvdata || !node)
		return 0;

	dev_type = &drvdata->dev_types[node->type];

	mutex_lock(&drvdata->lock);
	if (drvdata->pmu_registered) {
		unsigned long irqflags;

		perf_pmu_unregister(&xuantie_ntrace_pmu.pmu);
		drvdata->pmu_registered = false;
		trace_component_detected = false;

		/* Reset the session state too. */
		raw_spin_lock_irqsave(&xuantie_ntrace_hw_lock, irqflags);
		xuantie_ntrace_pmu.session_committed = false;
		xuantie_ntrace_pmu.hw_configured = false;
		raw_spin_unlock_irqrestore(&xuantie_ntrace_hw_lock, irqflags);
	}
	dev_type->probed_count--;
	dev_type->probe_complete = false;
	mutex_unlock(&drvdata->lock);

	mutex_lock(&xuantie_ntrace_owner_mutex);

	if (node->component) {
		mutex_lock(&xuantie_ntrace_lock);
		raw_spin_lock_irq(&xuantie_ntrace_hw_lock);
		list_del_rcu(&node->component->list);
		raw_spin_unlock_irq(&xuantie_ntrace_hw_lock);
		mutex_unlock(&xuantie_ntrace_lock);

		synchronize_rcu();

		xuantie_ntrace_free_component(node->component);
	}

	kfree(node);

	mutex_unlock(&xuantie_ntrace_owner_mutex);

	return 0;
}

static int __init xuantie_ntrace_init(void)
{
	struct xuantie_ntrace_drvdata *drvdata;
	int ret;

	pr_info("Initializing Xuantie NTrace PMU driver\n");

	drvdata = kzalloc(sizeof(*drvdata), GFP_KERNEL);
	if (!drvdata)
		return -ENOMEM;

	trace_component_detected = false;

	mutex_init(&drvdata->lock);
	init_completion(&drvdata->all_probed);
	drvdata->pmu_registered = false;

	// Initialize device type tracking
	drvdata->dev_types[NTRACE_TYPE_ENCODER].compatible = "xuantie_ntrace,encoder-controller";
	drvdata->dev_types[NTRACE_TYPE_FUNNEL].compatible = "xuantie_ntrace,funnel-controller";
	drvdata->dev_types[NTRACE_TYPE_SINK_SMEM].compatible = "xuantie_ntrace,sink-controller";

	// Count expected devices from DT
	xuantie_ntrace_count_expected_devices(drvdata);

	ntrace_drvdata = drvdata;

	// Register platform drivers
	ret = platform_driver_register(&xuantie_ntrace_encoder_driver);
	if (ret) {
		pr_err("Failed to register encoder driver: %d\n", ret);
		goto err_free_drvdata;
	}

	ret = platform_driver_register(&xuantie_ntrace_funnel_driver);
	if (ret) {
		pr_err("Failed to register funnel driver: %d\n", ret);
		goto err_unregister_encoder;
	}

	ret = platform_driver_register(&xuantie_ntrace_sink_driver);
	if (ret) {
		pr_err("Failed to register sink driver: %d\n", ret);
		goto err_unregister_funnel;
	}

	return 0;

err_unregister_funnel:
	platform_driver_unregister(&xuantie_ntrace_funnel_driver);
err_unregister_encoder:
	platform_driver_unregister(&xuantie_ntrace_encoder_driver);
err_free_drvdata:
	kfree(drvdata);
	ntrace_drvdata = NULL;
	return ret;
}

static void __exit xuantie_ntrace_exit(void)
{
	struct xuantie_ntrace_drvdata *drvdata = ntrace_drvdata;

	if (!drvdata)
		return;

	if (drvdata->pmu_registered)
		perf_pmu_unregister(&xuantie_ntrace_pmu.pmu);

	platform_driver_unregister(&xuantie_ntrace_sink_driver);
	platform_driver_unregister(&xuantie_ntrace_funnel_driver);
	platform_driver_unregister(&xuantie_ntrace_encoder_driver);

	/* Free all device nodes and their components */
	{
		struct xuantie_ntrace_component *comp, *tmp;

		list_for_each_entry_safe(comp, tmp, &xuantie_ntrace_controllers, list) {
			struct ntrace_dev_node *node = platform_get_drvdata(comp->pdev);

			list_del(&comp->list);
			xuantie_ntrace_free_component(comp);
			if (node)
				kfree(node);
		}
	}

	kfree(drvdata);
	ntrace_drvdata = NULL;
}

module_init(xuantie_ntrace_init);
module_exit(xuantie_ntrace_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jiangshuai Li <jiangshuai_li@linux.alibaba.com>");
MODULE_AUTHOR("Chen Pei <cp0613@linux.alibaba.com>");
MODULE_DESCRIPTION("Driver for XUANTIE RISC-V Nexus Trace Device");
