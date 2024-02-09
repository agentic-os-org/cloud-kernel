/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2024 Christoph Muellner <christoph.muellner@vrull.eu>
 */

#include <linux/cpu.h>
#include <linux/sched/signal.h>
#include <linux/smp.h>
#include <linux/prctl.h>

#include <asm/cpu.h>
#include <asm/dtso.h>

#include <trace/events/ipi.h>

static void dtso_apply_model_on_cpu(void *info)
{
	struct task_struct *task = info;

	/*
	 * Apply the memory consistency model to the task running on this
	 * CPU if it belongs to the thread group of the task that issued
	 * the prctl. A reschedule alone is not sufficient here, because
	 * schedule() skips context_switch() when prev == next, which
	 * would leave senvcfg.DTSO stale.
	 */
	if (same_thread_group(current, task))
		dtso_restore(current);
}

int dtso_set_memory_consistency_model(unsigned long arg)
{
	struct task_struct *t;
	unsigned long cur_model = get_memory_consistency_model(current);
	unsigned long new_model;

	switch (arg) {
	case PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO:
		new_model = RISCV_MEMORY_CONSISTENCY_MODEL_WMO;
		break;
	case PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO:
		new_model = RISCV_MEMORY_CONSISTENCY_MODEL_TSO;
		break;
	default:
		return -EINVAL;
	}

	/* No change requested. */
	if (cur_model == new_model)
		return 0;

	/* Enabling TSO only works if DTSO is available. */
	if (new_model == RISCV_MEMORY_CONSISTENCY_MODEL_TSO && !has_dtso())
		return -EINVAL;

	/* Switching TSO->WMO is not allowed. */
	if (new_model == RISCV_MEMORY_CONSISTENCY_MODEL_WMO)
		return -EINVAL;

	/*
	 * The stronger memory model affects all threads of the process,
	 * so update the memory model of every thread in the thread group.
	 */
	rcu_read_lock();
	for_each_thread(current, t)
		set_memory_consistency_model(t, new_model);
	rcu_read_unlock();

	/*
	 * Apply the new model on every CPU right away: neither the return
	 * to user space nor a reschedule necessarily involves a context
	 * switch (schedule() skips context_switch() when prev == next),
	 * so senvcfg.DTSO would otherwise stay stale until the next real
	 * context switch.
	 */
	on_each_cpu(dtso_apply_model_on_cpu, current, 1);

	return 0;
}

int dtso_get_memory_consistency_model(void)
{
	unsigned long cur_model = get_memory_consistency_model(current);

	if (cur_model == RISCV_MEMORY_CONSISTENCY_MODEL_TSO)
		return PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO;

	return PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO;
}
