/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hygon Non-Atomic FPU Management Interface
 *
 * This file implements a specialized FPU state management mechanism for
 * kernel routines that require extended usage of SIMD/FPU registers without
 * the strict constraints of the standard preemptible kernel_fpu mode.
 *
 * Standard kernel FPU usage (kernel_fpu_begin/end) requires preemption to
 * be disabled throughout the operation. For long-running memory copy
 * operations (e.g., Hygon Large Memory Copy), disabling preemption for the
 * entire duration is undesirable or may violate latency constraints.
 *
 * This interface provides a non-atomic alternative:
 *
 * 1. kernel_fpu_begin_nonatomic_mask():
 *    - Checks for safe conditions (no pre-existing FPU state, not in interrupt
 *      context, sufficient fpstate free space).
 *    - Saves the current FPU registers to the task's fpstate buffer.
 *    - Marks the task as 'TIF_USING_FPU_NONATOMIC'.
 *    - Allows preemption to be re-enabled immediately after saving state,
 *      so the actual FPU operation (copy) can run with preemption enabled.
 *
 * 2. kernel_fpu_end_nonatomic():
 *    - Clears the 'TIF_USING_FPU_NONATOMIC' flag.
 *    - Signals that the FPU registers are no longer being used by the kernel
 *      routine and can be restored or dirtied by the scheduler.
 *
 * Copyright (C) 2026 Zhiteng Qiu <qiuzhiteng@hygon.cn>
 */
#include <linux/percpu.h>
#include <linux/sched.h>
#include <asm/fpu/internal.h>
#include <asm/msr.h>
#include <asm/fpu/api.h>
#include <asm/fpu/signal.h>

#include "context.h"
#include "internal.h"
#include "legacy.h"
#include "xstate.h"


#include <asm/trace/fpu.h>

extern struct fpu_state_config fpu_kernel_cfg, fpu_user_cfg;

#if defined(CONFIG_X86_HYGON_LMC_SSE2_ON) || \
	defined(CONFIG_X86_HYGON_LMC_AVX2_ON)
extern void save_fpregs_to_fpstate(struct fpu *fpu);


unsigned int get_fpustate_free_space(struct fpu *fpu)
{
	if ((fpu_kernel_cfg.default_size + fpu_kernel_nonatomic_xstate_size) >
	    sizeof(fpu->fpstate->regs))
		return 0;
	return fpu_kernel_nonatomic_xstate_size;
}

/*
 * We can call kernel_fpu_begin_nonatomic in non-atomic task context.
 */
int kernel_fpu_begin_nonatomic_mask(unsigned int kfpu_mask)
{
    unsigned long flags;

	preempt_disable();

	/*
	 * This means we call kernel_fpu_begin_nonatomic after kernel_fpu_begin,
	 * but before kernel_fpu_end.
	 */
	if (KERNEL_FPU_NONATOMIC_SIZE >
	    get_fpustate_free_space(&current->thread.fpu))
		goto err;	

	if (test_thread_flag(TIF_USING_FPU_NONATOMIC))
		goto err;

	if (in_interrupt())
		goto err;

	if (current->flags & PF_KTHREAD)
		goto err;

    local_irq_save(flags);

	if (!test_thread_flag(TIF_NEED_FPU_LOAD)) {
		set_thread_flag(TIF_NEED_FPU_LOAD);
		save_fpregs_to_fpstate(&current->thread.fpu);
	}
	/* Set thread flag: TIC_USING_FPU_NONATOMIC */
	set_thread_flag(TIF_USING_FPU_NONATOMIC);

	__cpu_invalidate_fpregs_state();

    local_irq_restore(flags);

	/* Put sane initial values into the control registers. */
	if (likely(kfpu_mask & KFPU_MXCSR) && boot_cpu_has(X86_FEATURE_XMM))
		ldmxcsr(MXCSR_DEFAULT);

	if (unlikely(kfpu_mask & KFPU_387) && boot_cpu_has(X86_FEATURE_FPU))
		asm volatile ("fninit");

	preempt_enable();

	return 0;

err:
	preempt_enable();

	return -1;
}
EXPORT_SYMBOL(kernel_fpu_begin_nonatomic_mask);

void kernel_fpu_end_nonatomic(void)
{
	preempt_disable();
	/*
	 * This means we call kernel_fpu_end_nonatomic after kernel_fpu_begin,
	 * but before kernel_fpu_end.
	 */
    WARN_ON_FPU(!test_thread_flag(TIF_USING_FPU_NONATOMIC));

	clear_thread_flag(TIF_USING_FPU_NONATOMIC);

	preempt_enable();
}
EXPORT_SYMBOL(kernel_fpu_end_nonatomic);

#endif /* CONFIG_X86_HYGON_LMC_SSE2_ON || CONFIG_X86_HYGON_LMC_AVX2_ON */
