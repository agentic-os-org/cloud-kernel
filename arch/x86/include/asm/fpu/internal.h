/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_FPU_INTERNAL_H
#define _ASM_X86_FPU_INTERNAL_H
#include <linux/sched.h>
#include <asm/fpu/api.h>
#include <asm/fpu/types.h>

/*
 * Kernel FPU state switching for scheduling.
 *
 * This is a two-stage process:
 *
 *  - switch_kernel_fpu_prepare() saves the old kernel fpu state.
 *    This is done within the context of the old process.
 *
 *  - switch_kernel_fpu_finish() restore new kernel fpu state.
 *
 * The kernel FPU context is only stored/restored for a user task in kernel
 * mode and PF_KTHREAD is used to distinguish between kernel and user threads.
 */

#ifdef CONFIG_X86_HYGON_LMC_SSE2_ON
void fpu_save_xmm0_3(void *to, const void *from, unsigned len);
void fpu_restore_xmm0_3(void *to, const void *from, unsigned len);

#define kernel_fpu_states_save fpu_save_xmm0_3
#define kernel_fpu_states_restore fpu_restore_xmm0_3

/* SSE2: XMM0~3, totaling 4*16 = 64 bytes */
#define MAX_FPU_CTX_SIZE 64
#define KERNEL_FPU_NONATOMIC_SIZE (2 * (MAX_FPU_CTX_SIZE))

#endif

#ifdef CONFIG_X86_HYGON_LMC_AVX2_ON
void fpu_save_ymm0_7(void *to, const void *from, unsigned len);
void fpu_restore_ymm0_7(void *to, const void *from, unsigned len);

#define kernel_fpu_states_save fpu_save_ymm0_7
#define kernel_fpu_states_restore fpu_restore_ymm0_7

/* AVX2: YMM0~7, totaling 8*32 = 256 bytes */
#define MAX_FPU_CTX_SIZE 256
#define KERNEL_FPU_NONATOMIC_SIZE (2 * (MAX_FPU_CTX_SIZE))

#endif

#if defined(CONFIG_X86_HYGON_LMC_SSE2_ON) || \
	defined(CONFIG_X86_HYGON_LMC_AVX2_ON)

#define COPY_HYGON_LMC_NOT_HANDLED (~0UL)
extern unsigned int fpu_kernel_nonatomic_xstate_size;

static inline unsigned long get_fpu_registers_pos(struct fpu *fpu, unsigned int off)
{
	unsigned long addr = 0;

	if (fpu && (fpu_kernel_nonatomic_xstate_size > off)) {
		addr = (unsigned long)&fpu->__fpstate.regs.__padding[0];
		addr += fpu_kernel_cfg.default_size + off;
	}
	return addr;
}

static inline void save_fpregs_to_fpkernelstate(struct fpu *kfpu)
{
	kernel_fpu_states_save((void *)get_fpu_registers_pos(kfpu,
							     MAX_FPU_CTX_SIZE),
			       NULL, MAX_FPU_CTX_SIZE);
}

static inline void switch_kernel_fpu_prepare(struct task_struct *prev, int cpu)
{
	struct fpu *old_fpu = &prev->thread.fpu;

	if (!test_ti_thread_flag(task_thread_info(prev), TIF_USING_FPU_NONATOMIC))
		return;

	if (static_cpu_has(X86_FEATURE_FPU) && !(prev->flags & PF_KTHREAD))
		save_fpregs_to_fpkernelstate(old_fpu);
}

/* Internal helper for switch_kernel_fpu_finish() and signal frame setup */
static inline void fpregs_restore_kernelregs(struct fpu *kfpu)
{
	kernel_fpu_states_restore(NULL, (void *)get_fpu_registers_pos(kfpu, MAX_FPU_CTX_SIZE),
						MAX_FPU_CTX_SIZE);
}

/* Loading of the complete FPU state immediately. */
static inline void switch_kernel_fpu_finish(struct task_struct *next)
{
	struct fpu *new_fpu = &next->thread.fpu;

	if (next->flags & PF_KTHREAD)
		return;

	if (cpu_feature_enabled(X86_FEATURE_FPU) &&
	    test_ti_thread_flag(task_thread_info(next),
				TIF_USING_FPU_NONATOMIC))
		fpregs_restore_kernelregs(new_fpu);
}

extern int kernel_fpu_begin_nonatomic_mask(unsigned int kfpu_mask);
extern void kernel_fpu_end_nonatomic(void);

/* Code that is unaware of kernel_fpu_begin_nonatomic_mask() can use this */
static inline int kernel_fpu_begin_nonatomic(void)
{
	return kernel_fpu_begin_nonatomic_mask(KFPU_387 | KFPU_MXCSR);
}

static inline void check_using_kernel_fpu(bool flag)
{
	if (test_thread_flag(TIF_USING_FPU_NONATOMIC)) {
		struct fpu *current_fpu = &current->thread.fpu;

		if (flag)
			save_fpregs_to_fpkernelstate(current_fpu);
		else
			fpregs_restore_kernelregs(current_fpu);
	}
}

#else
static inline void switch_kernel_fpu_prepare(struct task_struct *prev, int cpu)
{
}
static inline void switch_kernel_fpu_finish(struct task_struct *next)
{
}

static inline void check_using_kernel_fpu(bool flag) { }

#endif

#endif /* _ASM_X86_FPU_INTERNAL_H */
