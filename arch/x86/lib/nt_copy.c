/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Non-Temporal (NT) Memory Copy Implementation for Hygon Processors
 *
 * This file provides optimized user-space memory copy routines tailored for
 * Hygon "Large Memory Copy" (LMC) scenarios. It utilizes non-temporal store
 * instructions (SSE2/AVX2) to bypass caches and minimize cache pollution when
 * handling large data blocks.
 *
 * Key features:
 * 1. Dynamic Implementation Selection:
 *    Depending on the kernel configuration (CONFIG_X86_HYGON_LMC_SSE2_ON or
 *    CONFIG_X86_HYGON_LMC_AVX2_ON), it maps the generic entry point
 *    'copy_large_memory_generic_string' to the appropriate SIMD assembly
 *    implementation (e.g., copy_user_sse2_opt_string or
 *    copy_user_avx2_pf64_nt_string).
 *
 * 2. Safety Checks & FPU Management:
 *    It implements 'Hygon_LMC_check' to determine whether the NT copy path
 *    should be used based on block size and system state. Critically, it
 *    encapsulates the necessary kernel FPU protection logic via
 *    'kernel_fpu_begin_nonatomic()' and 'kernel_fpu_end_nonatomic()' to
 *    safely utilize SIMD registers without corrupting user context or
 *    triggering #NM faults.
 *
 * Copyright (C) 2026 Zhiteng Qiu <qiuzhiteng@hygon.cn>
 */
#include <asm/fpu/internal.h>

#ifdef CONFIG_X86_HYGON_LMC_SSE2_ON

__must_check unsigned long copy_user_sse2_opt_string(void *to, const void *from,
						     unsigned len);

#define copy_user_large_memory_generic_string copy_user_sse2_opt_string

#endif

#ifdef CONFIG_X86_HYGON_LMC_AVX2_ON

__must_check unsigned long
copy_user_avx2_pf64_nt_string(void *to, const void *from, unsigned len);

#define copy_user_large_memory_generic_string copy_user_avx2_pf64_nt_string
#endif

#if defined(CONFIG_X86_HYGON_LMC_SSE2_ON) || \
	defined(CONFIG_X86_HYGON_LMC_AVX2_ON)
unsigned int get_nt_block_copy_mini_len(void);
bool Hygon_LMC_check(unsigned len)
{
	unsigned int nt_blk_cpy_mini_len = get_nt_block_copy_mini_len();

	if (((nt_blk_cpy_mini_len) && (nt_blk_cpy_mini_len <= len) &&
	     (system_state == SYSTEM_RUNNING) &&
	     (!kernel_fpu_begin_nonatomic())))
		return true;
	else
		return false;
}
EXPORT_SYMBOL(Hygon_LMC_check);

unsigned long
copy_large_memory_generic_string(void *to, const void *from, unsigned len)
{
	unsigned ret;

	ret = copy_user_large_memory_generic_string(to, from, len);
	kernel_fpu_end_nonatomic();
	return ret;
}
EXPORT_SYMBOL(copy_large_memory_generic_string);

#else
bool Hygon_LMC_check(unsigned len)
{
	return false;
}
EXPORT_SYMBOL(Hygon_LMC_check);
unsigned long
copy_large_memory_generic_string(void *to, const void *from, unsigned len)
{
	return 0;
}
EXPORT_SYMBOL(copy_large_memory_generic_string);
#endif
