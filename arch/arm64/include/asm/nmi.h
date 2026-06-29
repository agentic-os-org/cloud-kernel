/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 ARM Ltd.
 */
#ifndef __ASM_NMI_H
#define __ASM_NMI_H

static __always_inline void _allint_clear(void)
{
	asm volatile(__msr_s(SYS_ALLINT_CLR, "xzr"));
}

static __always_inline void _allint_set(void)
{
	asm volatile(__msr_s(SYS_ALLINT_SET, "xzr"));
}

#include <linux/cpumask.h>

/*
 * Cross-CPU NMI provider hooks, consulted by the arm64 arch code before
 * its regular-IRQ / pseudo-NMI IPI paths. The SDEI provider in
 * drivers/firmware/arm_sdei_nmi.c implements them when active; a future
 * FEAT_NMI provider could slot in here too. The stubs let callers stay
 * unconditional when ARM_SDEI_NMI is off.
 */
#ifdef CONFIG_ARM_SDEI_NMI
bool sdei_nmi_trigger_cpumask_backtrace(const cpumask_t *mask, int exclude_cpu);
#else
static inline bool sdei_nmi_trigger_cpumask_backtrace(const cpumask_t *mask,
						      int exclude_cpu)
{
	return false;
}
#endif


#endif
