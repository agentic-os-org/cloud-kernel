/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_PARAVIRT_H
#define _ASM_ARM64_PARAVIRT_H

#ifdef CONFIG_PARAVIRT

int __init pv_time_init(void);

__visible bool __native_vcpu_is_preempted(int cpu);
DECLARE_STATIC_CALL(pv_vcpu_preempted, __native_vcpu_is_preempted);

static inline bool pv_vcpu_is_preempted(int cpu)
{
	return static_call(pv_vcpu_preempted)(cpu);
}

#else

#define pv_time_init() do {} while (0)

#endif // CONFIG_PARAVIRT

#endif
