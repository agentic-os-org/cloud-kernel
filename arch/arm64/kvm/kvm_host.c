// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Ant Group.
 */
#include <linux/kvm_host.h>
#include <linux/perf/arm_pmu.h>
#include <kvm/arm_pmu.h>
#include <asm/arm_pmuv3.h>

#include "vgic/vgic.h"

static enum kvm_mode kvm_mode = KVM_MODE_DEFAULT;

static int __init early_kvm_mode_cfg(char *arg)
{
	if (!arg)
		return -EINVAL;

	if (strcmp(arg, "none") == 0) {
		kvm_mode = KVM_MODE_NONE;
		return 0;
	}

	if (!is_hyp_mode_available()) {
		pr_warn_once("KVM is not available. Ignoring kvm-arm.mode\n");
		return 0;
	}

	if (strcmp(arg, "protected") == 0) {
		if (!is_kernel_in_hyp_mode())
			kvm_mode = KVM_MODE_PROTECTED;
		else
			pr_warn_once("Protected KVM not available with VHE\n");

		return 0;
	}

	if (strcmp(arg, "nvhe") == 0 && !WARN_ON(is_kernel_in_hyp_mode())) {
		kvm_mode = KVM_MODE_DEFAULT;
		return 0;
	}

	if (strcmp(arg, "nested") == 0 && !WARN_ON(!is_kernel_in_hyp_mode())) {
		kvm_mode = KVM_MODE_NV;
		return 0;
	}

	return -EINVAL;
}
early_param("kvm-arm.mode", early_kvm_mode_cfg);

enum kvm_mode kvm_get_mode(void)
{
	return kvm_mode;
}

struct gic_kvm_info *gic_kvm_info;

void __init vgic_set_kvm_info(const struct gic_kvm_info *info)
{
	BUG_ON(gic_kvm_info != NULL);
	gic_kvm_info = kmalloc_obj(*gic_kvm_info);
	if (gic_kvm_info)
		*gic_kvm_info = *info;
}

LIST_HEAD(arm_pmus);
DEFINE_MUTEX(arm_pmus_lock);

void kvm_host_pmu_init(struct arm_pmu *pmu)
{
	struct arm_pmu_entry *entry;

	/*
	 * Check the sanitised PMU version for the system, as KVM does not
	 * support implementations where PMUv3 exists on a subset of CPUs.
	 */
	if (!pmuv3_implemented(kvm_arm_pmu_get_pmuver_limit()))
		return;

	guard(mutex)(&arm_pmus_lock);

	entry = kmalloc_obj(*entry);
	if (!entry)
		return;

	entry->arm_pmu = pmu;
	list_add_tail(&entry->entry, &arm_pmus);
}

u8 kvm_arm_pmu_get_pmuver_limit(void)
{
	unsigned int pmuver;

	pmuver = SYS_FIELD_GET(ID_AA64DFR0_EL1, PMUVer,
			       read_sanitised_ftr_reg(SYS_ID_AA64DFR0_EL1));

	/*
	 * Spoof a barebones PMUv3 implementation if the system supports IMPDEF
	 * traps of the PMUv3 sysregs
	 */
	if (cpus_have_final_cap(ARM64_WORKAROUND_PMUV3_IMPDEF_TRAPS))
		return ID_AA64DFR0_EL1_PMUVer_IMP;

	/*
	 * Otherwise, treat IMPLEMENTATION DEFINED functionality as
	 * unimplemented
	 */
	if (pmuver == ID_AA64DFR0_EL1_PMUVer_IMP_DEF)
		return 0;

	return min(pmuver, ID_AA64DFR0_EL1_PMUVer_V3P5);
}

#ifdef CONFIG_KVM_ARM_HOST_VHE_ONLY
struct kvm_pmu_ops *kvm_pmu_ops;

DEFINE_STATIC_CALL_NULL(__kvm_set_pmu_events, *kvm_pmu_ops->set_pmu_events);
DEFINE_STATIC_CALL_NULL(__kvm_clr_pmu_events, *kvm_pmu_ops->clr_pmu_events);
DEFINE_STATIC_CALL_RET0(__kvm_set_pmuserenr, *kvm_pmu_ops->set_pmuserenr);
DEFINE_STATIC_CALL_NULL(__kvm_vcpu_pmu_resync_el0, *kvm_pmu_ops->vcpu_pmu_resync_el0);

void kvm_register_pmu_handlers(struct kvm_pmu_ops *ops)
{
	if (WARN_ON_ONCE(rcu_access_pointer(kvm_pmu_ops)))
		return;

	rcu_assign_pointer(kvm_pmu_ops, ops);
	static_call_update(__kvm_set_pmu_events, ops->set_pmu_events);
	static_call_update(__kvm_clr_pmu_events, ops->clr_pmu_events);
	static_call_update(__kvm_set_pmuserenr, ops->set_pmuserenr);
	static_call_update(__kvm_vcpu_pmu_resync_el0, ops->vcpu_pmu_resync_el0);
}

void kvm_unregister_pmu_handlers(struct kvm_pmu_ops *ops)
{
	if (WARN_ON_ONCE(rcu_access_pointer(kvm_pmu_ops) != ops))
		return;

	rcu_assign_pointer(kvm_pmu_ops, NULL);
	static_call_update(__kvm_set_pmu_events, NULL);
	static_call_update(__kvm_clr_pmu_events, NULL);
	static_call_update(__kvm_set_pmuserenr, (void *)&__static_call_return0);
	static_call_update(__kvm_vcpu_pmu_resync_el0, NULL);
	/*
	 * All consumers (arm_pmuv3.c) run in preempt-disabled context.
	 * synchronize_rcu() ensures all ongoing preempt-disabled sections
	 * complete before we return, so the module can be safely unloaded.
	 */
	synchronize_rcu();
}
#endif

