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

