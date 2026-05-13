// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Ant Group.
 */
#include <linux/kvm_host.h>

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
