// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025 Alibaba Cloud. or its affiliates. All Rights Reserved.
 */

#include <linux/arm-smccc.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <asm/pv_cpufreq-abi.h>

static bool smccc_support_cpufreq;	/* v1 call, reader's host CPU */
static bool smccc_support_cpufreq_v2;	/* v2 call, target guest CPU */
/*
 * Per-CPU buffer: concurrent pv_cpufreq_get() calls from different CPUs
 * must not share the destination the hypervisor writes to.  A stack
 * buffer is not an option here because __pa() is invalid for vmalloc'd
 * kernel stacks (CONFIG_VMAP_STACK).
 */
static DEFINE_PER_CPU_ALIGNED(struct pv_vcpu_freq, pv_vcpu_freq_buf);

unsigned int pv_cpufreq_get(unsigned int cpu)
{
	struct arm_smccc_res res;
	struct pv_vcpu_freq *buf;
	unsigned int freq_khz;

	if (!smccc_support_cpufreq_v2 && !smccc_support_cpufreq) {
		pr_warn_once("%s: SMCCC doesn't support to provide cpu frequency.\n", __func__);
		return 0;
	}

	preempt_disable();
	buf = this_cpu_ptr(&pv_vcpu_freq_buf);
	if (smccc_support_cpufreq_v2)
		arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_CPU_FREQ_GET_V2,
				     __pa(buf), cpu, &res);
	else
		arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_CPU_FREQ_GET,
				     __pa(buf), &res);
	if (res.a0 != SMCCC_RET_SUCCESS) {
		preempt_enable();
		pr_err("%s: Failed to get cpu frequency from host by SMCCC.\n", __func__);
		return 0;
	}
	freq_khz = le64_to_cpu(buf->freq_khz);
	preempt_enable();

	return freq_khz;
}

/*
 * Detect SMCCC support for guest cpu frequency.
 */
static __init int detect_smccc_support_cpufreq(void)
{
	struct arm_smccc_res res;

	// Initialization.
	smccc_support_cpufreq = false;
	smccc_support_cpufreq_v2 = false;

	/* To detect the presence of PV CPUFREQ support we require SMCCC 1.1+ */
	if (arm_smccc_1_1_get_conduit() == SMCCC_CONDUIT_NONE) {
		pr_warn_once("Kernel doesn't support SMCCC 1.1+.\n");
		return -EOPNOTSUPP;
	}

	/* Prefer the v2 call that carries the target guest CPU number */
	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
			     ARM_SMCCC_HV_PV_CPU_FREQ_GET_V2, &res);
	if (res.a0 == SMCCC_RET_SUCCESS) {
		smccc_support_cpufreq_v2 = true;
		return 0;
	}

	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
			     ARM_SMCCC_HV_PV_CPU_FREQ_FEATURES, &res);
	if (res.a0 == SMCCC_RET_SUCCESS) {
		smccc_support_cpufreq = true;
		return 0;
	}

	pr_warn_once("Hypervisor doesn't support pv cpufreq.\n");
	return -EOPNOTSUPP;
}
late_initcall(detect_smccc_support_cpufreq);
