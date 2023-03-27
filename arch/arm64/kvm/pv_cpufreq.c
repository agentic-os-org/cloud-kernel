// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Alibaba Cloud. or its affiliates. All Rights Reserved.
 */

#include <linux/cpufreq.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <kvm/arm_hypercalls.h>
#include <asm/kvm_mmu.h>
#include <asm/pv_cpufreq-abi.h>

static u32 kvm_pv_cpu_freq_writeback(struct kvm_vcpu *vcpu, u64 host_cpufreq_khz)
{
	struct pv_vcpu_freq vcpu_freq = {};
	gpa_t guest_cpu_freq;
	int ret;

	guest_cpu_freq = smccc_get_arg1(vcpu);
	vcpu_freq.freq_khz = cpu_to_le64(host_cpufreq_khz);
	ret = kvm_write_guest_lock(vcpu->kvm, guest_cpu_freq, &vcpu_freq,
				   sizeof(struct pv_vcpu_freq));
	if (ret)
		return SMCCC_RET_INVALID_PARAMETER;

	return SMCCC_RET_SUCCESS;
}

/*
 * v1: report the frequency of the host CPU serving the hypercall, i.e. the
 * one the calling vCPU happens to run on.
 */
u32 kvm_pv_cpu_freq_get(struct kvm_vcpu *vcpu)
{
	u64 host_cpufreq_khz;

	host_cpufreq_khz = cpufreq_get(smp_processor_id());
	if (!host_cpufreq_khz)
		return SMCCC_RET_NOT_SUPPORTED;

	return kvm_pv_cpu_freq_writeback(vcpu, host_cpufreq_khz);
}

/*
 * v2: the guest passes the target guest CPU number in arg2; report the
 * frequency of the host CPU where that vCPU's thread is (en)queued.
 */
u32 kvm_pv_cpu_freq_get_v2(struct kvm_vcpu *vcpu)
{
	struct task_struct *vcpu_task;
	struct kvm_vcpu *target;
	u64 host_cpufreq_khz;

	target = kvm_get_vcpu_by_id(vcpu->kvm, smccc_get_arg2(vcpu));
	if (!target)
		return SMCCC_RET_INVALID_PARAMETER;

	vcpu_task = get_pid_task(target->pid, PIDTYPE_PID);
	if (!vcpu_task)
		return SMCCC_RET_NOT_SUPPORTED;

	host_cpufreq_khz = cpufreq_get(task_cpu(vcpu_task));
	put_task_struct(vcpu_task);
	if (!host_cpufreq_khz)
		return SMCCC_RET_NOT_SUPPORTED;

	return kvm_pv_cpu_freq_writeback(vcpu, host_cpufreq_khz);
}
