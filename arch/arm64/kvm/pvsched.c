// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#ifdef CONFIG_PARAVIRT_SCHED
#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>

#include <asm/pvsched-abi.h>

#include <kvm/arm_hypercalls.h>

void kvm_update_pvsched_preempted(struct kvm_vcpu *vcpu, u32 preempted)
{
	struct kvm *kvm = vcpu->kvm;
	u64 base = vcpu->arch.pvsched.base;
	u64 offset = offsetof(struct pvsched_vcpu_state, preempted);
	int idx;

	if (base == INVALID_GPA)
		return;

	/*
	 * This function is called from atomic context, so we need to
	 * disable page faults.
	 */
	pagefault_disable();

	idx = srcu_read_lock(&kvm->srcu);
	kvm_put_guest(kvm, base + offset, cpu_to_le32(preempted));
	srcu_read_unlock(&kvm->srcu, idx);

	pagefault_enable();
}

#endif /* CONFIG_PARAVIRT_SCHED */
