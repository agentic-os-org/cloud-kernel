// SPDX-License-Identifier: GPL-2.0-only
/*
 * tools/testing/selftests/kvm/lib/x86_64/svm.c
 * Helpers used for nested SVM testing
 * Largely inspired from KVM unit test svm.c
 *
 * Copyright (C) 2020, Red Hat, Inc.
 */

#include "test_util.h"
#include "kvm_util.h"
#include "../kvm_util_internal.h"
#include "processor.h"
#include "svm_util.h"
#include <stddef.h>

struct gpr64_regs guest_regs;
u64 rflags;

/* Allocate memory regions for nested SVM tests.
 *
 * Input Args:
 *   vm - The VM to allocate guest-virtual addresses in.
 *
 * Output Args:
 *   p_svm_gva - The guest virtual address for the struct svm_test_data.
 *
 * Return:
 *   Pointer to structure with the addresses of the SVM areas.
 */
struct svm_test_data *
vcpu_alloc_svm(struct kvm_vm *vm, vm_vaddr_t *p_svm_gva)
{
	vm_vaddr_t svm_gva = vm_vaddr_alloc(vm, getpagesize(),
					    0x10000, 0, 0);
	struct svm_test_data *svm = addr_gva2hva(vm, svm_gva);

	svm->vmcb = (void *)vm_vaddr_alloc(vm, getpagesize(),
					   0x10000, 0, 0);
	svm->vmcb_hva = addr_gva2hva(vm, (uintptr_t)svm->vmcb);
	svm->vmcb_gpa = addr_gva2gpa(vm, (uintptr_t)svm->vmcb);

	svm->save_area = (void *)vm_vaddr_alloc(vm, getpagesize(),
						0x10000, 0, 0);
	svm->save_area_hva = addr_gva2hva(vm, (uintptr_t)svm->save_area);
	svm->save_area_gpa = addr_gva2gpa(vm, (uintptr_t)svm->save_area);

	*p_svm_gva = svm_gva;
	return svm;
}

static void vmcb_set_seg(struct vmcb_seg *seg, u16 selector,
			 u64 base, u32 limit, u32 attr)
{
	seg->selector = selector;
	seg->attrib = attr;
	seg->limit = limit;
	seg->base = base;
}

/*
 * Avoid using memset to clear the vmcb, since libc may not be
 * available in L1 (and, even if it is, features that libc memset may
 * want to use, like AVX, may not be enabled).
 */
static void clear_vmcb(struct vmcb *vmcb)
{
	int n = sizeof(*vmcb) / sizeof(u32);

	asm volatile ("rep stosl" : "+c"(n), "+D"(vmcb) : "a"(0) : "memory");
}

void generic_svm_setup(struct svm_test_data *svm, void *guest_rip, void *guest_rsp)
{
	struct vmcb *vmcb = svm->vmcb;
	uint64_t vmcb_gpa = svm->vmcb_gpa;
	struct vmcb_save_area *save = &vmcb->save;
	struct vmcb_control_area *ctrl = &vmcb->control;
	u32 data_seg_attr = 3 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK
	      | SVM_SELECTOR_DB_MASK | SVM_SELECTOR_G_MASK;
	u32 code_seg_attr = 9 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK
		| SVM_SELECTOR_L_MASK | SVM_SELECTOR_G_MASK;
	uint64_t efer;

	efer = rdmsr(MSR_EFER);
	wrmsr(MSR_EFER, efer | EFER_SVME);
	wrmsr(MSR_VM_HSAVE_PA, svm->save_area_gpa);

	clear_vmcb(vmcb);
	asm volatile ("vmsave %0\n\t" : : "a" (vmcb_gpa) : "memory");
	vmcb_set_seg(&save->es, get_es(), 0, -1U, data_seg_attr);
	vmcb_set_seg(&save->cs, get_cs(), 0, -1U, code_seg_attr);
	vmcb_set_seg(&save->ss, get_ss(), 0, -1U, data_seg_attr);
	vmcb_set_seg(&save->ds, get_ds(), 0, -1U, data_seg_attr);
	vmcb_set_seg(&save->gdtr, 0, get_gdt().address, get_gdt().size, 0);
	vmcb_set_seg(&save->idtr, 0, get_idt().address, get_idt().size, 0);

	ctrl->asid = 1;
	save->cpl = 0;
	save->efer = rdmsr(MSR_EFER);
	asm volatile ("mov %%cr4, %0" : "=r"(save->cr4) : : "memory");
	asm volatile ("mov %%cr3, %0" : "=r"(save->cr3) : : "memory");
	asm volatile ("mov %%cr0, %0" : "=r"(save->cr0) : : "memory");
	asm volatile ("mov %%dr7, %0" : "=r"(save->dr7) : : "memory");
	asm volatile ("mov %%dr6, %0" : "=r"(save->dr6) : : "memory");
	asm volatile ("mov %%cr2, %0" : "=r"(save->cr2) : : "memory");
	save->g_pat = rdmsr(MSR_IA32_CR_PAT);
	save->dbgctl = rdmsr(MSR_IA32_DEBUGCTLMSR);
	ctrl->intercept = (1ULL << INTERCEPT_VMRUN) |
				(1ULL << INTERCEPT_VMMCALL);

	vmcb->save.rip = (u64)guest_rip;
	vmcb->save.rsp = (u64)guest_rsp;
	guest_regs.rdi = (u64)svm;
	guest_regs.rax = 0;
	rflags = X86_EFLAGS_FIXED;
}

/*
 * VMRUN handles rAX, rIP and rSP through the VMCB.  Exchange the
 * remaining guest GPRs with their correctly indexed software slots.
 * Each exchange is repeated after VMEXIT to restore the L1 registers.
 */
void run_guest(struct vmcb *vmcb, uint64_t vmcb_gpa)
{
	_Static_assert(offsetof(struct vmcb, save) == 0x400,
		       "Unexpected VMCB save-area offset");
	_Static_assert(offsetof(struct vmcb, save.rflags) == 0x570,
		       "Unexpected VMCB RFLAGS offset");
	_Static_assert(offsetof(struct vmcb, save.rax) == 0x5f8,
		       "Unexpected VMCB RAX offset");

	vmcb->save.rflags = rflags;
	vmcb->save.rax = guest_regs.rax;
	asm volatile (
		"vmload %[vmcb_gpa]\n\t"
		"xchg %%rbx, guest_regs+%c[off_rbx](%%rip)\n\t"
		"xchg %%rcx, guest_regs+%c[off_rcx](%%rip)\n\t"
		"xchg %%rdx, guest_regs+%c[off_rdx](%%rip)\n\t"
		"xchg %%rbp, guest_regs+%c[off_rbp](%%rip)\n\t"
		"xchg %%rsi, guest_regs+%c[off_rsi](%%rip)\n\t"
		"xchg %%rdi, guest_regs+%c[off_rdi](%%rip)\n\t"
		"xchg %%r8, guest_regs+%c[off_r8](%%rip)\n\t"
		"xchg %%r9, guest_regs+%c[off_r9](%%rip)\n\t"
		"xchg %%r10, guest_regs+%c[off_r10](%%rip)\n\t"
		"xchg %%r11, guest_regs+%c[off_r11](%%rip)\n\t"
		"xchg %%r12, guest_regs+%c[off_r12](%%rip)\n\t"
		"xchg %%r13, guest_regs+%c[off_r13](%%rip)\n\t"
		"xchg %%r14, guest_regs+%c[off_r14](%%rip)\n\t"
		"xchg %%r15, guest_regs+%c[off_r15](%%rip)\n\t"
		"vmrun %[vmcb_gpa]\n\t"
		"xchg %%rbx, guest_regs+%c[off_rbx](%%rip)\n\t"
		"xchg %%rcx, guest_regs+%c[off_rcx](%%rip)\n\t"
		"xchg %%rdx, guest_regs+%c[off_rdx](%%rip)\n\t"
		"xchg %%rbp, guest_regs+%c[off_rbp](%%rip)\n\t"
		"xchg %%rsi, guest_regs+%c[off_rsi](%%rip)\n\t"
		"xchg %%rdi, guest_regs+%c[off_rdi](%%rip)\n\t"
		"xchg %%r8, guest_regs+%c[off_r8](%%rip)\n\t"
		"xchg %%r9, guest_regs+%c[off_r9](%%rip)\n\t"
		"xchg %%r10, guest_regs+%c[off_r10](%%rip)\n\t"
		"xchg %%r11, guest_regs+%c[off_r11](%%rip)\n\t"
		"xchg %%r12, guest_regs+%c[off_r12](%%rip)\n\t"
		"xchg %%r13, guest_regs+%c[off_r13](%%rip)\n\t"
		"xchg %%r14, guest_regs+%c[off_r14](%%rip)\n\t"
		"xchg %%r15, guest_regs+%c[off_r15](%%rip)\n\t"
		"vmsave %[vmcb_gpa]\n\t"
		: [vmcb_gpa] "+a" (vmcb_gpa)
		:
		  [off_rbx] "i" (offsetof(struct gpr64_regs, rbx)),
		  [off_rcx] "i" (offsetof(struct gpr64_regs, rcx)),
		  [off_rdx] "i" (offsetof(struct gpr64_regs, rdx)),
		  [off_rbp] "i" (offsetof(struct gpr64_regs, rbp)),
		  [off_rsi] "i" (offsetof(struct gpr64_regs, rsi)),
		  [off_rdi] "i" (offsetof(struct gpr64_regs, rdi)),
		  [off_r8] "i" (offsetof(struct gpr64_regs, r8)),
		  [off_r9] "i" (offsetof(struct gpr64_regs, r9)),
		  [off_r10] "i" (offsetof(struct gpr64_regs, r10)),
		  [off_r11] "i" (offsetof(struct gpr64_regs, r11)),
		  [off_r12] "i" (offsetof(struct gpr64_regs, r12)),
		  [off_r13] "i" (offsetof(struct gpr64_regs, r13)),
		  [off_r14] "i" (offsetof(struct gpr64_regs, r14)),
		  [off_r15] "i" (offsetof(struct gpr64_regs, r15))
		: "memory");

	rflags = vmcb->save.rflags;
	guest_regs.rax = vmcb->save.rax;
}

bool nested_svm_supported(void)
{
	struct kvm_cpuid_entry2 *entry =
		kvm_get_supported_cpuid_entry(0x80000001);

	return entry->ecx & CPUID_SVM;
}

void nested_svm_check_supported(void)
{
	if (!nested_svm_supported()) {
		print_skip("nested SVM not enabled");
		exit(KSFT_SKIP);
	}
}
