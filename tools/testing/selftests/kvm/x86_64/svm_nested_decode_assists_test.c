// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test KVM's virtualization of SVM DecodeAssists for nested guests.
 */

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "svm_util.h"
#include <linux/compiler.h>

#include "../lib/kvm_util_internal.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef BIT
#define BIT(n) (1U << (n))
#endif
#ifndef BIT_ULL
#define BIT_ULL(n) (1ULL << (n))
#endif
#ifndef PF_VECTOR
#define PF_VECTOR 14
#endif
#ifndef PFERR_PRESENT_MASK
#define PFERR_PRESENT_MASK BIT(0)
#endif
#ifndef PFERR_FETCH_MASK
#define PFERR_FETCH_MASK BIT(4)
#endif

#define KVM_FEP ".byte 0x0f, 0x0b; .ascii \"kvm\"; "

#define SVM_EXIT_READ_CR4 0x004
#define SVM_EXIT_WRITE_CR0 0x010
#define SVM_EXIT_WRITE_DR7 0x037
#define SVM_EXIT_EXCP_BASE 0x040
#define SVM_EXIT_CR0_SEL_WRITE 0x065
#define SVM_EXIT_SWINT 0x075
#define SVM_EXIT_INVLPG 0x079
#define SVM_EXIT_INVLPGA 0x07a
#define SVM_EXIT_NPF 0x400

#define DA_PTE_PRESENT BIT_ULL(0)
#define DA_PTE_LARGE BIT_ULL(7)
#define DA_PHYSICAL_PAGE_MASK 0x000ffffffffff000ULL
#define DA_VCPU_ID 0

static bool is_forced_emulation_enabled;
static vm_paddr_t da_npt_root;
static u8 l2_stack[PAGE_SIZE] __aligned(PAGE_SIZE);

enum da_cpu_feature {
	DA_CPU_SVM,
	DA_CPU_NPT,
	DA_CPU_DECODEASSISTS,
};

static bool da_cpu_has(enum da_cpu_feature feature)
{
	u32 eax, ebx, ecx, edx;
	u32 leaf = feature == DA_CPU_SVM ? 0x80000001 : 0x8000000a;

	asm volatile("cpuid"
		     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		     : "0"(leaf), "2"(0));
	if (feature == DA_CPU_SVM)
		return ecx & BIT(2);
	return edx & BIT(feature == DA_CPU_NPT ? 0 : 7);
}

/* Avoid guest calls to host-selected libc implementations. */
static void *da_memcpy(void *dst, const void *src, size_t count)
{
	volatile u8 *d = dst;
	const volatile u8 *s = src;
	size_t i;

	for (i = 0; i < count; i++)
		d[i] = s[i];
	return dst;
}

static void *da_memset(void *dst, int value, size_t count)
{
	volatile u8 *d = dst;
	size_t i;

	for (i = 0; i < count; i++)
		d[i] = value;
	return dst;
}

static int da_memcmp(const void *a, const void *b, size_t count)
{
	const volatile u8 *p = a, *q = b;
	size_t i;

	for (i = 0; i < count; i++) {
		if (p[i] != q[i])
			return p[i] < q[i] ? -1 : 1;
	}
	return 0;
}

#define GUEST_ASSERT_EQ(a, b) do { \
	typeof(a) da_a = (a); \
	typeof(b) da_b = (b); \
	GUEST_ASSERT_2(da_a == da_b, (u64)da_a, (u64)da_b); \
} while (0)

#define GUEST_FAIL(message) do { \
	ucall(UCALL_ABORT, 2, message, (u64)__LINE__); \
	for (;;) \
		asm volatile("ud2"); \
} while (0)

/*
 * Both guest paging and NPT use four-level, 4K x86 page tables.
 * NPT entries additionally allow user accesses at every level.
 */
static u64 *da_get_pte(struct kvm_vm *vm, vm_paddr_t root,
		       u64 address, bool create)
{
	u64 *table;
	u64 *entry;
	vm_paddr_t page;
	int level;

	TEST_ASSERT(vm->mode == VM_MODE_PXXV48_4K,
		    "DecodeAssists test requires four-level 4K paging");
	for (level = 3; level > 0; level--) {
		table = addr_gpa2hva(vm, root);
		entry = &table[(address >> (12 + 9 * level)) & 511];
		if (!(*entry & DA_PTE_PRESENT)) {
			TEST_ASSERT(create, "Missing page-table level %d", level);
			page = vm_phy_page_alloc(vm, 0x2000, 0);
			memset(addr_gpa2hva(vm, page), 0, PAGE_SIZE);
			*entry = page | 7;
		}
		TEST_ASSERT(!(*entry & DA_PTE_LARGE),
			    "Unexpected large page at level %d", level);
		root = *entry & DA_PHYSICAL_PAGE_MASK;
	}
	table = addr_gpa2hva(vm, root);
	return &table[(address >> 12) & 511];
}

static void da_prepare_npt(struct kvm_vm *vm)
{
	struct userspace_mem_region *region = memslot2region(vm, 0);
	vm_paddr_t gpa, end;

	da_npt_root = vm_phy_page_alloc(vm, 0x2000, 0);
	memset(addr_gpa2hva(vm, da_npt_root), 0, PAGE_SIZE);
	end = region->region.guest_phys_addr + region->region.memory_size;
	for (gpa = region->region.guest_phys_addr; gpa < end;
	     gpa += PAGE_SIZE)
		*da_get_pte(vm, da_npt_root, gpa, true) = gpa | 7;

	sync_global_to_guest(vm, da_npt_root);
}

static void da_require(bool condition, const char *reason)
{
	if (!condition) {
		print_skip("%s", reason);
		exit(KSFT_SKIP);
	}
}

static void da_read_fep_parameter(void)
{
	FILE *file;
	char value;
	int rc;

	file = fopen("/sys/module/kvm/parameters/force_emulation_prefix", "r");
	TEST_ASSERT(file, "Cannot read kvm.force_emulation_prefix: %s",
		    strerror(errno));
	rc = fscanf(file, " %c", &value);
	fclose(file);
	TEST_ASSERT(rc == 1, "Cannot parse kvm.force_emulation_prefix");
	TEST_ASSERT(value == 'Y' || value == 'y' || value == '1' ||
		    value == 'N' || value == 'n' || value == '0',
		    "Unexpected force_emulation_prefix value: %c", value);
	is_forced_emulation_enabled =
		value == 'Y' || value == 'y' || value == '1';
	pr_info("DecodeAssists: forced-emulation cases %s\n",
		is_forced_emulation_enabled ? "enabled" : "disabled");
}

#define TEST_INT_VECTOR 0x81

/* Any canonical virtual address that is never mapped by the selftest VM. */
#define PF_TEST_GVA BIT_ULL(40)
#define PF_FETCH_TEST_GVA BIT_ULL(41)

#define OUTSB_OPCODE 0x6e
#define MOVSB_OPCODE 0xa4
#define NOP_OPCODE 0x90
#define BOUNDARY_OUTSB_CODE_SIZE 15
#define TEST_IOPM_SIZE (3 * PAGE_SIZE)

static u8 npf_target[PAGE_SIZE] __aligned(PAGE_SIZE);
static u8 mmio_source[PAGE_SIZE] __aligned(PAGE_SIZE);
static u8 boundary_outsb_code[2 * PAGE_SIZE] __aligned(PAGE_SIZE);

static void l2_read_code(void)
{
	asm volatile("mov (%0), %%rax" : : "r"(&npf_target) : "rax", "memory");
	GUEST_FAIL("L2 read did not cause a nested page fault");
}

static void l2_outsb_code(void)
{
	asm volatile("mov %0, %%rsi\n\t"
		     "mov $0x80, %%dx\n\t"
		     "outsb"
		     : : "r"(&npf_target) : "rsi", "rdx", "memory");
	GUEST_FAIL("L2 OUTSB did not cause a nested page fault");
}

extern u8 l2_movsb_insn[];

static void l2_movsb_code(void)
{
	asm volatile("mov %0, %%rsi\n\t"
		     "mov %1, %%rdi\n\t"
		     "l2_movsb_insn:\n\t"
		     "movsb"
		     : : "r"(&mmio_source), "r"(&npf_target)
		     : "rsi", "rdi", "memory");
	GUEST_FAIL("L2 MOVSB did not cause a nested page fault");
}

extern u8 l2_userspace_pf_insn[];

static void l2_userspace_pf_code(void)
{
	asm volatile("movzbl (%0), %%eax\n\t"
		     "l2_userspace_pf_insn:\n\t"
		     "nop"
		     : : "r"(&mmio_source) : "rax", "memory");
	GUEST_FAIL("Userspace-injected #PF was not intercepted by L1");
}

static void l2_pf_code(void)
{
	asm volatile("mov (%0), %%rax"
		     : : "r"(PF_TEST_GVA) : "rax", "memory");
	GUEST_FAIL("L2 access to an unmapped VA did not #PF");
}

static void l2_fep_pf_code(void)
{
	asm volatile(KVM_FEP "mov (%0), %%rax"
		     : : "r"(PF_TEST_GVA) : "rax", "memory");
	GUEST_FAIL("L2 forced-emulated access to an unmapped VA did not #PF");
}

static void l2_mov_from_cr4_code(bool fep)
{
	if (fep)
		asm volatile(KVM_FEP "mov %%cr4, %%r10" : : : "r10");
	else
		asm volatile("mov %%cr4, %%r10" : : : "r10");
	GUEST_FAIL("L2 MOV-from-CR4 was not intercepted");
}

static void l2_mov_to_cr0_code(bool fep)
{
	u64 cr0;

	asm volatile("mov %%cr0, %0" : "=r"(cr0));
	cr0 ^= X86_CR0_WP;
	if (fep)
		asm volatile(KVM_FEP "mov %0, %%cr0" : : "a"(cr0) : "memory");
	else
		asm volatile("mov %0, %%cr0" : : "a"(cr0) : "memory");
	GUEST_FAIL("L2 MOV-to-CR0 was not intercepted");
}

static void l2_mov_to_dr7_code(bool fep)
{
	u64 dr7;

	asm volatile("mov %%dr7, %0" : "=r"(dr7));
	if (fep)
		asm volatile(KVM_FEP "mov %0, %%dr7" : : "b"(dr7));
	else
		asm volatile("mov %0, %%dr7" : : "b"(dr7));
	GUEST_FAIL("L2 MOV-to-DR7 was not intercepted");
}

static void l2_clts_code(bool fep)
{
	if (fep)
		asm volatile(KVM_FEP "clts" : : : "memory");
	else
		asm volatile("clts" : : : "memory");
	GUEST_FAIL("L2 CLTS was not intercepted");
}

static void l2_int_code(bool fep)
{
	if (fep)
		asm volatile(KVM_FEP "int %0" : : "i"(TEST_INT_VECTOR));
	else
		asm volatile("int %0" : : "i"(TEST_INT_VECTOR));
	GUEST_FAIL("L2 INTn was not intercepted");
}

static void l2_invlpg_code(bool fep)
{
	if (fep)
		asm volatile(KVM_FEP "invlpg (%0)" : : "r"(&npf_target) : "memory");
	else
		asm volatile("invlpg (%0)" : : "r"(&npf_target) : "memory");
	GUEST_FAIL("L2 INVLPG was not intercepted");
}

static void l2_invlpga_code(bool fep)
{
	if (fep)
		asm volatile(KVM_FEP "invlpga"
			     : : "a"(&npf_target), "c"(0) : "memory");
	else
		asm volatile("invlpga" : : "a"(&npf_target), "c"(0) : "memory");
	GUEST_FAIL("L2 INVLPGA was not intercepted");
}

struct instruction_intercept_test {
	const char *name;
	void (*code)(bool fep);
	u64 intercept;
	u32 intercept_cr;
	u32 intercept_dr;
	u64 exit_code;
	u64 exit_info_1;
	u64 exit_info_1_mask;
	bool check_rax;
	u64 rax;
};

static const struct instruction_intercept_test instruction_intercept_tests[] = {
	{
		.name = "MOV-from-CR4",
		.code = l2_mov_from_cr4_code,
		.intercept_cr = BIT(INTERCEPT_CR4_READ),
		.exit_code = SVM_EXIT_READ_CR4,
		.exit_info_1 = BIT_ULL(63) | 10,
		.exit_info_1_mask = ~0ULL,
	}, {
		.name = "MOV-to-CR0-selective",
		.code = l2_mov_to_cr0_code,
		.intercept = BIT_ULL(INTERCEPT_SELECTIVE_CR0),
		.exit_code = SVM_EXIT_CR0_SEL_WRITE,
		.exit_info_1 = BIT_ULL(63),
		.exit_info_1_mask = ~0ULL,
	}, {
		.name = "MOV-to-DR7",
		.code = l2_mov_to_dr7_code,
		.intercept_dr = BIT(INTERCEPT_DR7_WRITE),
		.exit_code = SVM_EXIT_WRITE_DR7,
		.exit_info_1 = 3,
		.exit_info_1_mask = ~0ULL,
	}, {
		.name = "CLTS",
		.code = l2_clts_code,
		.intercept_cr = BIT(INTERCEPT_CR0_WRITE),
		.exit_code = SVM_EXIT_WRITE_CR0,
		.exit_info_1_mask = BIT_ULL(63),
	}, {
		.name = "INTn",
		.code = l2_int_code,
		.intercept = BIT_ULL(INTERCEPT_INTn),
		.exit_code = SVM_EXIT_SWINT,
		.exit_info_1 = TEST_INT_VECTOR,
		.exit_info_1_mask = ~0ULL,
	}, {
		.name = "INVLPG",
		.code = l2_invlpg_code,
		.intercept = BIT_ULL(INTERCEPT_INVLPG),
		.exit_code = SVM_EXIT_INVLPG,
		.exit_info_1 = (u64)&npf_target,
		.exit_info_1_mask = ~0ULL,
	}, {
		.name = "INVLPGA",
		.code = l2_invlpga_code,
		.intercept = BIT_ULL(INTERCEPT_INVLPGA),
		.exit_code = SVM_EXIT_INVLPGA,
		.exit_info_1_mask = ~0ULL,
		.check_rax = true,
		.rax = (u64)&npf_target,
	},
};

static void assert_decode_assist_insn_bytes(struct vmcb *vmcb)
{
	GUEST_ASSERT(vmcb->control.insn_len);
	GUEST_ASSERT(vmcb->control.insn_len <=
		     sizeof(vmcb->control.insn_bytes));
	GUEST_ASSERT(!da_memcmp(vmcb->control.insn_bytes,
				(void *)vmcb->save.rip,
				vmcb->control.insn_len));
}

static void assert_full_decode_assist_insn_bytes(struct vmcb *vmcb)
{
	GUEST_ASSERT_EQ(vmcb->control.insn_len,
			sizeof(vmcb->control.insn_bytes));
	assert_decode_assist_insn_bytes(vmcb);
}

static void prepare_l2_for_vmrun(struct svm_test_data *svm, vm_vaddr_t rip)
{
	struct vmcb *vmcb = svm->vmcb;

	vmcb->save.rip = rip;
	vmcb->save.rsp = (u64)&l2_stack[sizeof(l2_stack)];
	guest_regs.rax = 0;
	rflags = X86_EFLAGS_FIXED;
}

static void run_intercept_test(struct svm_test_data *svm,
			       const struct instruction_intercept_test *test,
			       bool fep)
{
	struct vmcb *vmcb = svm->vmcb;
	struct vmcb_control_area *control = &vmcb->control;
	u64 expected = test->exit_info_1 & test->exit_info_1_mask;
	u64 index = test - instruction_intercept_tests;

	control->intercept |= test->intercept;
	control->intercept_cr |= test->intercept_cr;
	control->intercept_dr |= test->intercept_dr;
	control->exit_info_1 = ~0ULL;
	control->insn_len = sizeof(control->insn_bytes);
	da_memset(control->insn_bytes, 0xa5, sizeof(control->insn_bytes));
	prepare_l2_for_vmrun(svm, (u64)test->code);
	guest_regs.rdi = fep;

	run_guest(vmcb, svm->vmcb_gpa);

	/* Arguments: test index, FEP mode, expected value, actual value. */
	GUEST_ASSERT_4(control->exit_code == test->exit_code,
		       index, (u64)fep, (u64)test->exit_code,
		       (u64)control->exit_code);
	GUEST_ASSERT_4((control->exit_info_1 & test->exit_info_1_mask) ==
		       expected, index, (u64)fep, expected,
		       (u64)(control->exit_info_1 & test->exit_info_1_mask));
	GUEST_ASSERT_4(!control->insn_len,
		       index, (u64)fep, 0ULL, (u64)control->insn_len);
	if (test->check_rax)
		GUEST_ASSERT_4(vmcb->save.rax == test->rax,
			       index, (u64)fep,
			       (u64)test->rax, (u64)vmcb->save.rax);

	control->intercept &= ~test->intercept;
	control->intercept_cr &= ~test->intercept_cr;
	control->intercept_dr &= ~test->intercept_dr;
}

static void test_instruction_intercepts(struct svm_test_data *svm)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(instruction_intercept_tests); i++) {
		run_intercept_test(svm, &instruction_intercept_tests[i], false);
		if (is_forced_emulation_enabled)
			run_intercept_test(svm, &instruction_intercept_tests[i], true);
	}
}

static void test_hardware_npf(struct svm_test_data *svm, vm_paddr_t npf_gpa)
{
	struct vmcb *vmcb = svm->vmcb;

	prepare_l2_for_vmrun(svm, (u64)l2_read_code);
	run_guest(vmcb, svm->vmcb_gpa);
	GUEST_ASSERT_EQ(vmcb->control.exit_code, SVM_EXIT_NPF);
	GUEST_ASSERT_EQ(vmcb->control.exit_info_2, npf_gpa);
	assert_decode_assist_insn_bytes(vmcb);
}

/*
 * The IOIO intercept causes L0 to emulate OUTSB before accessing its source
 * operand.  The emulated read then faults on L1's NPT, resulting in a
 * KVM-synthesized #NPF.
 */
static void test_synthesized_npf(struct svm_test_data *svm, vm_paddr_t npf_gpa)
{
	struct vmcb *vmcb = svm->vmcb;

	prepare_l2_for_vmrun(svm, (u64)l2_outsb_code);
	run_guest(vmcb, svm->vmcb_gpa);
	GUEST_ASSERT_EQ(vmcb->control.exit_code, SVM_EXIT_NPF);
	GUEST_ASSERT_EQ(vmcb->control.exit_info_2, npf_gpa);
	assert_full_decode_assist_insn_bytes(vmcb);
}

/*
 * MOVSB first reads from MMIO, causing a hardware #NPF that L0 emulates.
 * After userspace completes the read, the emulated destination write faults
 * on L1's NPT.  The new #NPF must not reuse the original hardware exit's GPA.
 * Userspace replaces MOVSB with NOP while the read is pending.  DecodeAssist
 * must retain the cached MOVSB bytes instead of re-reading the opcode.
 */
static void test_synthesized_npf_after_hardware_npf(struct svm_test_data *svm,
						    vm_paddr_t npf_gpa)
{
	struct vmcb *vmcb = svm->vmcb;
	u8 insn_bytes[sizeof(vmcb->control.insn_bytes)];

	da_memcpy(insn_bytes, l2_movsb_insn, sizeof(insn_bytes));
	GUEST_ASSERT_EQ(insn_bytes[0], MOVSB_OPCODE);
	prepare_l2_for_vmrun(svm, (u64)l2_movsb_code);
	run_guest(vmcb, svm->vmcb_gpa);
	GUEST_ASSERT_EQ(vmcb->control.exit_code, SVM_EXIT_NPF);
	GUEST_ASSERT_EQ(vmcb->control.exit_info_2, npf_gpa);
	GUEST_ASSERT_EQ(vmcb->save.rip, (u64)l2_movsb_insn);
	GUEST_ASSERT_EQ(l2_movsb_insn[0], NOP_OPCODE);
	GUEST_ASSERT_EQ(vmcb->control.insn_len, sizeof(insn_bytes));
	GUEST_ASSERT(!da_memcmp(vmcb->control.insn_bytes, insn_bytes,
				sizeof(insn_bytes)));
}

/*
 * OUTSB is the final byte of a mapped code page, and the following page is
 * not present in L2's page tables.  DecodeAssist byte fetching must stop at
 * the page boundary and report only the OUTSB opcode.
 */
static void test_synthesized_npf_truncated(struct svm_test_data *svm,
					   vm_paddr_t npf_gpa)
{
	struct vmcb *vmcb = svm->vmcb;

	prepare_l2_for_vmrun(svm,
			     (u64)&boundary_outsb_code[PAGE_SIZE -
						       BOUNDARY_OUTSB_CODE_SIZE]);
	run_guest(vmcb, svm->vmcb_gpa);
	GUEST_ASSERT_EQ(vmcb->control.exit_code, SVM_EXIT_NPF);
	GUEST_ASSERT_EQ(vmcb->control.exit_info_2, npf_gpa);
	GUEST_ASSERT_EQ(vmcb->save.rip,
			(u64)&boundary_outsb_code[PAGE_SIZE - 1]);
	GUEST_ASSERT_EQ(vmcb->control.insn_len, 1);
	GUEST_ASSERT_EQ(vmcb->control.insn_bytes[0], OUTSB_OPCODE);
}

static void test_hardware_intercepted_pf(struct svm_test_data *svm)
{
	struct vmcb *vmcb = svm->vmcb;

	prepare_l2_for_vmrun(svm, (u64)l2_pf_code);
	run_guest(vmcb, svm->vmcb_gpa);
	GUEST_ASSERT_EQ(vmcb->control.exit_code, SVM_EXIT_EXCP_BASE + PF_VECTOR);
	GUEST_ASSERT_EQ(vmcb->control.exit_info_2, PF_TEST_GVA);
	GUEST_ASSERT(!(vmcb->control.exit_info_1 & PFERR_PRESENT_MASK));
	GUEST_ASSERT(!(vmcb->control.exit_info_1 & PFERR_FETCH_MASK));
	assert_decode_assist_insn_bytes(vmcb);
}

static void test_hardware_intercepted_fetch_pf(struct svm_test_data *svm)
{
	struct vmcb *vmcb = svm->vmcb;

	prepare_l2_for_vmrun(svm, PF_FETCH_TEST_GVA);
	run_guest(vmcb, svm->vmcb_gpa);
	GUEST_ASSERT_EQ(vmcb->control.exit_code, SVM_EXIT_EXCP_BASE + PF_VECTOR);
	GUEST_ASSERT_EQ(vmcb->control.exit_info_2, PF_FETCH_TEST_GVA);
	GUEST_ASSERT(!(vmcb->control.exit_info_1 & PFERR_PRESENT_MASK));
	GUEST_ASSERT(vmcb->control.exit_info_1 & PFERR_FETCH_MASK);
	GUEST_ASSERT_EQ(vmcb->control.insn_len, 0);
}

static void test_synthesized_pf(struct svm_test_data *svm)
{
	struct vmcb *vmcb = svm->vmcb;

	if (!is_forced_emulation_enabled)
		return;

	prepare_l2_for_vmrun(svm, (u64)l2_fep_pf_code);
	run_guest(vmcb, svm->vmcb_gpa);
	GUEST_ASSERT_EQ(vmcb->control.exit_code, SVM_EXIT_EXCP_BASE + PF_VECTOR);
	GUEST_ASSERT_EQ(vmcb->control.exit_info_2, PF_TEST_GVA);
	GUEST_ASSERT(!(vmcb->control.exit_info_1 & PFERR_PRESENT_MASK));
	GUEST_ASSERT(!(vmcb->control.exit_info_1 & PFERR_FETCH_MASK));
	assert_full_decode_assist_insn_bytes(vmcb);
}

/* The pending MMIO instruction must complete before reflecting userspace #PF. */
static void test_userspace_injected_pf_during_emulation(struct svm_test_data *svm)
{
	struct vmcb *vmcb = svm->vmcb;

	prepare_l2_for_vmrun(svm, (u64)l2_userspace_pf_code);
	run_guest(vmcb, svm->vmcb_gpa);
	GUEST_ASSERT_EQ(vmcb->control.exit_code, SVM_EXIT_EXCP_BASE + PF_VECTOR);
	GUEST_ASSERT_EQ(vmcb->control.exit_info_1, 0);
	GUEST_ASSERT_EQ(vmcb->control.exit_info_2, PF_TEST_GVA);
	GUEST_ASSERT_EQ(vmcb->save.rip, (u64)l2_userspace_pf_insn);
	GUEST_ASSERT_EQ(vmcb->save.rax, 0x5a);
	assert_full_decode_assist_insn_bytes(vmcb);
	GUEST_ASSERT_EQ(vmcb->control.insn_bytes[0], NOP_OPCODE);
}

static void l1_guest_code(struct svm_test_data *svm, vm_paddr_t npf_gpa,
			  vm_paddr_t iopm_gpa)
{
	struct vmcb *vmcb = svm->vmcb;

	GUEST_ASSERT(da_cpu_has(DA_CPU_DECODEASSISTS));

	generic_svm_setup(svm, l2_read_code,
			  &l2_stack[sizeof(l2_stack)]);
	vmcb->control.nested_ctl |= SVM_NESTED_CTL_NP_ENABLE;
	vmcb->control.nested_cr3 = da_npt_root;
	vmcb->control.iopm_base_pa = iopm_gpa;

	vmcb->control.intercept |= BIT_ULL(INTERCEPT_IOIO_PROT);
	vmcb->control.intercept_exceptions |= 1U << PF_VECTOR;

	test_hardware_npf(svm, npf_gpa);
	test_synthesized_npf(svm, npf_gpa);
	test_synthesized_npf_after_hardware_npf(svm, npf_gpa);
	test_synthesized_npf_truncated(svm, npf_gpa);
	test_hardware_intercepted_pf(svm);
	test_hardware_intercepted_fetch_pf(svm);
	test_synthesized_pf(svm);
	test_userspace_injected_pf_during_emulation(svm);
	test_instruction_intercepts(svm);

	GUEST_DONE();
}

static void build_boundary_outsb_code(u8 *code)
{
	u64 source = (u64)&npf_target;

	/* movabs $npf_target, %rsi */
	code[0] = 0x48;
	code[1] = 0xbe;
	da_memcpy(&code[2], &source, sizeof(source));

	/* mov $0x80, %dx; outsb */
	code[10] = 0x66;
	code[11] = 0xba;
	code[12] = 0x80;
	code[13] = 0x00;
	code[14] = OUTSB_OPCODE;
}

static void prepare_boundary_outsb_code(struct kvm_vm *vm)
{
	vm_vaddr_t code_gva = (vm_vaddr_t)&boundary_outsb_code[PAGE_SIZE -
						      BOUNDARY_OUTSB_CODE_SIZE];

	build_boundary_outsb_code(addr_gva2hva(vm, code_gva));
}

static void da_report_guest_abort(struct kvm_vm *vm,
				  const struct ucall *uc)
{
	const char *message = addr_gva2hva(vm, uc->args[0]);

	TEST_FAIL("Guest assertion at line %lu: %s\n"
		  "Arguments: %#lx %#lx %#lx %#lx",
		  (unsigned long)uc->args[1], message,
		  (unsigned long)uc->args[2], (unsigned long)uc->args[3],
		  (unsigned long)uc->args[4], (unsigned long)uc->args[5]);
}

static void queue_userspace_pf(struct kvm_vm *vm)
{
	struct kvm_vcpu_events events;

	vcpu_events_get(vm, DA_VCPU_ID, &events);
	TEST_ASSERT(!events.exception.pending && !events.exception.injected,
		    "Unexpected exception before userspace #PF injection");
	TEST_ASSERT(events.flags & KVM_VCPUEVENT_VALID_PAYLOAD,
		    "KVM_CAP_EXCEPTION_PAYLOAD was not enabled");
	events.exception.pending = true;
	events.exception.nr = PF_VECTOR;
	events.exception.has_error_code = true;
	events.exception.error_code = 0;
	events.exception_has_payload = true;
	events.exception_payload = PF_TEST_GVA;
	vcpu_events_set(vm, DA_VCPU_ID, &events);
}

static void complete_mmio_read(struct kvm_vm *vm,
			       vm_paddr_t expected_gpa, u8 value)
{
	struct kvm_run *run = vcpu_state(vm, DA_VCPU_ID);
	struct ucall uc;

	if (run->exit_reason == KVM_EXIT_IO &&
	    get_ucall(vm, DA_VCPU_ID, &uc) == UCALL_ABORT)
		da_report_guest_abort(vm, &uc);

	TEST_ASSERT(run->exit_reason == KVM_EXIT_MMIO,
		    "Expected MMIO, got %u (%s)", run->exit_reason,
		    exit_reason_str(run->exit_reason));
	TEST_ASSERT(!run->mmio.is_write, "Expected an MMIO read");
	ASSERT_EQ(run->mmio.phys_addr, expected_gpa);
	ASSERT_EQ(run->mmio.len, 1);
	run->mmio.data[0] = value;
}

static void assert_ucall_done(struct kvm_vm *vm)
{
	struct kvm_run *run = vcpu_state(vm, DA_VCPU_ID);
	struct ucall uc;
	u64 actual;

	TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
		    "Expected IO, got %u (%s)", run->exit_reason,
		    exit_reason_str(run->exit_reason));
	actual = get_ucall(vm, DA_VCPU_ID, &uc);
	if (actual == UCALL_ABORT)
		da_report_guest_abort(vm, &uc);
	ASSERT_EQ(actual, UCALL_DONE);
}

int main(int argc, char *argv[])
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_EXCEPTION_PAYLOAD,
		.args[0] = 1,
	};
	struct kvm_cpuid_entry2 *svm_cpuid;
	struct userspace_mem_region *region;
	struct kvm_vm *vm;
	vm_vaddr_t svm_gva, boundary_page_gva;
	vm_paddr_t npf_gpa, mmio_source_gpa, mmio_gpa, iopm_gpa;
	u8 *movsb_insn;
	u64 *pte;

	nested_svm_check_supported();
	svm_cpuid = kvm_get_supported_cpuid_entry(0x8000000a);
	da_require(svm_cpuid->edx & BIT(0), "KVM does not expose NPT");
	da_require(da_cpu_has(DA_CPU_DECODEASSISTS),
		   "Hardware does not support DecodeAssists");
	TEST_ASSERT(svm_cpuid->edx & BIT(7),
		    "KVM failed to expose DecodeAssists");
	da_require(kvm_check_cap(KVM_CAP_EXCEPTION_PAYLOAD),
		   "KVM_CAP_EXCEPTION_PAYLOAD is unavailable");

	vm = vm_create_default(DA_VCPU_ID, 0, (void *)l1_guest_code);
	vcpu_set_cpuid(vm, DA_VCPU_ID, kvm_get_supported_cpuid());
	TEST_ASSERT(vm_enable_cap(vm, &cap) == 0,
		    "Cannot enable KVM_CAP_EXCEPTION_PAYLOAD");

	da_read_fep_parameter();
	sync_global_to_guest(vm, is_forced_emulation_enabled);
	prepare_boundary_outsb_code(vm);
	vcpu_alloc_svm(vm, &svm_gva);

	/* The hardware IOPM requires three contiguous physical pages. */
	iopm_gpa = vm_phy_pages_alloc(vm, TEST_IOPM_SIZE / PAGE_SIZE,
				      0x2000, 0);
	memset(addr_gpa2hva(vm, iopm_gpa), 0, TEST_IOPM_SIZE);
	npf_gpa = addr_gva2gpa(vm, (vm_vaddr_t)&npf_target);

	da_prepare_npt(vm);
	pte = da_get_pte(vm, da_npt_root, npf_gpa, false);
	*pte &= ~DA_PTE_PRESENT;

	region = memslot2region(vm, 0);
	mmio_gpa = region->region.guest_phys_addr +
		   region->region.memory_size + PAGE_SIZE;
	TEST_ASSERT((mmio_gpa >> vm->page_shift) <= vm->max_gfn,
		    "MMIO GPA exceeds the supported physical address width");
	mmio_source_gpa = addr_gva2gpa(vm, (vm_vaddr_t)&mmio_source);
	pte = da_get_pte(vm, da_npt_root, mmio_source_gpa, false);
	*pte = (*pte & ~DA_PHYSICAL_PAGE_MASK) | mmio_gpa;

	boundary_page_gva = (vm_vaddr_t)&boundary_outsb_code[PAGE_SIZE];
	pte = da_get_pte(vm, vm->pgd, boundary_page_gva, false);
	*pte &= ~DA_PTE_PRESENT;
	vcpu_args_set(vm, DA_VCPU_ID, 3, svm_gva, npf_gpa, iopm_gpa);

	vcpu_run(vm, DA_VCPU_ID);
	complete_mmio_read(vm, mmio_gpa, 0xa5);
	movsb_insn = addr_gva2hva(vm, (vm_vaddr_t)l2_movsb_insn);
	ASSERT_EQ(movsb_insn[0], MOVSB_OPCODE);
	movsb_insn[0] = NOP_OPCODE;

	vcpu_run(vm, DA_VCPU_ID);
	complete_mmio_read(vm, mmio_gpa, 0x5a);
	queue_userspace_pf(vm);
	vcpu_run(vm, DA_VCPU_ID);
	assert_ucall_done(vm);

	kvm_vm_free(vm);
	return 0;
}
