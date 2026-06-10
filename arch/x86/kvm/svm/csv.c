// SPDX-License-Identifier: GPL-2.0-only
/*
 * CSV driver for KVM
 *
 * HYGON CSV support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#include <linux/kvm_host.h>
#include <linux/psp-sev.h>
#include <linux/psp-csv.h>
#include <linux/memory.h>
#include <linux/kvm_types.h>
#include <linux/vmalloc.h>
#include <linux/rbtree.h>
#include <linux/swap.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <asm/cacheflush.h>
#include <asm/e820/api.h>
#include <asm/csv.h>
#include "kvm_cache_regs.h"
#include "svm.h"
#include "csv.h"
#include "x86.h"

#include "trace.h"

#undef  pr_fmt
#define pr_fmt(fmt) "CSV: " fmt

/* Function and variable pointers for hooks */
struct hygon_kvm_hooks_table hygon_kvm_hooks;

struct encrypt_data_block {
	struct {
		u64 npages:	12;
		u64 pfn:	52;
	} entry[512];
};

union csv_page_attr {
	struct {
		u64 reserved:	1;
		u64 rw:		1;
		u64 reserved1:	49;
		u64 mmio:	1;
		u64 reserved2:	12;
	};
	u64 val;
};

struct guest_paddr_block {
	struct {
		u64 share:	1;
		u64 reserved:	11;
		u64 gfn:	52;
	} entry[512];
};

struct trans_paddr_block {
	u64	trans_paddr[512];
};

struct vmcb_paddr_block {
	u64	vmcb_paddr[512];
};

enum csv_pg_level {
	CSV_PG_LEVEL_NONE,
	CSV_PG_LEVEL_4K,
	CSV_PG_LEVEL_2M,
	CSV_PG_LEVEL_NUM
};

/*
 * Manage shared page in rbtree, the node within the rbtree
 * is indexed by track_hva. @track_page points to the page mapped by @track_hva
 * in NPT.
 */
struct shared_page {
	struct rb_node node;
	/* The hva corresponds to @track_page. */
	u64 track_hva;
	/* Page order of @track_page. */
	unsigned int order;
	/*
	 * This field is NULL when @order equals 0, but must point to a
	 * valid bitmap when @order > 0 (i.e., for huge pages and THP).
	 */
	unsigned long *bitmap;
	/*
	 * Pointer to the head page of the page block.
	 * Always points to the head page, whether @order is 0 (a single 4K
	 * page) or greater (a huge page or THP).
	 */
	struct page *track_page;
};

struct shared_page_mgr {
	/* The root of the manager tree */
	struct rb_root root;
	/* The count of shared_page entries in the manager tree */
	u64 count;
	/* The total pages tracked by the manager */
	unsigned long nr_pages;
};

struct kvm_csv_info {
	struct kvm_sev_info *sev;

	bool csv_active;	/* CSV enabled guest */

	struct kmem_cache *sp_slab;	/* shared page slab */
	struct shared_page_mgr sp_mgr;	/* shared page manager */
	struct mutex sp_lock;		/* shared page lock */

	struct list_head smr_list; /* List of guest secure memory regions */
	struct list_head hugetlb_list; /* List of 1G hugetlb (if used) */
	unsigned long nodemask; /* Nodemask where CSV guest's memory resides */

	/* The following 6 fields record the extension status for current VM */
	bool fw_ext_valid;	/* if @fw_ext field is valid */
	u32 fw_ext;		/* extensions supported by current platform */
	bool kvm_ext_valid;	/* if @kvm_ext field is valid */
	u32 kvm_ext;		/* extensions supported by KVM */
	u32 inuse_ext;		/* extensions inused by current VM */
	u64 secure_call_exit_enabled;	/* valid secure call exit mask */

	/* The following 2 fields are used when CSV3_NPT_EX cap is in use. */
	u64 tom;
	u64 tom2;

#ifdef CONFIG_SYSFS
	unsigned long npt_size;
	unsigned long pri_mem;
#endif	/* CONFIG_SYSFS */
};

struct kvm_svm_csv {
	struct kvm_svm kvm_svm;
	struct kvm_csv_info csv_info;
};

enum csv_mem_type {
	CSV_METADATA,
	CSV_SEC_MEM,
};

struct secure_memory_region {
	struct list_head list;
	u64 npages;
	u64 hpa;
	enum csv_mem_type type;
};

struct csv3_hugetlb {
	struct list_head list;
	struct page *page;
};

static struct kvm_x86_ops csv_x86_ops;

#ifdef CONFIG_SYSFS
static void update_csv_share_mem(struct page *page, bool add)
{
	int nid;

	/* Exclude shared memory backed by 1 GB huge pages from accounting. */
	if (get_csv_smr_source() == USE_HUGETLB && page_size(page) == PUD_SIZE)
		return;

	nid = page_to_nid(page);
	if (add)
		atomic_long_add(page_size(page), &csv3_shared_mem[nid]);
	else
		atomic_long_sub(page_size(page), &csv3_shared_mem[nid]);
}
#else
static void update_csv_share_mem(struct page *page, bool add) { };
#endif	/* CONFIG_SYSFS */

/**
 * insert_shared_page_entry_locked - Insert a shared_page into the manager tree
 * @mgr:    Pointer to the shared page manager (must be valid).
 * @new_sp: The shared_page to insert.
 * @old_sp: Pointer to store conflicting entry if insertion fails (can be NULL).
 *
 * Attempts to insert @new_sp into the rbtree of @mgr. If an entry with the
 * same key (e.g., track_hva) already exists, the insertion is aborted and
 * the existing entry is returned via @old_sp.
 *
 * The caller must hold the appropriate lock protecting @mgr.
 *
 * Return:
 * %true if @new_sp was successfully inserted;
 * %false if a duplicate exists (in which case @old_sp is set if non-NULL).
 */
static bool insert_shared_page_entry_locked(struct shared_page_mgr *mgr,
					    struct shared_page *new_sp,
					    struct shared_page **old_sp)
{
	struct shared_page *sp_iter;
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *parent = NULL;

	root = &mgr->root;
	new = &(root->rb_node);

	/* Figure out where to put new node */
	while (*new) {
		sp_iter = rb_entry(*new, struct shared_page, node);
		parent = *new;

		if (new_sp->track_hva < sp_iter->track_hva) {
			new = &((*new)->rb_left);
		} else if (new_sp->track_hva > sp_iter->track_hva) {
			new = &((*new)->rb_right);
		} else {
			trace_kvm_csv3_sp_insert_dup(page_to_pfn(new_sp->track_page),
						     new_sp->track_hva,
						     new_sp->order,
						     page_to_pfn(sp_iter->track_page),
						     sp_iter->track_hva,
						     sp_iter->order);

			/*
			 * If found the same @track_page during insertion, the
			 * @track_page must be pinned more than once.
			 */
			if (new_sp->track_page == sp_iter->track_page &&
			    ((hpage_pincount_available(sp_iter->track_page) &&
			      compound_pincount(sp_iter->track_page) < 2) ||
			     (!hpage_pincount_available(sp_iter->track_page) &&
			      ((unsigned int)page_ref_count(sp_iter->track_page)
				< GUP_PIN_COUNTING_BIAS * 2))))
				pr_err_ratelimited("%s: SP_MGR_ERR: pfn:0x%lx"
						   " order:%d pincount < 2\n",
						   __func__,
						   page_to_pfn(sp_iter->track_page),
						   sp_iter->order);

			if (old_sp)
				*old_sp = sp_iter;
			return false;
		}
	}

	trace_kvm_csv3_sp_insert(page_to_pfn(new_sp->track_page),
				 new_sp->track_hva,
				 new_sp->order);

	/* Add new node and rebalance tree. */
	rb_link_node(&new_sp->node, parent, new);
	rb_insert_color(&new_sp->node, root);

	/* Update shared page statistics */
	mgr->count++;
	mgr->nr_pages += 1UL << new_sp->order;
	update_csv_share_mem(new_sp->track_page, true);

	return true;
}

/**
 * search_shared_page_entry_locked - Search for a shared page covering @hva
 * @mgr: Pointer to the shared page manager.
 * @hva: Host virtual address to search for.
 *
 * Searches the rbtree of @mgr for a shared page that maps @hva. The search
 * iterates through supported page orders (e.g., 4K, 2M, 1G) in ascending order
 * (starting from order 0).
 *
 * The caller must hold the lock protecting @mgr.
 *
 * Return: Pointer to matching shared_page, or NULL if not found.
 */
static
struct shared_page *search_shared_page_entry_locked(struct shared_page_mgr *mgr,
						    u64 hva)
{
	struct shared_page *sp;
	struct rb_root *root;
	struct rb_node *node;
	u64 track_hva;
	unsigned int order = 0;

again:
	track_hva = (hva & ~((1ULL << (order + PAGE_SHIFT)) - 1));

	root = &mgr->root;
	node = root->rb_node;
	while (node) {
		sp = rb_entry(node, struct shared_page, node);
		if (track_hva < sp->track_hva)
			node = node->rb_left;
		else if (track_hva > sp->track_hva)
			node = node->rb_right;
		else
			return (track_hva == hva || sp->order == order)
				? sp : NULL;
	}

	if (order == 0) {
		order = PMD_SHIFT - PAGE_SHIFT;
		goto again;
	} else if (order == (PMD_SHIFT - PAGE_SHIFT)) {
		order = PUD_SHIFT - PAGE_SHIFT;
		goto again;
	}

	return NULL;
}

/**
 * shared_page_entry_set_bit_locked - Set bitmap in a shared page entry if found
 * @mgr: Pointer to the shared page manager (caller must hold its lock).
 * @hva: Host virtual address identifying the 4K subpage of a compound page.
 * @sp:  Optional hint pointer to the shared_page entry; if NULL, the entry is
 *       looked up in @mgr's rbtree using @hva.
 *
 * If @sp is NULL, the function searches for the entry in the manager's tree.
 *
 * For compound pages (@order > 0), a bitmap tracks which 4K subpages are
 * shared memory for CSV3 VM. The bit corresponding to the offset of @hva within
 * the compound page is set atomically.
 *
 * On every successful found (including repeated hits), a trace event
 * kvm_csv3_sp_hit is emitted with the PFN, order.
 *
 * Return:
 * Pointer to the shared_page entry if found, or NULL if no entry covers @hva.
 */
static
struct shared_page *shared_page_entry_set_bit_locked(struct shared_page_mgr *mgr,
						     u64 hva,
						     struct shared_page *sp)
{
	/* If @sp is NULL, we need search entry from the manager tree. */
	if (!sp)
		sp = search_shared_page_entry_locked(mgr, hva);

	if (sp) {
		if (sp->order) {
			unsigned int pg_off = (hva & ~sp->track_hva) >> PAGE_SHIFT;

			set_bit(pg_off, sp->bitmap);
		}

		trace_kvm_csv3_sp_hit(page_to_pfn(sp->track_page),
				      sp->track_hva, hva, sp->order);
	}

	return sp;
}

/**
 * remove_shared_page_entry_locked - Remove a shared_page entry if any subpages
 *                                   are not shared memory of CSV3 VM.
 * @mgr: Pointer to the shared page manager (lock must be held by caller).
 * @hva: Host virtual address identifying the subpage.
 *
 * This function attempts to remove a shared_page entry from the manager when it
 * does not contain CSV3 VM's shared memory. The entry is only removed if:
 *   - All 4K subpages within the compound page are not VM's shared memory
 *   - The underlying physical page is not pinned by any other user
 *
 * If the page is found to be pinned more than once, the removal is aborted
 * the page is used by multiple users.
 *
 * Context: Caller must hold the lock protecting @mgr.
 *
 * Return:
 *   Pointer to the removed shared_page entry on success, or NULL if not found,
 *   some bits set in @bitmap, or page is pinned more than once.
 */
static
struct shared_page *remove_shared_page_entry_locked(struct shared_page_mgr *mgr,
						    u64 hva)
{
	struct shared_page *sp;

	sp = search_shared_page_entry_locked(mgr, hva);
	if (sp) {
		/*
		 * The bitmap records the 4K subpages within the compound page
		 * that are shared memory of VM. Clear the bit for this @hva.
		 */
		if (sp->order) {
			unsigned int pg_off = (hva & ~sp->track_hva) >> PAGE_SHIFT;

			clear_bit(pg_off, sp->bitmap);
			if (!bitmap_empty(sp->bitmap, 1U << sp->order))
				return NULL;
		}

		/*
		 * The @sp->track_page may be pinned more than once in some
		 * scenarios, such as device passthrough. We don't remove this
		 * entry from the tree.
		 */
		if ((hpage_pincount_available(sp->track_page) &&
		     compound_pincount(sp->track_page) >= 2) ||
		    (!hpage_pincount_available(sp->track_page) &&
		     ((unsigned int)page_ref_count(sp->track_page) >= GUP_PIN_COUNTING_BIAS * 2))) {
			return NULL;
		}

		trace_kvm_csv3_sp_remove(page_to_pfn(sp->track_page),
					 sp->track_hva, sp->order);

		rb_erase(&sp->node, &mgr->root);
		mgr->count--;
		mgr->nr_pages -= 1UL << sp->order;
		update_csv_share_mem(sp->track_page, false);
	}

	return sp;
}

/**
 * alloc_shared_page_entry - Allocate and initialize a shared_page entry for a
 *                           given page
 * @csv:  Pointer to the KVM CSV info structure containing the slab cache.
 * @hva:  Host virtual address associated with the page (used for alignment and
 *        tracking).
 * @page: The physical page being tracked (may be a base or compound/huge page).
 *
 * Allocates a new struct shared_page from the slab cache in @csv, initializes
 * it to represent the memory region covered by @page at virtual address @hva.
 * If @page is a compound page (order > 0), a bitmap is allocated to track
 * touched 4K subpages, and the bit corresponding to the 4K offset of @hva
 * within the compound page is set. For order-0 pages, no bitmap is allocated.
 * The @track_hva field is aligned to the start of the page block (i.e.,
 * compound page boundary if applicable).
 *
 * Return:
 * Pointer to the newly allocated and initialized shared_page on success,
 * or NULL on allocation failure (either slab or bitmap).
 */
struct shared_page *alloc_shared_page_entry(struct kvm_csv_info *csv,
					    u64 hva,
					    struct page *page)
{
	struct shared_page *sp;
	unsigned int order;
	unsigned int pg_off;

	sp = kmem_cache_zalloc(csv->sp_slab, GFP_KERNEL);
	if (!sp)
		return NULL;

	order = compound_order(compound_head(page));
	if (order) {
		unsigned long *bitmap = kvzalloc(BITS_TO_LONGS(1U << order)
							* sizeof(unsigned long),
						 GFP_KERNEL);
		if (!bitmap) {
			kmem_cache_free(csv->sp_slab, sp);
			return NULL;
		}
		sp->bitmap = bitmap;
		pg_off = (hva >> PAGE_SHIFT) & ((1U << order) - 1);
		set_bit(pg_off, sp->bitmap);
	}

	sp->track_hva = hva & ~((1ULL << (order + PAGE_SHIFT)) - 1);
	sp->order = order;
	sp->track_page = compound_head(page);

	return sp;
}

/**
 * free_shared_page_entry - Free a shared_page entry and its associated
 *                          resources
 * @csv: Pointer to the KVM CSV info structure containing the slab cache.
 * @sp:  The shared_page entry to free.
 *
 * The caller must ensure that @sp is no longer in use (e.g., already removed
 * from any rbtree) before calling this function.
 */
void free_shared_page_entry(struct kvm_csv_info *csv, struct shared_page *sp)
{
	if (!sp)
		return;

	kvfree(sp->bitmap);
	kmem_cache_free(csv->sp_slab, sp);
}

static inline struct kvm_svm_csv *to_kvm_svm_csv(struct kvm *kvm)
{
	return (struct kvm_svm_csv *)container_of(kvm, struct kvm_svm, kvm);
}

static int to_csv_pg_level(int level)
{
	int ret;

	switch (level) {
	case PG_LEVEL_4K:
		ret = CSV_PG_LEVEL_4K;
		break;
	case PG_LEVEL_2M:
		ret = CSV_PG_LEVEL_2M;
		break;
	default:
		ret = CSV_PG_LEVEL_NONE;
	}

	return ret;
}

static bool csv3_guest(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;

	return sev_es_guest(kvm) && csv->csv_active;
}

static int csv_sync_vmsa(struct vcpu_svm *svm)
{
	struct vmcb_save_area *save = &svm->vmcb->save;

	/* Check some debug related fields before encrypting the VMSA */
	if (svm->vcpu.guest_debug || (save->dr7 & ~DR7_FIXED_1))
		return -EINVAL;

	/* Sync registgers per spec. */
	save->rax = svm->vcpu.arch.regs[VCPU_REGS_RAX];
	save->rbx = svm->vcpu.arch.regs[VCPU_REGS_RBX];
	save->rcx = svm->vcpu.arch.regs[VCPU_REGS_RCX];
	save->rdx = svm->vcpu.arch.regs[VCPU_REGS_RDX];
	save->rsp = svm->vcpu.arch.regs[VCPU_REGS_RSP];
	save->rbp = svm->vcpu.arch.regs[VCPU_REGS_RBP];
	save->rsi = svm->vcpu.arch.regs[VCPU_REGS_RSI];
	save->rdi = svm->vcpu.arch.regs[VCPU_REGS_RDI];
#ifdef CONFIG_X86_64
	save->r8  = svm->vcpu.arch.regs[VCPU_REGS_R8];
	save->r9  = svm->vcpu.arch.regs[VCPU_REGS_R9];
	save->r10 = svm->vcpu.arch.regs[VCPU_REGS_R10];
	save->r11 = svm->vcpu.arch.regs[VCPU_REGS_R11];
	save->r12 = svm->vcpu.arch.regs[VCPU_REGS_R12];
	save->r13 = svm->vcpu.arch.regs[VCPU_REGS_R13];
	save->r14 = svm->vcpu.arch.regs[VCPU_REGS_R14];
	save->r15 = svm->vcpu.arch.regs[VCPU_REGS_R15];
#endif
	save->rip = svm->vcpu.arch.regs[VCPU_REGS_RIP];

	/* Sync some non-GPR registers before encrypting */
	save->xcr0 = svm->vcpu.arch.xcr0;
	save->pkru = svm->vcpu.arch.pkru;
	save->xss  = svm->vcpu.arch.ia32_xss;
	save->dr6  = svm->vcpu.arch.dr6;

	/*
	 * CSV3 will use a VMSA that is pointed to by the VMCB, not
	 * the traditional VMSA that is part of the VMCB. Copy the
	 * traditional VMSA as it has been built so far (in prep
	 * for LAUNCH_ENCRYPT_VMCB) to be the initial CSV3 state.
	 */
	memcpy(svm->vmsa, save, sizeof(*save));
	return 0;
}

static int __csv_issue_cmd(int fd, int id, void *data, int *error)
{
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = sev_issue_cmd_external_user(f.file, id, data, error);

	fdput(f);
	return ret;
}

static int csv_issue_cmd(struct kvm *kvm, int id, void *data, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return __csv_issue_cmd(sev->fd, id, data, error);
}

static inline void csv_init_update_npt(struct csv_data_update_npt *update_npt,
				       gpa_t gpa, u32 error, u32 handle)
{
	memset(update_npt, 0x00, sizeof(*update_npt));

	update_npt->gpa = gpa & PAGE_MASK;
	update_npt->error_code = error;
	update_npt->handle = handle;
}

static inline
void csv3_init_update_npt_ex(struct csv3_data_update_npt_ex *update_npt,
			     gpa_t gpa, u32 error, u32 handle)
{
	memset(update_npt, 0x00, sizeof(*update_npt));

	update_npt->gpa = gpa & PAGE_MASK;
	update_npt->error_code = error;
	update_npt->handle = handle;
}

static int csv_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv_init_data params;
	struct kmem_cache *sp_slab;
	char   slab_name[0x40];

	if (unlikely(csv->csv_active))
		return -EINVAL;

	if (unlikely(!sev->es_active))
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	csv->csv_active = true;
	csv->sev = sev;
	csv->nodemask = (unsigned long)params.nodemask;

	INIT_LIST_HEAD(&csv->smr_list);
	INIT_LIST_HEAD(&csv->hugetlb_list);
	mutex_init(&csv->sp_lock);

	memset(slab_name, 0, sizeof(slab_name));
	snprintf(slab_name, sizeof(slab_name), "csv3_%d_sp_slab", sev->asid);
	sp_slab = kmem_cache_create(slab_name, sizeof(struct shared_page), 0, 0, NULL);
	if (!sp_slab)
		return -ENOMEM;

	csv->sp_slab = sp_slab;
	csv->sp_mgr.root = RB_ROOT;

	return 0;
}

static bool csv_is_mmio_pfn(kvm_pfn_t pfn)
{
	return !e820__mapped_raw_any(pfn_to_hpa(pfn),
				     pfn_to_hpa(pfn + 1) - 1,
				     E820_TYPE_RAM);
}

/**
 * csv3_free_smr_list - Free secure_memory_region structure from CSV3 VM's
 *			smr_list.
 * There are 3 types memory described by secure_memory_region structure:
 *   - Guest private memory, NPT, metadata (e.g., VMSA) allocated from CMA.
 *     The CMA should be released when remove it from CSV3 VM's smr_list.
 *   - Guest private memory allocated from 1G hugetlb.
 *     The caller should release the 1G hugetlb pages.
 *   - Guest metadata (e.g., VMSA) allocated from system-reserved memory
 *     pool, used only when guest private memory is allocated from 1G
 *     hugetlb. This memory should be free back to the pool.
 */
static void csv3_free_smr_list(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct secure_memory_region *smr;
	struct list_head *pos, *q;
	enum csv_smr_source source = get_csv_smr_source();

	list_for_each_safe(pos, q, &csv->smr_list) {
		smr = list_entry(pos, struct secure_memory_region, list);
		if (smr) {
			if (source == USE_CMA)
				csv_release_to_contiguous(smr->hpa,
						smr->npages << PAGE_SHIFT);

			if (smr->type == CSV_METADATA)
				csv_free_metadata(smr->hpa);

			list_del(&smr->list);
			kfree(smr);
		}
	}
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static void csv3_free_1G_hugetlb_pages(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_hugetlb *hugetlb;
	struct list_head *pos, *q;

	list_for_each_safe(pos, q, &csv->hugetlb_list) {
		hugetlb = list_entry(pos, struct csv3_hugetlb, list);
		if (hugetlb) {
			put_page(hugetlb->page);
			list_del(&hugetlb->list);
			kfree(hugetlb);
		}
	}
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static int csv3_alloc_1G_hugetlb_pages(struct kvm *kvm,
					unsigned long size,
					nodemask_t *nodemask)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct hstate *h = size_to_hstate(1 << PUD_SHIFT);
	struct page *page;
	struct csv3_hugetlb *hugetlb;
	int huge_count;
	int i;

	if (!h)
		return -ENOMEM;

	huge_count = ALIGN(size, PUD_SIZE) / PUD_SIZE;

	for (i = 0; i < huge_count; i++) {
		hugetlb = kzalloc(sizeof(*hugetlb), GFP_KERNEL_ACCOUNT);
		if (!hugetlb)
			goto err;

		page = alloc_huge_page_nodemask(h, numa_mem_id(),
						nodemask, GFP_KERNEL);
		if (!page) {
			kfree(hugetlb);
			goto err;
		}

		hugetlb->page = page;
		list_add_tail(&hugetlb->list, &csv->hugetlb_list);
	}

	return 0;

err:
	csv3_free_1G_hugetlb_pages(kvm);

	return -ENOMEM;
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static int csv3_init_1G_hugetlb_smrs(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_hugetlb *hugetlb;
	struct secure_memory_region *smr;
	struct list_head *pos, *q;
	u64 hpa;
	u32 smr_entry_shift;
	int smr_count;
	int i;
	int ret = 0;

	smr_entry_shift = csv_get_smr_entry_shift();
	smr_count = PUD_SIZE / (1UL << smr_entry_shift);

	list_for_each_safe(pos, q, &csv->hugetlb_list) {
		hugetlb = list_entry(pos, struct csv3_hugetlb, list);
		if (!hugetlb) {
			WARN_ON(1);
			ret = -ENOMEM;
			goto err;
		}

		hpa = page_to_pfn(hugetlb->page) << PAGE_SHIFT;
		for (i = 0; i < smr_count; i++) {
			smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
			if (!smr) {
				ret = -ENOMEM;
				goto err;
			}

			smr->hpa = hpa + i * (1UL << smr_entry_shift);
			list_add_tail(&smr->list, &csv->smr_list);
		}
	}

	return 0;

err:
	csv3_free_smr_list(kvm);

	return ret;
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static u64 csv3_get_1G_hugetlb_smr(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct secure_memory_region *smr;
	struct list_head *pos, *q;
	u64 hpa = 0;

	list_for_each_safe(pos, q, &csv->smr_list) {
		smr = list_entry(pos, struct secure_memory_region, list);
		if (smr) {
			hpa = smr->hpa;
			list_del(&smr->list);
			kfree(smr);
			break;
		}
	}

	return hpa;
}

/**
 * This helper function is used when CSV3 private memory is allocated from 1G
 * hugetlb.
 */
static int csv3_set_hugetlb_smr(struct kvm *kvm, unsigned long vm_size,
				nodemask_t *nodemask, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_set_guest_private_memory *set_guest_private_memory;
	struct secure_memory_region *smr;
	struct csv_data_memory_region *regions;

	LIST_HEAD(tmp_list);
	u32 i = 0, count = 0, remainder;
	int ret = 0;
	u64 nr_smr = 0;
	u32 smr_entry_shift;
	bool metadata_allocated = false;

	set_guest_private_memory = kzalloc(sizeof(*set_guest_private_memory),
					GFP_KERNEL_ACCOUNT);
	if (!set_guest_private_memory)
		return -ENOMEM;

	regions = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!regions) {
		kfree(set_guest_private_memory);
		return -ENOMEM;
	}

	ret = csv3_alloc_1G_hugetlb_pages(kvm, vm_size, nodemask);
	if (ret)
		goto done;

	ret = csv3_init_1G_hugetlb_smrs(kvm);
	if (ret)
		goto done;

	smr_entry_shift = csv_get_smr_entry_shift();
	nr_smr = vm_size >> smr_entry_shift;
	nr_smr += 1;

	remainder = nr_smr;
	for (i = 0; i < nr_smr; i++) {
		smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
		if (!smr) {
			ret = -ENOMEM;
			goto done;
		}

		if (metadata_allocated == false) {
			smr->hpa = csv_alloc_metadata();
			smr->type = CSV_METADATA;
			metadata_allocated = true;
		} else {
			smr->hpa = csv3_get_1G_hugetlb_smr(kvm);
			smr->type = CSV_SEC_MEM;
		}
		if (!smr->hpa) {
			kfree(smr);
			ret = -ENOMEM;
			goto done;
		}

		smr->npages = ((1UL << smr_entry_shift) >> PAGE_SHIFT);
		list_add_tail(&smr->list, &tmp_list);

		regions[count].size = (1UL << smr_entry_shift);
		regions[count].base_address = smr->hpa;

		clflush_cache_range(__va(regions[count].base_address),
				    regions[count].size);

		count++;

		if (count >= (PAGE_SIZE / sizeof(regions[0])) || (remainder == count)) {
			set_guest_private_memory->nregions = count;
			set_guest_private_memory->handle = sev->handle;
			set_guest_private_memory->regions_paddr = __sme_pa(regions);

			/* set secury memory region for launch enrypt data */
			ret = hygon_kvm_hooks.sev_issue_cmd(kvm,
						CSV3_CMD_SET_GUEST_PRIVATE_MEMORY,
						set_guest_private_memory, &argp->error);
			if (ret)
				goto done;

			memset(regions, 0, PAGE_SIZE);
			remainder -= count;
			count = 0;
		}
	}

#ifdef CONFIG_SYSFS
	/* The NPT is allocated from global SMCR */
	csv->npt_size = 0;
	/**
	 * Don't account for guest private memory since:
	 *   - VMSAs are allocated from system-reserverd memory pool.
	 *   - CSV3 private memory is allocated from 1G hugetlb.
	 */
	csv->pri_mem = 0;
#endif

done:
	list_splice(&tmp_list, &csv->smr_list);

	kfree(set_guest_private_memory);
	kfree(regions);

	return ret;
}

/*
 * Calculate the npt size according to the input VM size, return the SMR number
 * for the NPT.
 *
 * This helper function is used when CSV3 private memory is allocated from CMA.
 */
static u32 csv3_get_vm_npt_smr_number(unsigned long vm_size)
{
	u64 nr_pages = vm_size >> PAGE_SHIFT;
	u32 smr_entry_shift, nr_smr;
	u64 size;

	/*
	 * NPT secure memory size
	 *
	 * PTEs_entries = nr_pages
	 * PDEs_entries = nr_pages / 512
	 * PDPEs_entries = nr_pages / (512 * 512)
	 * PML4Es_entries = nr_pages / (512 * 512 * 512)
	 *
	 * Totals_entries = nr_pages + nr_pages / 512 + nr_pages / (512 * 512) +
	 *		nr_pages / (512 * 512 * 512) <= nr_pages + nr_pages / 256
	 *
	 * Total_NPT_size = (Totals_entries / 512) * PAGE_SIZE = ((nr_pages +
	 *      nr_pages / 256) / 512) * PAGE_SIZE = nr_pages * 8 + nr_pages / 32
	 *      <= nr_pages * 9
	 *
	 */
	smr_entry_shift = csv_get_smr_entry_shift();
	size = ALIGN(nr_pages * 9, 1UL << smr_entry_shift);
	nr_smr = size >> smr_entry_shift;

	return nr_smr;
}

/**
 * This helper function is used when CSV3 private memory is allocated from CMA.
 */
static int csv3_set_cma_smr(struct kvm *kvm, unsigned long vm_size,
			    nodemask_t *nodemask, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_set_guest_private_memory *set_guest_private_memory;
	struct secure_memory_region *smr;
	struct csv_data_memory_region *regions;

	LIST_HEAD(tmp_list);
	u32 i = 0, count = 0, remainder;
	int ret = 0;
	u64 nr_smr = 0;
	u32 smr_entry_shift;

	set_guest_private_memory = kzalloc(sizeof(*set_guest_private_memory),
					GFP_KERNEL_ACCOUNT);
	if (!set_guest_private_memory)
		return -ENOMEM;

	regions = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!regions) {
		kfree(set_guest_private_memory);
		return -ENOMEM;
	}

	smr_entry_shift = csv_get_smr_entry_shift();

	/**
	 * If @csv_smcr_num is zero or the firmware does not support explicit
	 * NPT reservation in SMCR, both VMSA and NPT are allocated from CMA.
	 * Otherwise, the NPT is already reserved in SMCR, and only a single
	 * SMR is needed for the VMSA.
	 */
	if (!csv_smcr_num || hygon_csv_build < 2407)
		nr_smr = (vm_size >> smr_entry_shift)
				+ 1 + csv3_get_vm_npt_smr_number(vm_size);
	else
		nr_smr = (vm_size >> smr_entry_shift) + 1;

	remainder = nr_smr;
	for (i = 0; i < nr_smr; i++) {
		smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
		if (!smr) {
			ret = -ENOMEM;
			goto done;
		}

		smr->hpa = csv_alloc_from_contiguous((1UL << smr_entry_shift),
						nodemask,
						get_order(1 << smr_entry_shift));
		if (!smr->hpa) {
			kfree(smr);
			ret = -ENOMEM;
			goto done;
		}

		smr->npages = ((1UL << smr_entry_shift) >> PAGE_SHIFT);
		list_add_tail(&smr->list, &tmp_list);

		regions[count].size = (1UL << smr_entry_shift);
		regions[count].base_address = smr->hpa;
		count++;

		if (count >= (PAGE_SIZE / sizeof(regions[0])) || (remainder == count)) {
			set_guest_private_memory->nregions = count;
			set_guest_private_memory->handle = sev->handle;
			set_guest_private_memory->regions_paddr = __sme_pa(regions);

			/* set secury memory region for launch enrypt data */
			ret = csv_issue_cmd(kvm, CSV3_CMD_SET_GUEST_PRIVATE_MEMORY,
					set_guest_private_memory, &argp->error);
			if (ret)
				goto done;

			memset(regions, 0, PAGE_SIZE);
			remainder -= count;
			count = 0;
		}
	}

#ifdef CONFIG_SYSFS
	/**
	 * The NPT can be allocated from either CMA or global SMCR.
	 * Only account for it when allocated from CMA.
	 */
	if (!csv_smcr_num || hygon_csv_build < 2407)
		csv->npt_size = csv3_get_vm_npt_smr_number(vm_size)
							<< smr_entry_shift;
	else
		csv->npt_size = 0;
	csv->pri_mem = (nr_smr << smr_entry_shift) - csv->npt_size;
	atomic_long_add(csv->npt_size, &csv3_npt_size);
	atomic_long_add(csv->pri_mem, &csv3_pri_mem);
#endif	/* CONFIG_SYSFS */

done:
	list_splice(&tmp_list, &csv->smr_list);

	kfree(set_guest_private_memory);
	kfree(regions);

	return ret;
}

static int __csv3_set_guest_private_memory(struct kvm *kvm,
					   struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;
	nodemask_t nodemask;
	nodemask_t *nodemask_ptr;

	u32 i = 0;
	int ret = 0;
	u32 smr_entry_shift;

	unsigned int flags = FOLL_HWPOISON;
	u64 npages, nr_pages = 0;
	struct page *page;

	unsigned long vm_size;
	enum csv_smr_source source;

	nodes_clear(nodemask);
	for_each_set_bit(i, &csv->nodemask, BITS_PER_LONG)
		if (i < MAX_NUMNODES)
			node_set(i, nodemask);

	nodemask_ptr = csv->nodemask ? &nodemask : &node_online_map;

	/* Get guest secure memory size */
	kvm_for_each_memslot(memslot, slots) {
		if (memslot->flags & KVM_MEM_READONLY)
			continue;

		npages = get_user_pages_unlocked(memslot->userspace_addr, 1,
						&page, flags);
		if (npages != 1)
			continue;

		nr_pages += memslot->npages;

		put_page(page);
	}

	smr_entry_shift = csv_get_smr_entry_shift();
	vm_size = ALIGN((nr_pages << PAGE_SHIFT), 1UL << smr_entry_shift);

	/**
	 * Allocation policy for NPT and VMSA based on CSV3 private memory
	 * source:
	 *
	 * - When CSV3 private memory is allocated from 1GB hugepages:
	 *     * NPT is allocated from the global SMCR.
	 *     * VMSA is allocated from system-reserved memory pool.
	 *
	 * - When CSV3 private memory is allocated from CMA:
	 *     * VMSA is allocated from CMA.
	 *     * NPT is allocated from the global SMCR if it was reserved at
	 *	 host boot time; otherwise, it is allocated from CMA.
	 */
	source = get_csv_smr_source();
	if (source == USE_HUGETLB) {
		ret = csv3_set_hugetlb_smr(kvm, vm_size, nodemask_ptr, argp);
	} else if (source == USE_CMA) {
		ret = csv3_set_cma_smr(kvm, vm_size, nodemask_ptr, argp);
	} else {
		ret = -EFAULT;
		WARN_ON(1);
	}

	return ret;
}

/**
 * This helper function is used when userspace membackend of CSV3 VM is
 * allocated from 1G hugetlb.
 */
static int csv3_setup_1G_hugetlb_list(struct kvm *kvm,
				      unsigned long size,
				      nodemask_t *nodemask)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct hstate *h = size_to_hstate(1 << PUD_SHIFT);
	struct page *page;
	struct csv3_hugetlb *hugetlb;
	gpa_t gpa = 0;
	u64 hva;
	u64 npages;
	int huge_count;
	int i;

	if (!h)
		return -ENOMEM;

	huge_count = ALIGN(size, PUD_SIZE) / PUD_SIZE;

	for (i = 0; i < huge_count; i++) {
		hugetlb = kzalloc(sizeof(*hugetlb), GFP_KERNEL_ACCOUNT);
		if (!hugetlb)
			goto err;

retry:
		hva = gfn_to_hva(kvm, gpa >> PAGE_SHIFT);
		/* Increment gpa so that we can skip memory holes. */
		gpa += 1 << PUD_SHIFT;
		if (kvm_is_error_hva(hva))
			goto retry;

		npages = get_user_pages_unlocked(hva, 1, &page, FOLL_HWPOISON);
		if (npages != 1) {
			kfree(hugetlb);
			goto err;
		}

		/* The userspace membackend must be 1G hugetlb. */
		if (compound_order(compound_head(page)) != (PUD_SHIFT - PAGE_SHIFT)) {
			kfree(hugetlb);
			put_page(page);
			goto err;
		}
		hugetlb->page = page;
		list_add_tail(&hugetlb->list, &csv->hugetlb_list);
	}

	return 0;

err:
	csv3_free_1G_hugetlb_pages(kvm);

	return -ENOMEM;
}

/**
 * This helper function is used when userspace membackend of CSV3 VM is
 * allocated from 1G hugetlb.
 */
static int csv3_init_1G_hugetlb_smrs_ex(struct kvm *kvm, u64 *nr_smr)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_hugetlb *hugetlb;
	struct secure_memory_region *smr;
	struct list_head *pos, *q;
	u64 hpa;
	int ret = 0;

	if (!nr_smr)
		return -EINVAL;

	*nr_smr = 0;

	list_for_each_safe(pos, q, &csv->hugetlb_list) {
		hugetlb = list_entry(pos, struct csv3_hugetlb, list);
		if (!hugetlb) {
			WARN_ON(1);
			ret = -ENOMEM;
			goto err;
		}

		hpa = page_to_pfn(hugetlb->page) << PAGE_SHIFT;
		smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
		if (!smr) {
			ret = -ENOMEM;
			goto err;
		}

		smr->hpa = hpa;
		smr->npages = PUD_SIZE >> PAGE_SHIFT;
		list_add_tail(&smr->list, &csv->smr_list);
		(*nr_smr)++;
	}

	return 0;

err:
	csv3_free_smr_list(kvm);

	return ret;
}

/**
 * This helper function is used when userspace membackend of CSV3 VM is
 * allocated from 1G hugetlb.
 */
static int csv3_set_hugetlb_smr_ex(struct kvm *kvm, unsigned long vm_size,
				   nodemask_t *nodemask, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_set_guest_private_memory *set_guest_private_memory;
	struct secure_memory_region *smr;
	struct csv3_data_memory_region_ex *regions;

	LIST_HEAD(tmp_list);
	u32 i = 0, count = 0, remainder;
	int ret = 0;
	u64 nr_smr = 0;
	u64 gpa = 0;
	u64 tom;
	bool metadata_allocated = false;

	set_guest_private_memory = kzalloc(sizeof(*set_guest_private_memory),
					GFP_KERNEL_ACCOUNT);
	if (!set_guest_private_memory)
		return -ENOMEM;

	regions = kzalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	if (!regions) {
		kfree(set_guest_private_memory);
		return -ENOMEM;
	}

	ret = csv3_setup_1G_hugetlb_list(kvm, vm_size, nodemask);
	if (ret)
		goto done;

	ret = csv3_init_1G_hugetlb_smrs_ex(kvm, &nr_smr);
	if (ret)
		goto done;

	nr_smr += 1;

	tom = csv->tom;
	remainder = nr_smr;
	for (i = 0; i < nr_smr; i++) {
		smr = kzalloc(sizeof(*smr), GFP_KERNEL_ACCOUNT);
		if (!smr) {
			ret = -ENOMEM;
			goto done;
		}

		if (metadata_allocated == false) {
			smr->hpa = csv_alloc_metadata();
			smr->type = CSV_METADATA;
			smr->npages = (1UL << csv_get_smr_entry_shift()) >> PAGE_SHIFT;
			regions[count].guest_address = -1UL;
			metadata_allocated = true;
		} else {
			smr->hpa = csv3_get_1G_hugetlb_smr(kvm);
			smr->type = CSV_SEC_MEM;
			smr->npages = PUD_SIZE >> PAGE_SHIFT;
			regions[count].guest_address = gpa;
		}
		if (!smr->hpa) {
			kfree(smr);
			ret = -ENOMEM;
			goto done;
		}

		list_add_tail(&smr->list, &tmp_list);

		regions[count].size = smr->npages << PAGE_SHIFT;
		regions[count].base_address = smr->hpa;

		clflush_cache_range(__va(regions[count].base_address),
				    regions[count].size);

		if (smr->type == CSV_SEC_MEM) {
			gpa += regions[count].size;
			/* The range between @tom and 4G is memory hole. */
			if (gpa >= tom) {
				gpa = 4UL << PUD_SHIFT;
				tom = -1UL;
			}
		}
		count++;

		if (count >= (PAGE_SIZE / sizeof(regions[0])) || (remainder == count)) {
			set_guest_private_memory->nregions = count;
			set_guest_private_memory->handle = sev->handle;
			set_guest_private_memory->regions_paddr = __sme_pa(regions);

			/* set secury memory region for launch enrypt data */
			ret = hygon_kvm_hooks.sev_issue_cmd(kvm,
						CSV3_CMD_SET_GUEST_PRIVATE_MEMORY_EX,
						set_guest_private_memory, &argp->error);
			if (ret)
				goto done;

			memset(regions, 0, PAGE_SIZE);
			remainder -= count;
			count = 0;
		}
	}

#ifdef CONFIG_SYSFS
	/* The NPT is allocated from global SMCR */
	csv->npt_size = 0;
	/**
	 * Don't account for guest private memory since:
	 *   - VMSAs are allocated from system-reserverd memory pool.
	 *   - CSV3 private memory is allocated from 1G hugetlb.
	 */
	csv->pri_mem = 0;
#endif

done:
	list_splice(&tmp_list, &csv->smr_list);

	kfree(set_guest_private_memory);
	kfree(regions);

	return ret;
}

static int __csv3_set_guest_private_memory_ex(struct kvm *kvm,
					      struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;
	nodemask_t nodemask;
	nodemask_t *nodemask_ptr;
	u64 tom = 0;
	u64 tom2 = 0;
	u64 t;
	u32 i = 0;
	u32 smr_entry_shift;
	u64 nr_pages = 0;
	unsigned long vm_size;

	nodes_clear(nodemask);
	for_each_set_bit(i, &csv->nodemask, BITS_PER_LONG)
		if (i < MAX_NUMNODES)
			node_set(i, nodemask);

	nodemask_ptr = csv->nodemask ? &nodemask : &node_online_map;

	/* Get guest secure memory size */
	kvm_for_each_memslot(memslot, slots) {
		if (memslot->flags & KVM_MEM_READONLY)
			continue;

		t = memslot->base_gfn + memslot->npages;
		t = t << PAGE_SHIFT;
		if (t < (4UL << PUD_SHIFT) && t > tom)
			tom = t;

		if (t > (4UL << PUD_SHIFT) && t > tom2)
			tom2 = t;

		nr_pages += memslot->npages;
	}

	csv->tom = tom;
	csv->tom2 = tom2;

	smr_entry_shift = csv_get_smr_entry_shift();
	vm_size = ALIGN((nr_pages << PAGE_SHIFT), 1UL << smr_entry_shift);

	return csv3_set_hugetlb_smr_ex(kvm, vm_size, nodemask_ptr, argp);
}

static int csv3_set_guest_private_memory(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	/* The smr_list should be initialized only once */
	if (!list_empty(&csv->smr_list))
		return -EFAULT;

	if (csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_NPT_EX)
		return __csv3_set_guest_private_memory_ex(kvm, argp);
	else
		return __csv3_set_guest_private_memory(kvm, argp);
}

/**
 * csv3_launch_encrypt_data_alt_1 - The legacy handler to encrypt CSV3
 * guest's memory before VMRUN.
 */
static int csv3_launch_encrypt_data_alt_1(struct kvm *kvm,
					  struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv3_launch_encrypt_data params;
	struct csv3_data_launch_encrypt_data *encrypt_data = NULL;
	struct encrypt_data_block *blocks = NULL;
	u8 *data = NULL;
	u32 offset;
	u32 num_entries, num_entries_in_block;
	u32 num_blocks, num_blocks_max;
	u32 i, n;
	unsigned long pfn, pfn_sme_mask;
	int ret = 0;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params))) {
		ret = -EFAULT;
		goto exit;
	}

	if ((params.len & ~PAGE_MASK) || !params.len || !params.uaddr) {
		ret = -EINVAL;
		goto exit;
	}

	/*
	 * If userspace request to invoke CSV3_CMD_SET_GUEST_PRIVATE_MEMORY
	 * explicitly, we should not calls to csv3_set_guest_private_memory()
	 * here.
	 */
	if (!(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_SET_PRIV_MEM)) {
		/* Allocate all the guest memory from CMA */
		ret = csv3_set_guest_private_memory(kvm, argp);
		if (ret)
			goto exit;
	}

	num_entries = params.len / PAGE_SIZE;
	num_entries_in_block = ARRAY_SIZE(blocks->entry);
	num_blocks = (num_entries + num_entries_in_block - 1) / num_entries_in_block;
	num_blocks_max = ARRAY_SIZE(encrypt_data->data_blocks);

	if (num_blocks >= num_blocks_max) {
		ret = -EINVAL;
		goto exit;
	}

	data = vzalloc(params.len);
	if (!data) {
		ret = -ENOMEM;
		goto exit;
	}
	if (copy_from_user(data, (void __user *)params.uaddr, params.len)) {
		ret = -EFAULT;
		goto data_free;
	}

	blocks = vzalloc(num_blocks * sizeof(*blocks));
	if (!blocks) {
		ret = -ENOMEM;
		goto data_free;
	}

	for (offset = 0, i = 0, n = 0; offset < params.len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + data);
		pfn_sme_mask = __sme_set(pfn << PAGE_SHIFT) >> PAGE_SHIFT;
		if (offset && ((blocks[n].entry[i].pfn + 1) == pfn_sme_mask))
			blocks[n].entry[i].npages += 1;
		else {
			if (offset) {
				i = (i + 1) % num_entries_in_block;
				n = (i == 0) ? (n + 1) : n;
			}
			blocks[n].entry[i].pfn = pfn_sme_mask;
			blocks[n].entry[i].npages = 1;
		}
	}

	encrypt_data = kzalloc(sizeof(*encrypt_data), GFP_KERNEL);
	if (!encrypt_data) {
		ret = -ENOMEM;
		goto block_free;
	}

	encrypt_data->handle = csv->sev->handle;
	encrypt_data->length = params.len;
	encrypt_data->gpa = params.gpa;
	for (i = 0; i <= n; i++) {
		encrypt_data->data_blocks[i] =
		__sme_set(vmalloc_to_pfn((void *)blocks + i * sizeof(*blocks)) << PAGE_SHIFT);
	}

	clflush_cache_range(data, params.len);
	ret = csv_issue_cmd(kvm, CSV3_CMD_LAUNCH_ENCRYPT_DATA,
			    encrypt_data, &argp->error);

	kfree(encrypt_data);
block_free:
	vfree(blocks);
data_free:
	vfree(data);
exit:
	return ret;
}

#define MAX_ENTRIES_PER_BLOCK							\
	(sizeof(((struct encrypt_data_block *)0)->entry) /			\
	 sizeof(((struct encrypt_data_block *)0)->entry[0]))
#define MAX_BLOCKS_PER_CSV3_LUP_DATA						\
	(sizeof(((struct csv3_data_launch_encrypt_data *)0)->data_blocks) /	\
	 sizeof(((struct csv3_data_launch_encrypt_data *)0)->data_blocks[0]))
#define MAX_ENTRIES_PER_CSV3_LUP_DATA						\
	(MAX_BLOCKS_PER_CSV3_LUP_DATA * MAX_ENTRIES_PER_BLOCK)

/**
 * __csv3_launch_encrypt_data - The helper for handler
 * csv3_launch_encrypt_data_alt_2.
 */
static int __csv3_launch_encrypt_data(struct kvm *kvm,
				      struct kvm_sev_cmd *argp,
				      struct kvm_csv3_launch_encrypt_data *params,
				      void *src_buf,
				      unsigned int start_pgoff,
				      unsigned int end_pgoff)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv3_data_launch_encrypt_data *data = NULL;
	struct encrypt_data_block *block = NULL;
	struct page **pages = NULL;
	unsigned long len, remain_len;
	unsigned long pfn, pfn_sme_mask, last_pfn;
	unsigned int pgoff = start_pgoff;
	int i, j;
	int ret = -ENOMEM;

	/* Alloc command buffer for CSV3_CMD_LAUNCH_ENCRYPT_DATA command */
	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	/* Alloc pages for data_blocks[] in the command buffer */
	len = ARRAY_SIZE(data->data_blocks) * sizeof(struct page *);
	pages = kzalloc(len, GFP_KERNEL_ACCOUNT);
	if (!pages)
		goto e_free_data;

	for (i = 0; i < ARRAY_SIZE(data->data_blocks); i++) {
		pages[i] = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!pages[i])
			goto e_free_pages;
	}

	i = 0;
	while (i < ARRAY_SIZE(data->data_blocks) && pgoff < end_pgoff) {
		block = (struct encrypt_data_block *)page_to_virt(pages[i]);

		j = 0;
		last_pfn = 0;
		while (j < ARRAY_SIZE(block->entry) && pgoff < end_pgoff) {
			pfn = vmalloc_to_pfn(src_buf + (pgoff << PAGE_SHIFT));
			pfn_sme_mask = __sme_set(pfn << PAGE_SHIFT) >> PAGE_SHIFT;

			/*
			 * One entry can record a number of contiguous physical
			 * pages. If the current page is not adjacent to the
			 * previous physical page, we should record the page to
			 * the next entry. If entries of current block is used
			 * up, we should try the next block.
			 */
			if (last_pfn && (last_pfn + 1 == pfn)) {
				block->entry[j].npages++;
			} else if (j < (ARRAY_SIZE(block->entry) - 1)) {
				/* @last_pfn == 0 means fill in entry[0] */
				if (likely(last_pfn != 0))
					j++;
				block->entry[j].pfn = pfn_sme_mask;
				block->entry[j].npages = 1;
			} else {
				break;
			}

			/*
			 * Succeed to record one page, increase the page offset.
			 * We also record the pfn of current page so that we can
			 * record the contiguous physical pages into one entry.
			 */
			last_pfn = pfn;
			pgoff++;
		}

		i++;
	}

	if (pgoff < end_pgoff) {
		pr_err("CSV3: Fail to fill in LAUNCH_ENCRYPT_DATA command!\n");
		goto e_free_pages;
	}

	len = (end_pgoff - start_pgoff) << PAGE_SHIFT;
	clflush_cache_range(src_buf + (start_pgoff << PAGE_SHIFT), len);

	/* Fill in command buffer */
	data->handle = csv->sev->handle;

	if (start_pgoff == 0) {
		data->gpa = params->gpa;
		len -= params->gpa & ~PAGE_MASK;
	} else {
		data->gpa = (params->gpa & PAGE_MASK) + (start_pgoff << PAGE_SHIFT);
	}
	remain_len = params->len - (data->gpa - params->gpa);

	data->length = (len <= remain_len) ? len : remain_len;

	for (j = 0; j < i; j++)
		data->data_blocks[j] = __sme_set(page_to_phys(pages[j]));

	/* Issue command */
	ret = csv_issue_cmd(kvm, CSV3_CMD_LAUNCH_ENCRYPT_DATA, data, &argp->error);

e_free_pages:
	for (i = 0; i < ARRAY_SIZE(data->data_blocks); i++) {
		if (pages[i])
			__free_page(pages[i]);
	}
	kfree(pages);
e_free_data:
	kfree(data);

	return ret;
}

/**
 * csv3_launch_encrypt_data_alt_2 - The handler to support encrypt CSV3
 * guest's memory before VMRUN. This handler support issue API command
 * multiple times, both the GPA and length of the memory region are not
 * required to be 4K-aligned.
 */
static int csv3_launch_encrypt_data_alt_2(struct kvm *kvm,
					  struct kvm_sev_cmd *argp)
{
	struct kvm_csv3_launch_encrypt_data params;
	void *buffer = NULL;
	unsigned long len;
	unsigned int total_pages, start_pgoff, next_pgoff;
	int ret = 0;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params))) {
		return -EFAULT;
	}

	/* Both the GPA and length must be 16 Bytes aligned at least */
	if (!params.len ||
	    !params.uaddr ||
	    !IS_ALIGNED(params.len, 16) ||
	    !IS_ALIGNED(params.gpa, 16)) {
		return -EINVAL;
	}

	/*
	 * Alloc buffer to save source data. When we copy source data from
	 * userspace to the buffer, the data in the first page of the buffer
	 * should keep the offset as params.gpa.
	 */
	len = PAGE_ALIGN((params.gpa & ~PAGE_MASK) + params.len);
	total_pages = len >> PAGE_SHIFT;
	next_pgoff = 0;

	buffer = vzalloc(len);
	if (!buffer)
		return -ENOMEM;

	if (copy_from_user(buffer + (params.gpa & ~PAGE_MASK),
			   (void __user *)params.uaddr, params.len)) {
		ret = -EFAULT;
		goto e_free_buffer;
	}

	/*
	 * If the source data is too large, we should issue command more than
	 * once. The LAUNCH_ENCRYPT_DATA API updates not only the measurement
	 * of the data, but also the measurement of the metadata correspond to
	 * the data. The guest owner is obligated to verify the launch
	 * measurement, so guest owner must be aware of the launch measurement
	 * of each LAUNCH_ENCRYPT_DATA API command. If we processing pages more
	 * than MAX_ENTRIES_PER_CSV3_LUP_DATA in each API command, the guest
	 * owner could not able to calculate the correct measurement and fail
	 * to verify the launch measurement. For this reason, we limit the
	 * maximum number of pages processed by each API command to
	 * MAX_ENTRIES_PER_CSV3_LUP_DATA.
	 */
	while (next_pgoff < total_pages) {
		start_pgoff = next_pgoff;
		next_pgoff += MAX_ENTRIES_PER_CSV3_LUP_DATA;

		if (next_pgoff > total_pages)
			next_pgoff = total_pages;

		ret = __csv3_launch_encrypt_data(kvm, argp, &params,
						 buffer, start_pgoff, next_pgoff);
		if (ret)
			goto e_free_buffer;
	}

e_free_buffer:
	vfree(buffer);
	return ret;
}

static int csv3_launch_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (!(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_MULT_LUP_DATA))
		return csv3_launch_encrypt_data_alt_1(kvm, argp);

	return csv3_launch_encrypt_data_alt_2(kvm, argp);
}

static int csv_launch_encrypt_vmcb(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv_data_launch_encrypt_vmcb *encrypt_vmcb = NULL;
	struct kvm_vcpu *vcpu;
	int ret = 0;
	unsigned long i = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	encrypt_vmcb = kzalloc(sizeof(*encrypt_vmcb), GFP_KERNEL);
	if (!encrypt_vmcb) {
		ret = -ENOMEM;
		goto exit;
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		ret = csv_sync_vmsa(svm);
		if (ret)
			goto e_free;
		clflush_cache_range(svm->vmsa, PAGE_SIZE);
		clflush_cache_range(svm->vmcb, PAGE_SIZE);
		encrypt_vmcb->handle = csv->sev->handle;
		encrypt_vmcb->vcpu_id = i;
		encrypt_vmcb->vmsa_addr = __sme_pa(svm->vmsa);
		encrypt_vmcb->vmsa_len = PAGE_SIZE;
		encrypt_vmcb->shadow_vmcb_addr = __sme_pa(svm->vmcb);
		encrypt_vmcb->shadow_vmcb_len = PAGE_SIZE;
		ret = csv_issue_cmd(kvm, CSV_CMD_LAUNCH_ENCRYPT_VMCB,
				    encrypt_vmcb, &argp->error);
		if (ret)
			goto e_free;

		svm->vmcb_pa = encrypt_vmcb->secure_vmcb_addr;
		svm->vcpu.arch.guest_state_protected = true;
	}

e_free:
	kfree(encrypt_vmcb);
exit:
	return ret;
}

static int csv3_launch_finish_ex(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv3_launch_finish_ex params;
	struct csv3_data_launch_finish_ex *finish_ex = NULL;
	int ret = 0;

	if (!csv3_guest(kvm) ||
	    !(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_LFINISH_EX))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	finish_ex = kzalloc(sizeof(*finish_ex), GFP_KERNEL);
	if (!finish_ex)
		return -ENOMEM;

	finish_ex->handle = csv->sev->handle;
	memcpy(finish_ex->host_data, params.host_data, KVM_CSV3_HOST_DATA_SIZE);
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, CSV3_CMD_LAUNCH_FINISH_EX,
						finish_ex, &argp->error);

	kfree(finish_ex);

	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
csv_send_encrypt_data_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
				    struct kvm_csv_send_encrypt_data *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv_data_send_encrypt_data data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = csv_issue_cmd(kvm, CSV_CMD_SEND_ENCRYPT_DATA, &data, &argp->error);

	params->hdr_len = data.hdr_len;
	params->trans_len = data.trans_len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, params, sizeof(*params)))
		ret = -EFAULT;

	return ret;
}

#define CSV_SEND_ENCRYPT_DATA_MIGRATE_PAGE  0x00000000
#define CSV_SEND_ENCRYPT_DATA_SET_READONLY  0x00000001
static int csv_send_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv_data_send_encrypt_data data;
	struct kvm_csv_send_encrypt_data params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	struct guest_paddr_block *guest_block;
	unsigned long pfn;
	u32 offset;
	int ret = 0;
	int i;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return csv_send_encrypt_data_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.guest_addr_data ||
	    !params.guest_addr_len || !params.hdr_uaddr)
		return -EINVAL;

	if (params.guest_addr_len > sizeof(*guest_block))
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	if ((params.trans_len & PAGE_MASK) == 0 ||
	    (params.trans_len & ~PAGE_MASK) != 0)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	guest_block = kzalloc(sizeof(*guest_block), GFP_KERNEL_ACCOUNT);
	if (!guest_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}

	if (copy_from_user(guest_block,
			   (void __user *)(uintptr_t)params.guest_addr_data,
			   params.guest_addr_len)) {
		ret = -EFAULT;
		goto e_free_guest_block;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_guest_block;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}
	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;

	data.guest_block = __psp_pa(guest_block);
	data.guest_len = params.guest_addr_len;
	data.handle = sev->handle;

	clflush_cache_range(hdr, params.hdr_len);
	clflush_cache_range(trans_data, params.trans_len);
	clflush_cache_range(trans_block, PAGE_SIZE);
	clflush_cache_range(guest_block, PAGE_SIZE);

	data.flag = CSV_SEND_ENCRYPT_DATA_SET_READONLY;
	ret = csv_issue_cmd(kvm, CSV_CMD_SEND_ENCRYPT_DATA, &data, &argp->error);
	if (ret)
		goto e_free_trans_data;

	kvm_flush_remote_tlbs(kvm);

	data.flag = CSV_SEND_ENCRYPT_DATA_MIGRATE_PAGE;
	ret = csv_issue_cmd(kvm, CSV_CMD_SEND_ENCRYPT_DATA, &data, &argp->error);
	if (ret)
		goto e_free_trans_data;

	ret = -EFAULT;
	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len))
		goto e_free_trans_data;

	/* copy guest address block to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.guest_addr_data,
			 guest_block, params.guest_addr_len))
		goto e_free_trans_data;

	/* copy packet header to userspace. */
	if (copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
			 params.hdr_len))
		goto e_free_trans_data;

	ret = 0;
e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_guest_block:
	kfree(guest_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
csv_send_encrypt_context_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
				      struct kvm_csv_send_encrypt_context *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv_data_send_encrypt_context data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.handle = sev->handle;
	ret = csv_issue_cmd(kvm, CSV_CMD_SEND_ENCRYPT_CONTEXT, &data, &argp->error);

	params->hdr_len = data.hdr_len;
	params->trans_len = data.trans_len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, params, sizeof(*params)))
		ret = -EFAULT;

	return ret;
}

static int csv_send_encrypt_context(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv_data_send_encrypt_context data;
	struct kvm_csv_send_encrypt_context params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	unsigned long pfn;
	unsigned long i;
	u32 offset;
	int ret = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return csv_send_encrypt_context_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.hdr_uaddr)
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;
	data.handle = sev->handle;

	/* flush hdr, trans data, trans block, secure VMSAs */
	wbinvd_on_all_cpus();

	ret = csv_issue_cmd(kvm, CSV_CMD_SEND_ENCRYPT_CONTEXT, &data, &argp->error);

	if (ret)
		goto e_free_trans_data;

	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	/* copy packet header to userspace. */
	if (copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
			 params.hdr_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

static int csv_receive_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct csv_data_receive_encrypt_data data;
	struct kvm_csv_receive_encrypt_data params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	struct guest_paddr_block *guest_block;
	unsigned long pfn;
	int i;
	u32 offset;
	int ret = 0;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (unlikely(list_empty(&csv->smr_list))) {
		/* Allocate all the guest memory from CMA */
		ret = csv3_set_guest_private_memory(kvm, argp);
		if (ret)
			goto exit;
	}

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	if (!params.hdr_uaddr || !params.hdr_len ||
	    !params.guest_addr_data || !params.guest_addr_len ||
	    !params.trans_uaddr || !params.trans_len)
		return -EINVAL;

	if (params.guest_addr_len > sizeof(*guest_block))
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	if (copy_from_user(hdr,
			  (void __user *)(uintptr_t)params.hdr_uaddr,
			   params.hdr_len)) {
		ret = -EFAULT;
		goto e_free_hdr;
	}

	guest_block = kzalloc(sizeof(*guest_block), GFP_KERNEL_ACCOUNT);
	if (!guest_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}

	if (copy_from_user(guest_block,
			  (void __user *)(uintptr_t)params.guest_addr_data,
			   params.guest_addr_len)) {
		ret = -EFAULT;
		goto e_free_guest_block;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_guest_block;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	if (copy_from_user(trans_data,
			  (void __user *)(uintptr_t)params.trans_uaddr,
			  params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}

	memset(&data, 0, sizeof(data));
	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;
	data.guest_block = __psp_pa(guest_block);
	data.guest_len = params.guest_addr_len;
	data.handle = sev->handle;

	clflush_cache_range(hdr, params.hdr_len);
	clflush_cache_range(trans_data, params.trans_len);
	clflush_cache_range(trans_block, PAGE_SIZE);
	clflush_cache_range(guest_block, PAGE_SIZE);
	ret = csv_issue_cmd(kvm, CSV_CMD_RECEIVE_ENCRYPT_DATA, &data,
			    &argp->error);

e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_guest_block:
	kfree(guest_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

static int csv_receive_encrypt_context(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct csv_data_receive_encrypt_context data;
	struct kvm_csv_receive_encrypt_context params;
	void *hdr;
	void *trans_data;
	struct trans_paddr_block *trans_block;
	struct vmcb_paddr_block *shadow_vmcb_block;
	struct vmcb_paddr_block *secure_vmcb_block;
	unsigned long pfn;
	u32 offset;
	int ret = 0;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	if (!csv3_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	if (!params.trans_uaddr || !params.trans_len ||
	    !params.hdr_uaddr || !params.hdr_len)
		return -EINVAL;

	if (params.trans_len > ARRAY_SIZE(trans_block->trans_paddr) * PAGE_SIZE)
		return -EINVAL;

	/* allocate memory for header and transport buffer */
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr) {
		ret = -ENOMEM;
		goto exit;
	}

	if (copy_from_user(hdr,
			  (void __user *)(uintptr_t)params.hdr_uaddr,
			   params.hdr_len)) {
		ret = -EFAULT;
		goto e_free_hdr;
	}

	trans_block = kzalloc(sizeof(*trans_block), GFP_KERNEL_ACCOUNT);
	if (!trans_block) {
		ret = -ENOMEM;
		goto e_free_hdr;
	}
	trans_data = vzalloc(params.trans_len);
	if (!trans_data) {
		ret = -ENOMEM;
		goto e_free_trans_block;
	}

	if (copy_from_user(trans_data,
			  (void __user *)(uintptr_t)params.trans_uaddr,
			  params.trans_len)) {
		ret = -EFAULT;
		goto e_free_trans_data;
	}

	for (offset = 0, i = 0; offset < params.trans_len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + trans_data);
		trans_block->trans_paddr[i] = __sme_set(pfn_to_hpa(pfn));
		i++;
	}

	secure_vmcb_block = kzalloc(sizeof(*secure_vmcb_block),
				    GFP_KERNEL_ACCOUNT);
	if (!secure_vmcb_block) {
		ret = -ENOMEM;
		goto e_free_trans_data;
	}

	shadow_vmcb_block = kzalloc(sizeof(*shadow_vmcb_block),
				    GFP_KERNEL_ACCOUNT);
	if (!shadow_vmcb_block) {
		ret = -ENOMEM;
		goto e_free_secure_vmcb_block;
	}

	memset(&data, 0, sizeof(data));

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		if (i >= ARRAY_SIZE(shadow_vmcb_block->vmcb_paddr)) {
			ret = -EINVAL;
			goto e_free_shadow_vmcb_block;
		}
		shadow_vmcb_block->vmcb_paddr[i] = __sme_pa(svm->vmcb);
		data.vmcb_block_len += sizeof(shadow_vmcb_block->vmcb_paddr[0]);
	}

	data.hdr_address = __psp_pa(hdr);
	data.hdr_len = params.hdr_len;
	data.trans_block = __psp_pa(trans_block);
	data.trans_len = params.trans_len;
	data.shadow_vmcb_block = __psp_pa(shadow_vmcb_block);
	data.secure_vmcb_block = __psp_pa(secure_vmcb_block);
	data.handle = sev->handle;

	clflush_cache_range(hdr, params.hdr_len);
	clflush_cache_range(trans_data, params.trans_len);
	clflush_cache_range(trans_block, PAGE_SIZE);
	clflush_cache_range(shadow_vmcb_block, PAGE_SIZE);
	clflush_cache_range(secure_vmcb_block, PAGE_SIZE);

	ret = csv_issue_cmd(kvm, CSV_CMD_RECEIVE_ENCRYPT_CONTEXT, &data,
			    &argp->error);
	if (ret)
		goto e_free_shadow_vmcb_block;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		if (i >= ARRAY_SIZE(secure_vmcb_block->vmcb_paddr)) {
			ret = -EINVAL;
			goto e_free_shadow_vmcb_block;
		}

		svm->vmcb_pa = secure_vmcb_block->vmcb_paddr[i];
		svm->vcpu.arch.guest_state_protected = true;
	}

e_free_shadow_vmcb_block:
	kfree(shadow_vmcb_block);
e_free_secure_vmcb_block:
	kfree(secure_vmcb_block);
e_free_trans_data:
	vfree(trans_data);
e_free_trans_block:
	kfree(trans_block);
e_free_hdr:
	kfree(hdr);
exit:
	return ret;
}

static void csv_mark_page_dirty(struct kvm_vcpu *vcpu, gva_t gpa,
				unsigned long npages)
{
	gfn_t gfn;
	gfn_t gfn_end;

	gfn = gpa >> PAGE_SHIFT;
	gfn_end = gfn + npages;
	spin_lock(&vcpu->kvm->mmu_lock);
	for (; gfn < gfn_end; gfn++)
		kvm_vcpu_mark_page_dirty(vcpu, gfn);
	spin_unlock(&vcpu->kvm->mmu_lock);
}

static int __csv3_mmio_page_fault(struct kvm_vcpu *vcpu,
				  gva_t gpa, u32 error_code)
{
	int r = 0;
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);
	union csv_page_attr page_attr = {.mmio = 1};
	union csv_page_attr page_attr_mask = {.mmio = 1};
	struct csv_data_update_npt *update_npt;
	int psp_ret;

	update_npt = kzalloc(sizeof(*update_npt), GFP_KERNEL);
	if (!update_npt) {
		WARN_ONCE(1, "Failure allocate npt command\n");
		r = -ENOMEM;
		goto exit;
	}

	csv_init_update_npt(update_npt, gpa, error_code,
			    kvm_svm->sev_info.handle);
	update_npt->page_attr = page_attr.val;
	update_npt->page_attr_mask = page_attr_mask.val;
	update_npt->level = CSV_PG_LEVEL_4K;

	r = csv_issue_cmd(vcpu->kvm, CSV_CMD_UPDATE_NPT, update_npt, &psp_ret);

	if (psp_ret != SEV_RET_SUCCESS) {
		WARN_ONCE(1, "Failure update NPT\n");
		r = -EFAULT;
	}

	kfree(update_npt);
exit:
	/* If CSV_CMD_UPDATE_NPT command is success, then return 1 and resume
	 * the guest.
	 */
	return r == 0 ? 1 : r;
}

static int __csv3_mmio_page_fault_ex(struct kvm_vcpu *vcpu,
				     gva_t gpa, u32 error_code)
{
	int r = 0;
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);
	union csv_page_attr page_attr = {.mmio = 1};
	union csv_page_attr page_attr_mask = {.mmio = 1};
	struct csv3_data_update_npt_ex *update_npt;
	int psp_ret;

	update_npt = kzalloc(sizeof(*update_npt), GFP_KERNEL);
	if (!update_npt) {
		WARN_ONCE(1, "Failure allocate npt command\n");
		r = -ENOMEM;
		goto exit;
	}

	csv3_init_update_npt_ex(update_npt, gpa, error_code,
				kvm_svm->sev_info.handle);
	update_npt->page_attr = page_attr.val;
	update_npt->page_attr_mask = page_attr_mask.val;
	update_npt->level = CSV_PG_LEVEL_4K;

	r = csv_issue_cmd(vcpu->kvm, CSV3_CMD_UPDATE_NPT_EX, update_npt, &psp_ret);

	if (psp_ret != SEV_RET_SUCCESS) {
		WARN_ONCE(1, "Failure update NPT\n");
		r = -EFAULT;
	}

	kfree(update_npt);
exit:
	/* If CSV3_CMD_UPDATE_NPT_EX command is success, then return 1 and
	 * resume the guest.
	 */
	return r == 0 ? 1 : r;
}

static int csv3_mmio_page_fault(struct kvm_vcpu *vcpu, gva_t gpa, u32 error_code)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(vcpu->kvm)->csv_info;

	if (csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_NPT_EX)
		return __csv3_mmio_page_fault_ex(vcpu, gpa, error_code);
	else
		return __csv3_mmio_page_fault(vcpu, gpa, error_code);
}

static int __csv3_page_fault(struct kvm_vcpu *vcpu, gva_t gpa,
			     u32 error_code, struct kvm_memory_slot *slot,
			     int *psp_ret_ptr, kvm_pfn_t pfn, u32 level)
{
	int r = 0;
	struct csv_data_update_npt *update_npt;
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);
	int psp_ret = 0;

	update_npt = kzalloc(sizeof(*update_npt), GFP_KERNEL);
	if (!update_npt) {
		r = -ENOMEM;
		goto exit;
	}

	csv_init_update_npt(update_npt, gpa, error_code,
			    kvm_svm->sev_info.handle);

	update_npt->spa = pfn << PAGE_SHIFT;
	update_npt->level = level;

	if (!csv_is_mmio_pfn(pfn))
		update_npt->spa |= sme_me_mask;

	r = csv_issue_cmd(vcpu->kvm, CSV_CMD_UPDATE_NPT, update_npt, &psp_ret);

	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
	kvm_flush_remote_tlbs(vcpu->kvm);

	csv_mark_page_dirty(vcpu, update_npt->gpa, update_npt->npages);

	if (psp_ret_ptr)
		*psp_ret_ptr = psp_ret;

	kfree(update_npt);
exit:
	/* If CSV_CMD_UPDATE_NPT command is success, then return 1 and resume
	 * the guest.
	 */
	return r == 0 ? 1 : r;
}

static int __csv3_page_fault_ex(struct kvm_vcpu *vcpu, gva_t gpa,
				u32 error_code, struct kvm_memory_slot *slot,
				int *psp_ret_ptr, kvm_pfn_t pfn, u32 level)
{
	int r = 0;
	struct csv3_data_update_npt_ex *update_npt;
	struct kvm_svm *kvm_svm = to_kvm_svm(vcpu->kvm);
	struct kvm_csv_info *csv = &to_kvm_svm_csv(vcpu->kvm)->csv_info;
	int psp_ret = 0;

	update_npt = kzalloc(sizeof(*update_npt), GFP_KERNEL);
	if (!update_npt) {
		r = -ENOMEM;
		goto exit;
	}

	csv3_init_update_npt_ex(update_npt, gpa, error_code,
				kvm_svm->sev_info.handle);

	update_npt->spa = pfn << PAGE_SHIFT;
	update_npt->level = level;

	if (!csv_is_mmio_pfn(pfn))
		update_npt->spa |= sme_me_mask;

	r = csv_issue_cmd(vcpu->kvm, CSV3_CMD_UPDATE_NPT_EX, update_npt, &psp_ret);

	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
	kvm_flush_remote_tlbs(vcpu->kvm);

	csv_mark_page_dirty(vcpu, update_npt->gpa, update_npt->npages);

	if (psp_ret_ptr)
		*psp_ret_ptr = psp_ret;

	/* If CSV3_CMD_UPDATE_NPT_EX command is fail, then return error to the
	 * caller.
	 */
	if (r)
		goto exit;

	if (update_npt->type == CSV3_UPDATE_NPT_TYPE_SECURE_CALL &&
	    (csv->secure_call_exit_enabled & KVM_CSV3_SECURE_CALL_PG_ENC_DEC_MASK) &&
	    (update_npt->sc_type == CSV_SECURE_CMD_ENC ||
	     update_npt->sc_type == CSV_SECURE_CMD_DEC)) {
		bool enc = update_npt->sc_type == CSV_SECURE_CMD_ENC ? true : false;

		vcpu->run->exit_reason = KVM_EXIT_CSV3_SECURE_CALL;
		vcpu->run->secure_call.type =
			enc ? KVM_CSV3_SECURE_CALL_PG_ENC : KVM_CSV3_SECURE_CALL_PG_DEC;
		vcpu->run->secure_call.enc_dec_info.gpa = update_npt->sc_gpa;
		vcpu->run->secure_call.enc_dec_info.size = update_npt->sc_size;
		vcpu->run->secure_call.enc_dec_info.smr_size =
							1 << csv_get_smr_entry_shift();
		vcpu->run->secure_call.enc_dec_info.enc = enc ? 1 : 0;

		/* Indicate exit to userspace. */
		r = 0;
	} else {
		/* Indicate resume the guest. */
		r = 1;
	}
exit:
	kfree(update_npt);

	return r;
}

static int csv_pin_shared_memory_locked(struct kvm_vcpu *vcpu,
					struct kvm_memory_slot *slot,
					gfn_t gfn,
					kvm_pfn_t *pfn)
{
	u64 hva;
	kvm_pfn_t tmp_pfn;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct shared_page *sp;
	unsigned int pg_off;
	bool write = !(slot->flags & KVM_MEM_READONLY);
	bool is_dma_pinned;

	tmp_pfn = __gfn_to_pfn_memslot(slot, gfn, false, NULL, write, NULL);
	if (unlikely(is_error_pfn(tmp_pfn))) {
		WARN_ONCE(1, "Invalid pfn\n");
		return -EINVAL;
	}

	if (csv_is_mmio_pfn(tmp_pfn)) {
		*pfn = tmp_pfn;
		return 0;
	}

	hva = __gfn_to_hva_memslot(slot, gfn);

	is_dma_pinned = page_maybe_dma_pinned(pfn_to_page(tmp_pfn));
	kvm_release_pfn_clean(tmp_pfn);
	if (is_dma_pinned) {
		/*
		 * If we have already pinned the page when traversing the
		 * memslot, and the pinned page is part of a compound page that
		 * tracked by shared page entry, we must set the corresponding
		 * bit in the @bitmap to reflect that this subpage is shared
		 * memory for CSV3 VM.
		 *
		 * This ensures that all 4K subpages within a compound page can
		 * be accurately tracked, preventing premature removal of pages
		 * that are still be shared memory.
		 */
		shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, NULL);
		*pfn = tmp_pfn;
		return 0;
	}

	/*
	 * If the shared page manager does not already track @hva:
	 *   - Pin the page using pin_user_pages();
	 *   - Allocate a new shared_page entry, if the pinned page is part of
	 *     a compound page, allocate a @bitmap and set the bit corresponding
	 *     to this 4K subpage.
	 *
	 * If the @hva is already tracked by the manager, set the corresponding
	 * bit in the @bitmap.
	 */
	sp = shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, NULL);
	if (unlikely(sp)) {
		pr_err_ratelimited("%s: not pinned but in the tree\n", __func__);
		pg_off = (hva & ~sp->track_hva) >> PAGE_SHIFT;
		*pfn = page_to_pfn(sp->track_page) + pg_off;
	} else {
		struct shared_page *old_sp;
		struct page *page;
		int npinned;

		mmap_write_lock(current->mm);
		npinned = pin_user_pages(hva, 1, FOLL_WRITE | FOLL_LONGTERM, &page, NULL);
		mmap_write_unlock(current->mm);
		if (npinned != 1) {
			pr_err_ratelimited("Failure pin gfn:0x%llx\n", gfn);
			return -ENOMEM;
		}

		sp = alloc_shared_page_entry(csv, hva, page);
		if (!sp) {
			unpin_user_page(page);
			return -ENOMEM;
		}

		if (insert_shared_page_entry_locked(&csv->sp_mgr, sp, &old_sp)) {
			*pfn = page_to_pfn(page);
		} else {
			pr_err_ratelimited("%s: search fail but insertion found\n", __func__);
			unpin_user_page(page);
			free_shared_page_entry(csv, sp);

			shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, old_sp);

			pg_off = (hva & ~old_sp->track_hva) >> PAGE_SHIFT;
			*pfn = page_to_pfn(old_sp->track_page) + pg_off;
		}
	}

	return 0;
}

static int csv_mapping_level(struct kvm_vcpu *vcpu, gfn_t gfn, kvm_pfn_t pfn,
			     struct kvm_memory_slot *slot)
{
	unsigned long hva;
	int level;
	pte_t *pte;
	int page_num;
	gfn_t gfn_base;

	if (csv_is_mmio_pfn(pfn)) {
		level = PG_LEVEL_4K;
		goto end;
	}

	if (!PageCompound(pfn_to_page(pfn))) {
		level = PG_LEVEL_4K;
		goto end;
	}

	level = PG_LEVEL_2M;
	page_num = KVM_PAGES_PER_HPAGE(level);
	gfn_base = gfn & ~(page_num - 1);

	/*
	 * 2M aligned guest address in memslot.
	 */
	if ((gfn_base < slot->base_gfn) ||
	    (gfn_base + page_num > slot->base_gfn + slot->npages)) {
		level = PG_LEVEL_4K;
		goto end;
	}

	/*
	 * hva in memslot is 2M aligned.
	 */
	if (__gfn_to_hva_memslot(slot, gfn_base) & ~PMD_PAGE_MASK) {
		level = PG_LEVEL_4K;
		goto end;
	}

	hva = __gfn_to_hva_memslot(slot, gfn);
	pte = lookup_address_in_mm(vcpu->kvm->mm, hva, &level);
	if (unlikely(!pte)) {
		level = PG_LEVEL_4K;
		goto end;
	}

	/*
	 * Firmware supports 2M/4K level.
	 */
	level = level > PG_LEVEL_2M ? PG_LEVEL_2M : level;

end:
	return to_csv_pg_level(level);
}

static int csv3_page_fault(struct kvm_vcpu *vcpu,
			   struct kvm_memory_slot *slot,
			   gfn_t gfn, u32 error_code)
{
	int ret = 0;
	int psp_ret = 0;
	int level;
	kvm_pfn_t pfn = KVM_PFN_NOSLOT;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(vcpu->kvm)->csv_info;

	if (error_code & PFERR_PRESENT_MASK)
		level = CSV_PG_LEVEL_4K;
	else {
		mutex_lock(&csv->sp_lock);
		ret = csv_pin_shared_memory_locked(vcpu, slot, gfn, &pfn);
		mutex_unlock(&csv->sp_lock);
		if (ret) {
			/* Resume guest to retry #NPF. */
			if (ret == -ENOMEM)
				ret = 1;
			goto exit;
		}

		level = csv_mapping_level(vcpu, gfn, pfn, slot);
	}

	if (csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_NPT_EX)
		ret = __csv3_page_fault_ex(vcpu, gfn << PAGE_SHIFT, error_code, slot,
					   &psp_ret, pfn, level);
	else
		ret = __csv3_page_fault(vcpu, gfn << PAGE_SHIFT, error_code, slot,
					&psp_ret, pfn, level);

	if (psp_ret != SEV_RET_SUCCESS) {
		WARN_ONCE(1, "Failure update NPT\n");
		ret = -EFAULT;
	}
exit:
	return ret;
}

/**
 * csv_release_shared_memory - Release shared pages and notify userspace to
 *			       madvise.
 * @params: Pointer to ioctl input/output structure, containing GPA range
 *	    and output fields.
 *
 * This function processes the KVM_CSV3_RELEASE_SHARED_MEMORY command by:
 *   - Iterating over each page in the specified GPA range;
 *   - For each page, attempting to remove it from the shared page manager;
 *   - If successful, updating the total number of unpinned pages;
 *   - Setting the start_hva to the first HVA that needs madvise (for
 *     contiguous range).
 *
 * The kernel ensures that:
 *   - Only one thread can modify the shared page manager at a time (via
 *     sp_lock);
 *   - The start_hva is set to the lowest HVA among all removed pages;
 *   - Userspace VMM should call madvise() on [start_hva, start_hva +
 *     unpinned * PAGE_SIZE).
 *
 * Return: 0 on success, negative error code on failure (though none are
 * currently returned).
 */
static int csv_release_shared_memory(struct kvm *kvm,
				     struct kvm_csv_handle_memory *params)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct shared_page *sp;
	u64 hva;
	gfn_t gfn = gpa_to_gfn(params->gpa);
	u32 num_pages = params->num_pages;
	int i;

	/* Initialize output fields */
	params->start_hva = 0;
	params->unpinned = 0;
	params->handled0 = 0;

	/* Protect shared page manager from concurrent access */
	mutex_lock(&csv->sp_lock);
	for (i = 0; i < num_pages; i++, gfn++) {
		hva = gfn_to_hva(kvm, gfn);

		if (unlikely(!params->start_hva))
			params->start_hva = hva;

		/*
		 * The madvise requested from user space need provide hva and
		 * length. This handler should fill back a range of contiguous
		 * hva. We maintain start_hva as the smallest hva among all
		 * released pages.
		 */
		if ((params->start_hva >> PAGE_SHIFT)
			+ params->unpinned != (hva >> PAGE_SHIFT))
			break;

		/*
		 * Try to remove the shared_page entry corresponding to this
		 * hva. If remove_shared_page_entry_locked() found and removed
		 * the entry from manager tree, it will return the entry, and
		 * we can release the page tracked by the entry.
		 */
		sp = remove_shared_page_entry_locked(&csv->sp_mgr, hva);
		if (sp) {
			/* Update @unpinned only when an sp is removed */
			params->unpinned += 1U << sp->order;

			/*
			 * If this page is a tail page of a compound page, its
			 * HVA may be smaller than the head page's HVA. Since
			 * madvise must cover the entire compound page, we
			 * update start_hva to the smallest HVA in the range.
			 */
			if (sp->track_hva < params->start_hva) {
				params->handled0 = (1U << sp->order) -
					((params->start_hva - sp->track_hva) >> PAGE_SHIFT);
				params->start_hva = sp->track_hva;
			} else {
				params->handled0 += 1U << sp->order;
			}

			if (page_maybe_dma_pinned(sp->track_page))
				unpin_user_page(sp->track_page);
			else
				pr_err_ratelimited("%s: the track_page was not pinned\n",
						   __func__);
			free_shared_page_entry(csv, sp);
		} else {
			break;
		}

		cond_resched();
	}
	mutex_unlock(&csv->sp_lock);

	return 0;
}

static inline unsigned long get_vma_flags(unsigned long addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long vm_flags = 0;

	down_read(&mm->mmap_lock);
	vma = find_vma(mm, addr);
	if (vma && vma->vm_start <= addr)
		vm_flags = vma->vm_flags;
	up_read(&mm->mmap_lock);

	return vm_flags;
}

#define RETRY_CSV3_PIN_MAX	5
#define RETRY_CSV3_ALLOC_SP_MAX	5

/**
 * csv_get_shared_memory - Pin a number of pages specified in the input.
 * @params: Pointer to ioctl input/output structure, containing GPA range and
 *	    output field.
 *
 * This function processes the KVM_CSV3_GET_SHARED_MEMORY command by:
 *   - Iterating over each page in the specified GPA range;
 *   - For each page, checking if it is already tracked in the shared page
 *     manager;
 *   - If not, attempting to pin it and create a new entry;
 *   - Incrementing @pinned for every page that is successfully pinned.
 *   - Incrementing @handled for every GPA that is handled.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int csv_get_shared_memory(struct kvm *kvm,
				 struct kvm_csv_handle_memory *params)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct shared_page *sp, *old_sp;
	struct page *page;
	unsigned long vm_flags = 0;
	u64 hva;
	gfn_t gfn = gpa_to_gfn(params->gpa);
	u32 num_pages = params->num_pages;
	enum csv_smr_source source = get_csv_smr_source();
	int i, npinned, try_pin, try_alloc_sp;
	int ret = 0;

	/* Initialize output field */
	params->pinned = 0;
	params->handled1 = 0;

	/* Protect shared page manager from concurrent access */
	mutex_lock(&csv->sp_lock);
	for (i = 0; i < num_pages; i++, gfn++) {
		hva = gfn_to_hva(kvm, gfn);
		if (kvm_is_error_hva(hva)) {
			/*
			 * If the HVA is invalid (e.g., not mapped), skip this
			 * page. This prevents unnecessary pinning attempts and
			 * continues processing remaining pages.
			 */
			params->handled1++;
			continue;
		}

		if (unlikely(!vm_flags))
			vm_flags = get_vma_flags((unsigned long)hva);

		/*
		 * Reject hugetlbfs-backed pages to prevent severe page
		 * migration pressure when 2M hugetlb is used with CMA.
		 */
		if (!vm_flags ||
		    ((vm_flags & VM_HUGETLB) && (source != USE_HUGETLB))) {
			ret = -EINVAL;
			goto out;
		}

		sp = shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, NULL);
		if (sp) {
			params->handled1++;
			continue;
		}

		try_pin = 0;
		try_alloc_sp = 0;
retry_pin:
		/*
		 * The page is not yet tracked. We need to pin it and create a
		 * new entry. Acquire mm_write_lock to safely pin the page.
		 */
		mmap_write_lock(current->mm);
		npinned = pin_user_pages(hva, 1, FOLL_WRITE | FOLL_LONGTERM, &page, NULL);
		mmap_write_unlock(current->mm);
		if (npinned != 1) {
			if (++try_pin <= RETRY_CSV3_PIN_MAX)
				goto retry_pin;
			pr_err_ratelimited("%s: try pin fail\n", __func__);
			break;
		}

retry_alloc_sp:
		sp = alloc_shared_page_entry(csv, hva, page);
		if (!sp) {
			if (++try_alloc_sp <= RETRY_CSV3_ALLOC_SP_MAX)
				goto retry_alloc_sp;
			pr_err_ratelimited("%s: try alloc sp fail\n", __func__);
			unpin_user_page(page);
			break;
		}

		if (!insert_shared_page_entry_locked(&csv->sp_mgr, sp, &old_sp)) {
			pr_err_ratelimited("%s: search fail but insertion found\n",
					   __func__);
			unpin_user_page(page);
			free_shared_page_entry(csv, sp);

			shared_page_entry_set_bit_locked(&csv->sp_mgr, hva, old_sp);
		} else {
			/* Update @pinned only upon insertion of a new sp */
			params->pinned += 1U << sp->order;
		}
		params->handled1++;

		cond_resched();
	}

out:
	mutex_unlock(&csv->sp_lock);

	return ret;
}

static void csv_vm_destroy(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_vcpu *vcpu;
	struct list_head *smr_head = &csv->smr_list;
	struct shared_page *sp;
	struct rb_node *node;
	unsigned long i = 0;
	enum csv_smr_source source = get_csv_smr_source();

	if (csv3_guest(kvm)) {
		mutex_lock(&csv->sp_lock);
		while ((node = rb_first(&csv->sp_mgr.root))) {
			sp = rb_entry(node, struct shared_page, node);
			/* Remove shared page entry from the manager tree */
			rb_erase(&sp->node, &csv->sp_mgr.root);
			/* Update shared page statistics */
			csv->sp_mgr.count--;
			csv->sp_mgr.nr_pages -= 1UL << sp->order;
			update_csv_share_mem(sp->track_page, false);
			/* Putback the tracked page to system */
			if (page_maybe_dma_pinned(sp->track_page))
				unpin_user_page(sp->track_page);
			else
				pr_err_ratelimited("%s: the track_page was not pinned\n",
						   __func__);
			free_shared_page_entry(csv, sp);

			cond_resched();
		}
		mutex_unlock(&csv->sp_lock);

		if (csv->sp_mgr.count || csv->sp_mgr.nr_pages)
			pr_err("%s: SP_MGR_ERR: track fault, cnt:%lld nr_pages:0x%lx\n",
			       __func__, csv->sp_mgr.count, csv->sp_mgr.nr_pages);

		kmem_cache_destroy(csv->sp_slab);
		csv->sp_slab = NULL;

		kvm_for_each_vcpu(i, vcpu, kvm) {
			struct vcpu_svm *svm = to_svm(vcpu);
			svm->vmcb_pa = __sme_pa(svm->vmcb);
		}
	}

	if (likely(csv_x86_ops.vm_destroy))
		csv_x86_ops.vm_destroy(kvm);

	if (!csv3_guest(kvm))
		return;

	/* free secure memory region */
	if (!list_empty(smr_head))
		csv3_free_smr_list(kvm);

	/* Free hugetlb if CSV3 private memory is allocated from 1G hugetlb */
	if (source == USE_HUGETLB)
		csv3_free_1G_hugetlb_pages(kvm);

#ifdef CONFIG_SYSFS
	atomic_long_sub(csv->npt_size, &csv3_npt_size);
	atomic_long_sub(csv->pri_mem, &csv3_pri_mem);
#endif
}

static int csv_handle_page_fault(struct kvm_vcpu *vcpu, gpa_t gpa,
				 u32 error_code)
{
	gfn_t gfn = gpa_to_gfn(gpa);
	struct kvm_memory_slot *slot = gfn_to_memslot(vcpu->kvm, gfn);
	struct kvm_csv_info *csv = &to_kvm_svm_csv(vcpu->kvm)->csv_info;
	int ret;

	/* Retry PF if the GPA hit a memslot that is being deleted or moved. */
	if (slot && (slot->flags & KVM_MEMSLOT_INVALID))
		return 1;

	if (kvm_is_visible_memslot(slot))
		ret = csv3_page_fault(vcpu, slot, gfn, error_code);
	else {
		if ((csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_NPT_EX) &&
		    ((csv->tom != 0 && gpa < csv->tom) ||
		     (csv->tom2 != 0 && (4ull << 30) <= gpa && gpa < csv->tom2))) {
			/* Retry PF from guest */
			return 1;
		}
		ret = csv3_mmio_page_fault(vcpu, gpa, error_code);
	}

	return ret;
}

static int csv_handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 exit_code = svm->vmcb->control.exit_code;
	int ret = -EIO;

	/*
	 * NPF for csv is dedicated.
	 */
	if (csv3_guest(vcpu->kvm) && exit_code == SVM_EXIT_NPF) {
		gpa_t gpa = __sme_clr(svm->vmcb->control.exit_info_2);
		u64 error_code = svm->vmcb->control.exit_info_1;

		ret = csv_handle_page_fault(vcpu, gpa, error_code);
	} else {
		if (likely(csv_x86_ops.handle_exit))
			ret = csv_x86_ops.handle_exit(vcpu, exit_fastpath);
	}

	return ret;
}

static void csv_guest_memory_reclaimed(struct kvm *kvm)
{
	if (!csv3_guest(kvm)) {
		if (likely(csv_x86_ops.guest_memory_reclaimed))
			csv_x86_ops.guest_memory_reclaimed(kvm);
	}
}

static int csv_handle_memory(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv_handle_memory params;
	int r = -EINVAL;

	if (!csv3_guest(kvm) ||
	    !(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_SP_MGR))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params)))
		return -EFAULT;

	switch (params.opcode) {
	case KVM_CSV3_RELEASE_SHARED_MEMORY:
		r = csv_release_shared_memory(kvm, &params);
		break;
	case KVM_CSV3_GET_SHARED_MEMORY:
		r = csv_get_shared_memory(kvm, &params);
		break;
	default:
		goto out;
	}

	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params,
			 sizeof(params)))
		return -EFAULT;

out:
	return r;
};

static int csv_launch_secret(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct sev_data_launch_secret *data;
	struct kvm_sev_launch_secret params;
	struct page **pages;
	void *blob, *hdr;
	unsigned long n, i;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	if (!csv3_guest(kvm) ||
	    !(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_INJ_SECRET)) {
		pages = hygon_kvm_hooks.sev_pin_memory(kvm, params.guest_uaddr,
						       params.guest_len, &n, FOLL_WRITE);
		if (IS_ERR(pages)) {
			ret = PTR_ERR(pages);
			goto e_free_data;
		}

		/*
		 * Flush (on non-coherent CPUs) before LAUNCH_SECRET encrypts pages in
		 * place; the cache may contain the data that was written unencrypted.
		 */
		hygon_kvm_hooks.sev_clflush_pages(pages, n);

		/*
		 * The secret must be copied into contiguous memory region, lets verify
		 * that userspace memory pages are contiguous before we issue command.
		 */
		if (hygon_kvm_hooks.get_num_contig_pages(0, pages, n) != n) {
			ret = -EINVAL;
			goto e_unpin_memory;
		}

		offset = params.guest_uaddr & (PAGE_SIZE - 1);
		data->guest_address = __sme_page_pa(pages[0]) + offset;
	} else {
		/* It's gpa for CSV3 guest */
		data->guest_address = params.guest_uaddr;
	}
	data->guest_len = params.guest_len;

	blob = psp_copy_user_blob(params.trans_uaddr, params.trans_len);
	if (IS_ERR(blob)) {
		ret = PTR_ERR(blob);
		goto e_unpin_memory;
	}

	data->trans_address = __psp_pa(blob);
	data->trans_len = params.trans_len;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto e_free_blob;
	}
	data->hdr_address = __psp_pa(hdr);
	data->hdr_len = params.hdr_len;

	data->handle = sev->handle;
	ret = hygon_kvm_hooks.sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_SECRET,
							data, &argp->error);

	kfree(hdr);

e_free_blob:
	kfree(blob);
e_unpin_memory:
	if (!csv3_guest(kvm) ||
	    !(csv->inuse_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_INJ_SECRET)) {
		/* content of memory is updated, mark pages dirty */
		for (i = 0; i < n; i++) {
			set_page_dirty_lock(pages[i]);
			mark_page_accessed(pages[i]);
		}
		hygon_kvm_hooks.sev_unpin_memory(kvm, pages, n);
	}
e_free_data:
	kfree(data);
	return ret;
}

static int csv_mem_enc_op(struct kvm *kvm, void __user *argp)
{
	struct kvm_sev_cmd sev_cmd;
	int r = -EINVAL;

	if (!hygon_kvm_hooks.sev_hooks_installed ||
	    !(*hygon_kvm_hooks.sev_enabled))
		return -ENOTTY;

	if (!argp)
		return 0;

	if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (sev_cmd.id) {
	case KVM_SEV_LAUNCH_SECRET:
		r = csv_launch_secret(kvm, &sev_cmd);
		break;
	case KVM_CSV3_INIT:
		r = csv_guest_init(kvm, &sev_cmd);
		break;
	case KVM_CSV3_LAUNCH_ENCRYPT_DATA:
		r = csv3_launch_encrypt_data(kvm, &sev_cmd);
		break;
	case KVM_CSV3_LAUNCH_ENCRYPT_VMCB:
		r = csv_launch_encrypt_vmcb(kvm, &sev_cmd);
		break;
	case KVM_CSV3_LAUNCH_FINISH_EX:
		r = csv3_launch_finish_ex(kvm, &sev_cmd);
		break;
	case KVM_CSV3_SEND_ENCRYPT_DATA:
		r = csv_send_encrypt_data(kvm, &sev_cmd);
		break;
	case KVM_CSV3_SEND_ENCRYPT_CONTEXT:
		r = csv_send_encrypt_context(kvm, &sev_cmd);
		break;
	case KVM_CSV3_RECEIVE_ENCRYPT_DATA:
		r = csv_receive_encrypt_data(kvm, &sev_cmd);
		break;
	case KVM_CSV3_RECEIVE_ENCRYPT_CONTEXT:
		r = csv_receive_encrypt_context(kvm, &sev_cmd);
		break;
	case KVM_CSV3_HANDLE_MEMORY:
		r = csv_handle_memory(kvm, &sev_cmd);
		break;
	case KVM_CSV3_SET_GUEST_PRIVATE_MEMORY:
		r = csv3_set_guest_private_memory(kvm, &sev_cmd);
		break;
	default:
		mutex_unlock(&kvm->lock);
		if (likely(csv_x86_ops.mem_enc_op))
			r = csv_x86_ops.mem_enc_op(kvm, argp);
		goto out;
	}

	mutex_unlock(&kvm->lock);

	if (copy_to_user(argp, &sev_cmd, sizeof(struct kvm_sev_cmd)))
		r = -EFAULT;

out:
	return r;
}

/**
 * When userspace recognizes these extensions, it is suggested that the userspace
 * enables these extensions through KVM_ENABLE_CAP, so that both the userspace
 * and KVM can utilize these extensions.
 */
static int csv_get_hygon_coco_extension(struct kvm *kvm)
{
	struct kvm_csv_info *csv;
	size_t len = sizeof(uint32_t);
	int ret = 0;

	if (!kvm || !csv3_guest(kvm))
		return 0;

	csv = &to_kvm_svm_csv(kvm)->csv_info;

	if (csv->fw_ext_valid == false) {
		ret = csv_get_extension_info(&csv->fw_ext, &len);

		if (ret == -ENODEV) {
			pr_err("Unable to interact with CSV firmware!\n");
			return 0;
		} else if (ret == -EINVAL) {
			pr_err("Need %ld bytes to record fw extension!\n", len);
			return 0;
		}

		csv->fw_ext_valid = true;
	}

	/* The kvm_ext field of kvm_csv_info is filled in only if the fw_ext
	 * field of kvm_csv_info is valid.
	 */
	if (csv->kvm_ext_valid == false) {
		if (csv3_guest(kvm)) {
			csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_SET_PRIV_MEM;
			if (csv->fw_ext & CSV_EXT_CSV3_MULT_LUP_DATA)
				csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_MULT_LUP_DATA;
			if (csv->fw_ext & CSV_EXT_CSV3_INJ_SECRET)
				csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_INJ_SECRET;
			if (csv->fw_ext & CSV_EXT_CSV3_LFINISH_EX)
				csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_LFINISH_EX;
			csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_SP_MGR;
			/* Expose CSV3_NPT_EX cap only when the private memory
			 * of CSV3 VM is from 1G hugetlb.
			 */
			if ((csv->fw_ext & CSV_EXT_CSV3_NPT_EX) &&
			    get_csv_smr_source() == USE_HUGETLB)
				csv->kvm_ext |= KVM_CAP_HYGON_COCO_EXT_CSV3_NPT_EX;
		}
		csv->kvm_ext_valid = true;
	}

	/* Return extension info only if both fw_ext and kvm_ext fields of
	 * kvm_csv_info are valid.
	 */
	pr_debug("%s: fw_ext=%#x kvm_ext=%#x\n",
		 __func__, csv->fw_ext, csv->kvm_ext);
	return (int)csv->kvm_ext;
}

/**
 * Return 0 means KVM accept the negotiation from userspace. Both the
 * userspace and KVM should not utilise extensions if failed to negotiate.
 */
static int csv_enable_hygon_coco_extension(struct kvm *kvm, u32 arg)
{
	struct kvm_csv_info *csv;

	if (!kvm)
		return -EINVAL;

	csv = &to_kvm_svm_csv(kvm)->csv_info;

	/* Negotiation is accepted only if both the fw_ext and kvm_ext fields
	 * of kvm_csv_info are valid and the virtual machine is a CSV3 guest.
	 */
	if (csv->fw_ext_valid && csv->kvm_ext_valid && csv3_guest(kvm)) {
		csv->inuse_ext = csv->kvm_ext & arg;

		/* Use CSV3_NPT_EX cap only if the secure_call_exit is enabled
		 * by userspace.
		 */
		if (csv->secure_call_exit_enabled == 0)
			csv->inuse_ext &= ~KVM_CAP_HYGON_COCO_EXT_CSV3_NPT_EX;

		pr_debug("%s: inuse_ext=%#x\n", __func__, csv->inuse_ext);
		return csv->inuse_ext;
	}

	/* Userspace should not utilise the extensions */
	return -EINVAL;
}

/**
 * Enable CSV3 secure call exit to userspace.
 * This func should be called between csv_get_hygon_coco_extension() and
 * csv_enable_hygon_coco_extension().
 */
static int csv_enable_exit_csv3_secure_call(struct kvm *kvm, u64 arg)
{
	struct kvm_csv_info *csv;

	if (!kvm)
		return -EINVAL;

	csv = &to_kvm_svm_csv(kvm)->csv_info;

	/* Enabling secure_call_exit only when:
	 *   - this is a CSV3 VM, and
	 *   - firmware and kvm support CSV3 NPT_EX, and
	 *   - the secure call mask is valid
	 */
	if (!csv3_guest(kvm) ||
	    !csv->kvm_ext_valid ||
	    !(csv->kvm_ext & KVM_CAP_HYGON_COCO_EXT_CSV3_NPT_EX) ||
	    (arg & ~KVM_EXIT_CSV3_SECURE_CALL_VALID_MASK))
		return -EINVAL;

	csv->secure_call_exit_enabled = arg;
	return 0;
}

#define CSV_BIT		BIT(30)

void __init csv_init(struct kvm_x86_ops *ops)
{
	unsigned int eax, ebx, ecx, edx;

	/*
	 * Hygon CSV is indicated by X86_FEATURE_SEV, return directly if CSV
	 * is unsupported.
	 */
	if (!boot_cpu_has(X86_FEATURE_SEV))
		return;

	memcpy(&csv_x86_ops, ops, sizeof(struct kvm_x86_ops));

	ops->mem_enc_op = csv_mem_enc_op;
	ops->vm_size = sizeof(struct kvm_svm_csv);
	ops->get_hygon_coco_extension = csv_get_hygon_coco_extension;
	ops->enable_hygon_coco_extension = csv_enable_hygon_coco_extension;
	ops->enable_exit_csv3_secure_call = csv_enable_exit_csv3_secure_call;

	/* Retrieve CSV CPUID information */
	cpuid(0x8000001f, &eax, &ebx, &ecx, &edx);
	if (boot_cpu_has(X86_FEATURE_SEV_ES) && (eax & CSV_BIT)) {
		ops->vm_destroy = csv_vm_destroy;
		ops->handle_exit = csv_handle_exit;
		ops->guest_memory_reclaimed = csv_guest_memory_reclaimed;
	}
}
