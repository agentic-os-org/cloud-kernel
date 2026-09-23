// SPDX-License-Identifier: GPL-2.0

#include <linux/list.h>
#include <linux/xarray.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/migrate.h>
#include <linux/memcontrol.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/page_dup.h>
#include <linux/cpuset.h>
#include <linux/swap.h>
#include <linux/sched/mm.h>

#include "internal.h"

DEFINE_STATIC_KEY_FALSE(duptext_enabled_key);
struct xarray dup_pages[MAX_NUMNODES];

#define DUPTEXT_REFRESH_KICK 0

struct duptext_refresh {
	struct delayed_work dwork;
	struct mm_struct *mm;
};

static void duptext_refresh_workfn(struct work_struct *work);

/* XXX copy_huge_page without cond_resched */
static void copy_huge_page(struct page *dst, struct page *src)
{
	int nr_pages;
	int i;

	nr_pages = thp_nr_pages(src);

	for (i = 0; i < nr_pages; i++)
		copy_highpage(dst + i, src + i);
}

static inline void attach_dup_page_private(struct page *dup_page,
					   struct page *page)
{
	set_page_private(dup_page, (unsigned long)page);
	SetPagePrivate(dup_page);
}

static inline void detach_dup_page_private(struct page *dup_page)
{
	ClearPagePrivate(dup_page);
	set_page_private(dup_page, 0);
}

static struct page *find_get_dup_page(struct page *page, int node)
{
	struct page *dup_page, *tmp_page;
	struct list_head *list;
	int nid = page_to_nid(page);

	XA_STATE(xas, &dup_pages[nid], page_to_pfn(page));

	rcu_read_lock();
repeat:
	dup_page = NULL;
	xas_reset(&xas);
	list = xas_load(&xas);
	if (xas_retry(&xas, list))
		goto repeat;

	if (!list)
		goto out;

	list_for_each_entry(tmp_page, list, lru) {
		if (page_to_nid(tmp_page) == node) {
			dup_page = tmp_page;
			break;
		}
	}

	if (dup_page && !page_cache_get_speculative(dup_page))
		goto repeat;

out:
	rcu_read_unlock();
	return dup_page;
}

static int add_to_dup_pages(struct page *new_page, struct page *page)
{
	struct list_head *list;
	unsigned long flags;
	int ret = 0;
	int nid = page_to_nid(page);

	XA_STATE(xas, &dup_pages[nid], page_to_pfn(page));

	get_page(new_page);
	xas_lock_irqsave(&xas, flags);

	/*
	 * Check the global enabled key inside xa_lock, in order to ensure
	 * this dup_page not to be added, or truncation not to miss this
	 * dup_page.
	 */
	if (!static_branch_likely(&duptext_enabled_key)) {
		ret = -EBUSY;
		goto out;
	}

	list = xas_load(&xas);
	if (!list) {
		list = kmalloc_node(sizeof(struct list_head), GFP_ATOMIC, nid);
		if (!list) {
			ret = -ENOMEM;
			goto out;
		}

		INIT_LIST_HEAD(list);
		xas_store(&xas, list);
	}

	new_page->mapping = page->mapping;
	new_page->index = page->index;
	attach_dup_page_private(new_page, page);
	SetPageDup(new_page);
	list_add(&new_page->lru, list);

	if (!PageDup(page))
		SetPageDup(page);
	__mod_node_page_state(page_pgdat(page), NR_DUPTEXT,
			      PageTransHuge(page) ? HPAGE_PMD_NR : 1);
	filemap_nr_duptext_add(page_mapping(page),
			       PageTransHuge(page) ? HPAGE_PMD_NR : 1);

out:
	xas_unlock_irqrestore(&xas, flags);
	if (unlikely(ret))
		put_page(new_page);
	return ret;
}

static void __delete_from_dup_pages(struct page *dup_page, struct page *page)
{
	struct address_space *mapping = page_mapping(dup_page);

	list_del(&dup_page->lru);
	ClearPageDup(dup_page);
	detach_dup_page_private(dup_page);
	dup_page->mapping = NULL;
	dup_page->index = 0;
	__mod_node_page_state(page_pgdat(page), NR_DUPTEXT,
			      PageTransHuge(page) ? -HPAGE_PMD_NR : -1);
	filemap_nr_duptext_add(mapping,
			       PageTransHuge(page) ? -HPAGE_PMD_NR : -1);
}

static bool delete_from_dup_pages(struct page *page, bool locked, bool ignore_mlock)
{
	struct page *tmp_page, *next_page;
	struct list_head *list, *old;
	unsigned long flags;
	enum ttu_flags ttu_flags = TTU_SYNC | TTU_BATCH_FLUSH;
	int nid = page_to_nid(page);

	XA_STATE(xas, &dup_pages[nid], page_to_pfn(page));

	xas_lock_irqsave(&xas, flags);
	list = xas_load(&xas);
	if (!list) {
		xas_unlock_irqrestore(&xas, flags);
		goto out;
	}
	xas_store(&xas, NULL);
	xas_unlock_irqrestore(&xas, flags);

	if (locked)
		ttu_flags |= TTU_RMAP_LOCKED;
	if (ignore_mlock)
		ttu_flags |= TTU_IGNORE_MLOCK;
	if (unlikely(PageTransHuge(page)))
		ttu_flags |= TTU_SPLIT_HUGE_PMD;

	list_for_each_entry_safe(tmp_page, next_page, list, lru) {
		VM_BUG_ON_PAGE(!page_dup_slave(tmp_page), tmp_page);

		/* Unmap before delete */
		if (page_mapped(tmp_page)) {
			lock_page(tmp_page);

			if (!try_to_unmap(tmp_page, ttu_flags)) {
				unlock_page(tmp_page);
				goto error;
			}

			unlock_page(tmp_page);
		}
	}

	try_to_unmap_flush();

	list_for_each_entry_safe(tmp_page, next_page, list, lru) {
		__delete_from_dup_pages(tmp_page, page);
		put_page(tmp_page);
	}

	kfree(list);
out:
	ClearPageDup(page);
	return true;

error:
	xas_lock_irqsave(&xas, flags);
repeat:
	xas_reset(&xas);
	old = xas_load(&xas);
	if (xas_retry(&xas, old))
		goto repeat;
	VM_BUG_ON_PAGE(old != NULL, page);
	xas_store(&xas, list);
	xas_unlock_irqrestore(&xas, flags);

	return false;
}

#ifdef CONFIG_MEMCG
static inline bool memcg_allow_duptext(struct mm_struct *mm)
{
	struct mem_cgroup *memcg;
	bool allow_duptext = false;

	memcg = get_mem_cgroup_from_mm(mm);
	if (memcg) {
		allow_duptext = memcg->allow_duptext;
		css_put(&memcg->css);
	}

	return allow_duptext;
}
static inline bool memcg_allow_duptext_refresh(struct mm_struct *mm)
{
	struct mem_cgroup *memcg;
	bool allow_duptext_refresh = false;

	memcg = get_mem_cgroup_from_mm(mm);
	if (memcg) {
		allow_duptext_refresh = memcg->allow_duptext_refresh;
		css_put(&memcg->css);
	}

	return allow_duptext_refresh;
}
static inline int duptext_target_node(struct mm_struct *mm, int page_node)
{
	struct mem_cgroup *memcg;
	nodemask_t allowed_nodes = cpuset_current_mems_allowed;
	int target_node = numa_node_id();

	memcg = get_mem_cgroup_from_mm(mm);
	if (memcg) {
		nodes_and(allowed_nodes, allowed_nodes, memcg->duptext_nodes);
		css_put(&memcg->css);
	}

	if (unlikely(nodes_empty(allowed_nodes)))
		return page_node;

	if (!node_isset(target_node, allowed_nodes)) {
		if (!node_isset(page_node, allowed_nodes))
			target_node = first_node(allowed_nodes);
		else
			target_node = page_node;
	}

	return target_node;
}
#else
static inline bool memcg_allow_duptext(struct mm_struct *mm)
{
	return true;
}
static inline bool memcg_allow_duptext_refresh(struct mm_struct *mm)
{
	return false;
}
static inline int duptext_target_node(struct mm_struct *mm, int page_node)
{
	return page_node;
}
#endif

bool __dup_page_suitable(struct vm_area_struct *vma, struct mm_struct *mm)
{
	/* Is executable file? */
	if ((vma->vm_flags & VM_EXEC) && vma->vm_file)  {
		struct inode *inode = vma->vm_file->f_inode;

		/* Is read-only ? */
		if (!S_ISREG(inode->i_mode) || inode_is_open_for_write(inode))
			return false;

		/* Memcg allow duptext ? */
		return memcg_allow_duptext(mm);
	}

	return false;
}

struct page *__dup_page_master(struct page *page)
{
	struct page *mhpage = NULL;
	struct page *hpage = compound_head(page);

	if (!page_dup_slave(hpage))
		return page;

	mhpage = (struct page *)page_private(hpage);

	return mhpage + (page - hpage);
}

bool __dup_page_mapped(struct page *page)
{
	struct page *tmp_page;
	struct list_head *list;
	bool ret = false;
	int nid = page_to_nid(page);

	XA_STATE(xas, &dup_pages[nid], 0);

	page = compound_head(page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (!page_dup_master(page))
		return false;
	xas_set(&xas, page_to_pfn(page));

	rcu_read_lock();
repeat:
	xas_reset(&xas);
	list = xas_load(&xas);
	if (xas_retry(&xas, list))
		goto repeat;

	if (!list)
		goto out;

	list_for_each_entry(tmp_page, list, lru) {
		if (page_mapped(tmp_page)) {
			ret = true;
			break;
		}
	}

out:
	rcu_read_unlock();
	return ret;
}

/* NOTE @page can be file THP head or tail page */
struct page *__dup_page(struct page *page, struct vm_area_struct *vma)
{
	struct page *dup_hpage = NULL;
	struct page *hpage = compound_head(page);
	struct mm_struct *mm = current->mm;
	int page_node = page_to_nid(hpage);
	int target_node;

	VM_BUG_ON_PAGE(!PageLocked(hpage), hpage);

	if (is_zero_page(hpage))
		return NULL;

	if (!__dup_page_suitable(vma, mm))
		return NULL;

	target_node = duptext_target_node(mm, page_node);
	if (likely(page_node == target_node))
		return NULL;

	if (unlikely(PageDirty(hpage) || PageWriteback(hpage) || !PageUptodate(hpage))) {
		struct duptext_refresh *refresh;
		int delay_ms;

		if (memcg_allow_duptext_refresh(mm) &&
		    !test_bit(DUPTEXT_REFRESH_KICK, &mm->duptext_flags)) {
			refresh = kmalloc(sizeof(struct duptext_refresh), GFP_ATOMIC);
			if (!refresh)
				return NULL;

			if (test_and_set_bit(DUPTEXT_REFRESH_KICK, &mm->duptext_flags)) {
				kfree(refresh);
				return NULL;
			}

			mmgrab(mm);
			refresh->mm = mm;
			INIT_DELAYED_WORK(&refresh->dwork, duptext_refresh_workfn);
			/*
			 * Dirty page lasts (dirty_writeback_interval +
			 * dirty_expire_interval) centiseconds at most,
			 * if the writeback time doesn't count.
			 */
			delay_ms = (dirty_writeback_interval + dirty_expire_interval) * 10;
			schedule_delayed_work(&refresh->dwork, msecs_to_jiffies(delay_ms));
		}

		return NULL;
	}

	if (page_has_private(hpage) &&
	    !try_to_release_page(hpage, GFP_ATOMIC))
		return NULL;

	if (page_dup_master(hpage))
		dup_hpage = find_get_dup_page(hpage, target_node);

	if (!dup_hpage) {
		/*
		 * XXX GFP_ATOMIC is used, since dup_page is called
		 * inside rcu lock in filemap_map_pages.
		 */
		gfp_t gfp_mask = GFP_ATOMIC | __GFP_THISNODE;
		unsigned int order = 0;
		struct page *new_hpage = NULL;
		int ret;

		if (PageTransHuge(hpage)) {
			gfp_mask |= __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NOWARN;
			order = HPAGE_PMD_ORDER;
		}

		new_hpage = __alloc_pages(gfp_mask, order, target_node);
		if (!new_hpage)
			return NULL;

		if (PageTransHuge(new_hpage)) {
			prep_transhuge_page(new_hpage);
			copy_huge_page(new_hpage, hpage);
		} else
			copy_highpage(new_hpage, hpage);

		ret = add_to_dup_pages(new_hpage, hpage);
		if (ret) {
			put_page(new_hpage);
			return NULL;
		}

		/*
		 * Paired with smp_mb() in do_dentry_open() to ensure
		 * i_writecount is up to date and the update to nr_duptext
		 * is visible. Ensures the page cache will be truncated if
		 * the file is opened writable.
		 */
		smp_mb();
		if (inode_is_open_for_write(hpage->mapping->host)) {
			__delete_from_dup_pages(new_hpage, hpage);
			put_page(new_hpage);
			return NULL;
		}

		dup_hpage = new_hpage;
	}

	/* dup_page is returned with refcount increased, but !PageLocked */
	return PageTransHuge(dup_hpage) ? find_subpage(dup_hpage, page_to_pgoff(page))
					: dup_hpage;
}

/*
 * NOTE Be careful if you want to call __dedup_page with ignore_mlock as false.
 *
 * Truncating routines should always succeed, perhaps with multiple attempts,
 * usually accompanied by unmap_mapping_range().  In orer to coordinate with
 * truncating, __dedup_page() should better succeed in this scenario, with
 * ignore_mlock as true.
 *
 * On the other hand, invalidating routines have __dup_page_mapped() check in
 * common helper, i.e., invalidate_inode_page(). That is to say, mapped slave
 * pages should not be invalidated irrespective of whether mlocked or not.
 *
 * Finally the only place currently where mlock is honoured is reclaiming
 * routines, e.g., shrink_page_list, where __dedup_page() can be called with
 * ignore_mlock as false.
 */
bool __dedup_page(struct page *page, bool locked, bool ignore_mlock)
{
	page = compound_head(page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (!page_dup_master(page))
		return true;
	return delete_from_dup_pages(page, locked, ignore_mlock);
}

static unsigned int find_get_master_pages(struct pagevec *pvec, int nid,
					  unsigned long start_pfn, unsigned long end_pfn)
{
	XA_STATE(xas, &dup_pages[nid], start_pfn);
	struct page *page;
	void *entry;

	pagevec_init(pvec);

	rcu_read_lock();
	xas_for_each(&xas, entry, end_pfn) {
		if (xas_retry(&xas, entry))
			continue;

		page = pfn_to_online_page(xas.xa_index);
		if (!page || !page_cache_get_speculative(page))
			continue;

		if (pagevec_add(pvec, page) == 0)
			break;
	}
	rcu_read_unlock();

	return pagevec_count(pvec);
}

static void truncate_dup_pages(void)
{
	int nid;

	for_each_online_node(nid) {
		unsigned long start_pfn = node_start_pfn(nid);
		unsigned long end_pfn = node_end_pfn(nid);
		struct pagevec pvec;
		struct page *page;
		int i;

		while (find_get_master_pages(&pvec, nid, start_pfn, end_pfn)) {
			for (i = 0; i < pagevec_count(&pvec); i++) {
				page = pvec.pages[i];

				lock_page(page);
				__dedup_page(page, false, true);
				unlock_page(page);
				put_page(page);

				cond_resched();
			}
		}
	}
}

static int __init setup_duptext(char *s)
{
	if (!strcmp(s, "1"))
		static_branch_enable(&duptext_enabled_key);
	else if (!strcmp(s, "0"))
		static_branch_disable(&duptext_enabled_key);
	return 1;
}
__setup("duptext=", setup_duptext);

#ifdef CONFIG_SYSFS
static ssize_t duptext_enabled_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!static_branch_unlikely(&duptext_enabled_key));
}
static ssize_t duptext_enabled_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	static DEFINE_MUTEX(mutex);
	ssize_t ret = count;

	mutex_lock(&mutex);

	if (!strncmp(buf, "1", 1))
		static_branch_enable(&duptext_enabled_key);
	else if (!strncmp(buf, "0", 1)) {
		int nid;

		static_branch_disable(&duptext_enabled_key);
		/*
		 * Grab xa_lock of each dup_pages xarray after disable the
		 * global enabled key, in order to prevent new dup_page from
		 * being added, or wait for all inflight dup_page to be added.
		 *
		 * On the other hand, PG_locked will serialize
		 * page_add_file_rmap() and truncate_dup_pages() for each
		 * identical page.
		 */
		for_each_online_node(nid) {
			xa_lock(&dup_pages[nid]);
			xa_unlock(&dup_pages[nid]);
		}

		truncate_dup_pages();
	} else
		ret = -EINVAL;

	mutex_unlock(&mutex);
	return ret;
}
static struct kobj_attribute duptext_enabled_attr =
	__ATTR(enabled, 0644, duptext_enabled_show,
	       duptext_enabled_store);

static struct attribute *duptext_attrs[] = {
	&duptext_enabled_attr.attr,
	NULL,
};

static struct attribute_group duptext_attr_group = {
	.attrs = duptext_attrs,
};

static int __init duptext_init_sysfs(void)
{
	int err;
	struct kobject *duptext_kobj;

	duptext_kobj = kobject_create_and_add("duptext", mm_kobj);
	if (!duptext_kobj) {
		pr_err("failed to create duptext kobject\n");
		return -ENOMEM;
	}
	err = sysfs_create_group(duptext_kobj, &duptext_attr_group);
	if (err) {
		pr_err("failed to register duptext group\n");
		goto delete_obj;
	}
	return 0;

delete_obj:
	kobject_put(duptext_kobj);
	return err;
}
#endif /* CONFIG_SYSFS */

static int __init duptext_init(void)
{
	int ret = 0, nid;

	for_each_node(nid)
		xa_init_flags(&dup_pages[nid], XA_FLAGS_LOCK_IRQ);

#ifdef CONFIG_SYSFS
	ret = duptext_init_sysfs();
#endif

	return ret;
}
module_init(duptext_init);

/*
 * Currently the way to refresh duptext, in order to apply duptext to
 * pages which were dirty, wirteback, or !uptodate before, is simply
 * to zap the page range of corresponding vma, and then make process
 * fault again.
 *
 * FIXME Optimize with walk_page_range() if obvious overhead is found
 * in current implementation. However, there are a few points to note.
 * 1. How to determine "numa_node_id()" of specific mm, in the context
 *    of asynchronous work.
 * 2. Implementation with walk_page_range() is complex and error-prone.
 */
static void duptext_refresh_mm(struct mm_struct *mm)
{
	struct vm_area_struct *vma;

	mmap_read_lock(mm);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!__dup_page_suitable(vma, mm))
			continue;
		zap_page_range(vma, vma->vm_start, vma->vm_end - vma->vm_start);
		cond_resched();
	}
	mmap_read_unlock(mm);
}

static void duptext_refresh_workfn(struct work_struct *work)
{
	struct duptext_refresh *refresh = container_of(to_delayed_work(work),
						struct duptext_refresh, dwork);
	struct mm_struct *mm = refresh->mm;

	if (!duptext_enabled() ||
	    atomic_read(&mm->mm_users) == 0)
		goto out;

	duptext_refresh_mm(mm);

out:
	mmdrop(mm);
	kfree(refresh);
}
