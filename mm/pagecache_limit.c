// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "pagecache_limit: " fmt

#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/pagemap.h>
#include <linux/memcontrol.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/pagecache_limit.h>

DEFINE_STATIC_KEY_FALSE(pagecache_limit_enabled_key);

static int __init setup_pagecache_limit(char *s)
{
	if (!strcmp(s, "1"))
		static_branch_enable(&pagecache_limit_enabled_key);
	else if (!strcmp(s, "0"))
		static_branch_disable(&pagecache_limit_enabled_key);
	return 1;
}
__setup("pagecache_limit=", setup_pagecache_limit);

#ifdef CONFIG_SYSFS
static ssize_t pagecache_limit_enabled_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!static_branch_unlikely(&pagecache_limit_enabled_key));
}

static ssize_t pagecache_limit_enabled_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     const char *buf, size_t count)
{
	static DEFINE_MUTEX(mutex);
	ssize_t ret = count;

	mutex_lock(&mutex);

	if (!strncmp(buf, "1", 1))
		static_branch_enable(&pagecache_limit_enabled_key);
	else if (!strncmp(buf, "0", 1))
		static_branch_disable(&pagecache_limit_enabled_key);
	else
		ret = -EINVAL;

	mutex_unlock(&mutex);
	return ret;
}

static struct kobj_attribute pagecache_limit_enabled_attr =
	__ATTR(enabled, 0644, pagecache_limit_enabled_show,
	       pagecache_limit_enabled_store);

static struct attribute *pagecache_limit_attrs[] = {
	&pagecache_limit_enabled_attr.attr,
	NULL,
};

static struct attribute_group pagecache_limit_attr_group = {
	.attrs = pagecache_limit_attrs,
};

static int __init pagecache_limit_init_sysfs(void)
{
	int err;
	struct kobject *pagecache_limit_kobj;

	pagecache_limit_kobj = kobject_create_and_add("pagecache_limit", mm_kobj);
	if (!pagecache_limit_kobj) {
		pr_err("failed to create pagecache_limit kobject\n");
		return -ENOMEM;
	}
	err = sysfs_create_group(pagecache_limit_kobj, &pagecache_limit_attr_group);
	if (err) {
		pr_err("failed to register pagecache_limit group\n");
		goto delete_obj;
	}

	return 0;

delete_obj:
	kobject_put(pagecache_limit_kobj);
	return err;
}
#endif /* CONFIG_SYSFS */

static int __init pagecache_limit_init(void)
{
	int ret = -EINVAL;

#ifdef CONFIG_SYSFS
	ret = pagecache_limit_init_sysfs();
#endif

	return ret;
}
module_init(pagecache_limit_init);
