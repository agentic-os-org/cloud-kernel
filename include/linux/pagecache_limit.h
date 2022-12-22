/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _PAGECACHE_LIMIT_H
#define _PAGECACHE_LIMIT_H

#ifdef CONFIG_PAGECACHE_LIMIT

DECLARE_STATIC_KEY_FALSE(pagecache_limit_enabled_key);

enum pgcache_limit_reclaim_type {
	/* per-memcg or global pagecaeche reclaim defaut way is async */
	PGCACHE_RECLAIM_ASYNC = 0,
	PGCACHE_RECLAIM_DIRECT
};

static inline bool pagecache_limit_enabled(void)
{
	return static_branch_unlikely(&pagecache_limit_enabled_key);
}

#else
static inline bool pagecache_limit_enabled(void)
{
	return false;
}
#endif
#endif
