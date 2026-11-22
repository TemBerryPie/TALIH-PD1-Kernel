/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * 4.14 compatibility shims for the fragments-era EROFS driver.
 *
 * The driver was written against 4.19/5.x-era VFS APIs; everything here
 * re-exposes those APIs on top of 4.14 primitives with identical
 * semantics.  Nothing in here changes driver behaviour on a 4.19+ kernel
 * (all definitions are guarded or 4.14-only).
 */
#ifndef __EROFS_COMPAT_H
#define __EROFS_COMPAT_H

#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

/*
 * 4.14 has kvmalloc_array() but not the kvcalloc()/kvzalloc_array() sugar.
 * (kvzalloc() itself exists in this tree; kvcalloc() does not.)
 */
static inline void *kvcalloc(size_t n, size_t size, gfp_t flags)
{
	return kvmalloc_array(n, size, flags | __GFP_ZERO);
}

/*
 * <linux/overflow.h> is 5.1+; 4.14 gcc/clang all support the builtins.
 */
#define check_add_overflow(a, b, d)	__builtin_add_overflow(a, b, d)

/*
 * calc_struct_size()/struct_size() arrived in 5.1.  Flex-array members make
 * sizeof(*(p)) the full struct without the array, so add the array bytes.
 */
#ifndef struct_size
#define struct_size(p, member, count) \
	(sizeof(*(p)) + (count) * sizeof(*(p)->member))
#endif

/*
 * sysfs_emit() is 5.10+ (the kobject attribute buffer is always page
 * aligned and never larger than PAGE_SIZE, exactly like the 5.10 version
 * assumes).
 */
static inline ssize_t sysfs_emit(char *buf, const char *fmt, ...)
{
	va_list args;
	ssize_t len;

	va_start(args, fmt);
	len = vscnprintf(buf, PAGE_SIZE, fmt, args);
	va_end(args);
	return len;
}

/*
 * rcu_read_lock_any_held() is 5.x.  A 4.14 rcu_read_lock() disables
 * preemption (PREEMPT_RCU accounting is not exposed), so preempt_count()
 * is the closest available atomic-context probe; erring towards
 * "held" only makes z_erofs_decompress_kickoff() queue work instead of
 * decompressing inline, which is always safe.
 */
#ifndef rcu_read_lock_any_held
#define rcu_read_lock_any_held()	(!!preempt_count())
#endif

/*
 * alloc_pages_bulk_array() is 5.9+.  Fill every NULL slot of page_array,
 * leaving already-filled slots (in-place pages) untouched; return the
 * number of filled slots, i.e. the index of the first slot that could not
 * be allocated on failure.  Callers in zutil.c retry while there is
 * progress, which is exactly the behaviour this reproduces.
 */
static inline unsigned long alloc_pages_bulk_array(gfp_t gfp,
		unsigned long nr_pages, struct page **page_array)
{
	unsigned long i;

	for (i = 0; i < nr_pages; i++) {
		if (page_array[i])
			continue;
		page_array[i] = alloc_page(gfp);
		if (unlikely(!page_array[i]))
			return i;
	}
	return nr_pages;
}

/*
 * kmap_local_page()/kunmap_local()/memcpy_to_page() are 5.10/5.11+; the
 * no-highmem 4.14 shims for those already live at the bottom of
 * internal.h, so they are not duplicated here.
 */

#endif /* __EROFS_COMPAT_H */
