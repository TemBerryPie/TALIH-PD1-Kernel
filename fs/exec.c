/*
 *  linux/fs/exec.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * #!-checking implemented by tytso.
 */
/*
 * Demand-loading implemented 01.12.91 - no need to read anything but
 * the header into memory. The inode of the executable is put into
 * "current->executable", and page faults do the actual loading. Clean.
 *
 * Once more I can proudly say that linux stood up to being changed: it
 * was less than 2 hours work to get demand-loading completely implemented.
 *
 * Demand loading changed July 1993 by Eric Youngdale.   Use mmap instead,
 * current->executable is only used by the procfs.  This allows a dispatch
 * table to check for several different types  of binary formats.  We keep
 * trying until we recognize the file or we run out of supported binary
 * formats.
 */

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/signal.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/perf_event.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/audit.h>
#include <linux/tracehook.h>
#include <linux/kmod.h>
#include <linux/fsnotify.h>
#include <linux/fs_struct.h>
#include <linux/pipe_fs_i.h>
#include <linux/oom.h>
#include <linux/compat.h>
#include <linux/vmalloc.h>
#ifdef CONFIG_TALIH_PASS2_BOOT_DIAG
#include <linux/crc32.h>
#include <linux/reboot.h>
#include <linux/sizes.h>
#endif
#ifdef CONFIG_TALIH_PASS2_SECOND_STAGE_DIAG
#include <linux/talih_pass2_diag.h>
#include <linux/task_work.h>
#include <linux/uprobes.h>
#include <asm/ptrace.h>
#endif

#include <linux/uaccess.h>
#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#endif
#include <asm/mmu_context.h>
#include <asm/tlb.h>

#include <trace/events/task.h>
#include "internal.h"

#include <trace/events/sched.h>

#include <mt-plat/mtk_pidmap.h>
#ifdef CONFIG_TALIH_PASS2_SELINUX_DIAG
#include <mt-plat/mtk_boot_common.h>
#endif
#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags);
#endif

int suid_dumpable = 0;

static LIST_HEAD(formats);
static DEFINE_RWLOCK(binfmt_lock);

void __register_binfmt(struct linux_binfmt * fmt, int insert)
{
	BUG_ON(!fmt);
	if (WARN_ON(!fmt->load_binary))
		return;
	write_lock(&binfmt_lock);
	insert ? list_add(&fmt->lh, &formats) :
		 list_add_tail(&fmt->lh, &formats);
	write_unlock(&binfmt_lock);
}

EXPORT_SYMBOL(__register_binfmt);

void unregister_binfmt(struct linux_binfmt * fmt)
{
	write_lock(&binfmt_lock);
	list_del(&fmt->lh);
	write_unlock(&binfmt_lock);
}

EXPORT_SYMBOL(unregister_binfmt);

static inline void put_binfmt(struct linux_binfmt * fmt)
{
	module_put(fmt->module);
}

bool path_noexec(const struct path *path)
{
	return (path->mnt->mnt_flags & MNT_NOEXEC) ||
	       (path->mnt->mnt_sb->s_iflags & SB_I_NOEXEC);
}

#ifdef CONFIG_USELIB
/*
 * Note that a shared library must be both readable and executable due to
 * security reasons.
 *
 * Also note that we take the address to load from from the file itself.
 */
SYSCALL_DEFINE1(uselib, const char __user *, library)
{
	struct linux_binfmt *fmt;
	struct file *file;
	struct filename *tmp = getname(library);
	int error = PTR_ERR(tmp);
	static const struct open_flags uselib_flags = {
		.open_flag = O_LARGEFILE | O_RDONLY | __FMODE_EXEC,
		.acc_mode = MAY_READ | MAY_EXEC,
		.intent = LOOKUP_OPEN,
		.lookup_flags = LOOKUP_FOLLOW,
	};

	if (IS_ERR(tmp))
		goto out;

	file = do_filp_open(AT_FDCWD, tmp, &uselib_flags);
	putname(tmp);
	error = PTR_ERR(file);
	if (IS_ERR(file))
		goto out;

	error = -EINVAL;
	if (!S_ISREG(file_inode(file)->i_mode))
		goto exit;

	error = -EACCES;
	if (path_noexec(&file->f_path))
		goto exit;

	fsnotify_open(file);

	error = -ENOEXEC;

	read_lock(&binfmt_lock);
	list_for_each_entry(fmt, &formats, lh) {
		if (!fmt->load_shlib)
			continue;
		if (!try_module_get(fmt->module))
			continue;
		read_unlock(&binfmt_lock);
		error = fmt->load_shlib(file);
		read_lock(&binfmt_lock);
		put_binfmt(fmt);
		if (error != -ENOEXEC)
			break;
	}
	read_unlock(&binfmt_lock);
exit:
	fput(file);
out:
  	return error;
}
#endif /* #ifdef CONFIG_USELIB */

#ifdef CONFIG_MMU
/*
 * The nascent bprm->mm is not visible until exec_mmap() but it can
 * use a lot of memory, account these pages in current->mm temporary
 * for oom_badness()->get_mm_rss(). Once exec succeeds or fails, we
 * change the counter back via acct_arg_size(0).
 */
static void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
	struct mm_struct *mm = current->mm;
	long diff = (long)(pages - bprm->vma_pages);

	if (!mm || !diff)
		return;

	bprm->vma_pages = pages;
	add_mm_counter(mm, MM_ANONPAGES, diff);
}

static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos,
		int write)
{
	struct page *page;
	int ret;
	unsigned int gup_flags = FOLL_FORCE;

#ifdef CONFIG_STACK_GROWSUP
	if (write) {
		ret = expand_downwards(bprm->vma, pos);
		if (ret < 0)
			return NULL;
	}
#endif

	if (write)
		gup_flags |= FOLL_WRITE;

	/*
	 * We are doing an exec().  'current' is the process
	 * doing the exec and bprm->mm is the new process's mm.
	 */
	ret = get_user_pages_remote(current, bprm->mm, pos, 1, gup_flags,
			&page, NULL, NULL);
	if (ret <= 0)
		return NULL;

	if (write) {
		unsigned long size = bprm->vma->vm_end - bprm->vma->vm_start;
		unsigned long ptr_size, limit;

		/*
		 * Since the stack will hold pointers to the strings, we
		 * must account for them as well.
		 *
		 * The size calculation is the entire vma while each arg page is
		 * built, so each time we get here it's calculating how far it
		 * is currently (rather than each call being just the newly
		 * added size from the arg page).  As a result, we need to
		 * always add the entire size of the pointers, so that on the
		 * last call to get_arg_page() we'll actually have the entire
		 * correct size.
		 */
		ptr_size = (bprm->argc + bprm->envc) * sizeof(void *);
		if (ptr_size > ULONG_MAX - size)
			goto fail;
		size += ptr_size;

		acct_arg_size(bprm, size / PAGE_SIZE);

		/*
		 * We've historically supported up to 32 pages (ARG_MAX)
		 * of argument strings even with small stacks
		 */
		if (size <= ARG_MAX)
			return page;

		/*
		 * Limit to 1/4 of the max stack size or 3/4 of _STK_LIM
		 * (whichever is smaller) for the argv+env strings.
		 * This ensures that:
		 *  - the remaining binfmt code will not run out of stack space,
		 *  - the program will have a reasonable amount of stack left
		 *    to work from.
		 */
		limit = _STK_LIM / 4 * 3;
		limit = min(limit, rlimit(RLIMIT_STACK) / 4);
		if (size > limit)
			goto fail;
	}

	return page;

fail:
	put_page(page);
	return NULL;
}

static void put_arg_page(struct page *page)
{
	put_page(page);
}

static void free_arg_pages(struct linux_binprm *bprm)
{
}

static void flush_arg_page(struct linux_binprm *bprm, unsigned long pos,
		struct page *page)
{
	flush_cache_page(bprm->vma, pos, page_to_pfn(page));
}

static int __bprm_mm_init(struct linux_binprm *bprm)
{
	int err;
	struct vm_area_struct *vma = NULL;
	struct mm_struct *mm = bprm->mm;

	bprm->vma = vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma)
		return -ENOMEM;

	if (down_write_killable(&mm->mmap_sem)) {
		err = -EINTR;
		goto err_free;
	}
	vma->vm_mm = mm;

	/*
	 * Place the stack at the largest stack address the architecture
	 * supports. Later, we'll move this to an appropriate place. We don't
	 * use STACK_TOP because that can depend on attributes which aren't
	 * configured yet.
	 */
	BUILD_BUG_ON(VM_STACK_FLAGS & VM_STACK_INCOMPLETE_SETUP);
	vma->vm_end = STACK_TOP_MAX;
	vma->vm_start = vma->vm_end - PAGE_SIZE;
	vma->vm_flags = VM_SOFTDIRTY | VM_STACK_FLAGS | VM_STACK_INCOMPLETE_SETUP;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	INIT_VMA(vma);

	err = insert_vm_struct(mm, vma);
	if (err)
		goto err;

	mm->stack_vm = mm->total_vm = 1;
	arch_bprm_mm_init(mm, vma);
	up_write(&mm->mmap_sem);
	bprm->p = vma->vm_end - sizeof(void *);
	return 0;
err:
	up_write(&mm->mmap_sem);
err_free:
	bprm->vma = NULL;
	kmem_cache_free(vm_area_cachep, vma);
	return err;
}

static bool valid_arg_len(struct linux_binprm *bprm, long len)
{
	return len <= MAX_ARG_STRLEN;
}

#else

static inline void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
}

static struct page *get_arg_page(struct linux_binprm *bprm, unsigned long pos,
		int write)
{
	struct page *page;

	page = bprm->page[pos / PAGE_SIZE];
	if (!page && write) {
		page = alloc_page(GFP_HIGHUSER|__GFP_ZERO);
		if (!page)
			return NULL;
		bprm->page[pos / PAGE_SIZE] = page;
	}

	return page;
}

static void put_arg_page(struct page *page)
{
}

static void free_arg_page(struct linux_binprm *bprm, int i)
{
	if (bprm->page[i]) {
		__free_page(bprm->page[i]);
		bprm->page[i] = NULL;
	}
}

static void free_arg_pages(struct linux_binprm *bprm)
{
	int i;

	for (i = 0; i < MAX_ARG_PAGES; i++)
		free_arg_page(bprm, i);
}

static void flush_arg_page(struct linux_binprm *bprm, unsigned long pos,
		struct page *page)
{
}

static int __bprm_mm_init(struct linux_binprm *bprm)
{
	bprm->p = PAGE_SIZE * MAX_ARG_PAGES - sizeof(void *);
	return 0;
}

static bool valid_arg_len(struct linux_binprm *bprm, long len)
{
	return len <= bprm->p;
}

#endif /* CONFIG_MMU */

/*
 * Create a new mm_struct and populate it with a temporary stack
 * vm_area_struct.  We don't have enough context at this point to set the stack
 * flags, permissions, and offset, so we use temporary values.  We'll update
 * them later in setup_arg_pages().
 */
static int bprm_mm_init(struct linux_binprm *bprm)
{
	int err;
	struct mm_struct *mm = NULL;

	bprm->mm = mm = mm_alloc();
	err = -ENOMEM;
	if (!mm)
		goto err;

	err = __bprm_mm_init(bprm);
	if (err)
		goto err;

	return 0;

err:
	if (mm) {
		bprm->mm = NULL;
		mmdrop(mm);
	}

	return err;
}

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

/*
 * count() counts the number of strings in array ARGV.
 */
static int count(struct user_arg_ptr argv, int max)
{
	int i = 0;

	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p)
				break;

			if (IS_ERR(p))
				return -EFAULT;

			if (i >= max)
				return -E2BIG;
			++i;

			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
			cond_resched();
		}
	}
	return i;
}

/*
 * 'copy_strings()' copies argument/environment strings from the old
 * processes's memory to the new process's stack.  The call to get_user_pages()
 * ensures the destination page is created and not swapped out.
 */
static int copy_strings(int argc, struct user_arg_ptr argv,
			struct linux_binprm *bprm)
{
	struct page *kmapped_page = NULL;
	char *kaddr = NULL;
	unsigned long kpos = 0;
	int ret;

	while (argc-- > 0) {
		const char __user *str;
		int len;
		unsigned long pos;

		ret = -EFAULT;
		str = get_user_arg_ptr(argv, argc);
		if (IS_ERR(str))
			goto out;

		len = strnlen_user(str, MAX_ARG_STRLEN);
		if (!len)
			goto out;

		ret = -E2BIG;
		if (!valid_arg_len(bprm, len))
			goto out;

		/* We're going to work our way backwords. */
		pos = bprm->p;
		str += len;
		bprm->p -= len;

		while (len > 0) {
			int offset, bytes_to_copy;

			if (fatal_signal_pending(current)) {
				ret = -ERESTARTNOHAND;
				goto out;
			}
			cond_resched();

			offset = pos % PAGE_SIZE;
			if (offset == 0)
				offset = PAGE_SIZE;

			bytes_to_copy = offset;
			if (bytes_to_copy > len)
				bytes_to_copy = len;

			offset -= bytes_to_copy;
			pos -= bytes_to_copy;
			str -= bytes_to_copy;
			len -= bytes_to_copy;

			if (!kmapped_page || kpos != (pos & PAGE_MASK)) {
				struct page *page;

				page = get_arg_page(bprm, pos, 1);
				if (!page) {
					ret = -E2BIG;
					goto out;
				}

				if (kmapped_page) {
					flush_kernel_dcache_page(kmapped_page);
					kunmap(kmapped_page);
					put_arg_page(kmapped_page);
				}
				kmapped_page = page;
				kaddr = kmap(kmapped_page);
				kpos = pos & PAGE_MASK;
				flush_arg_page(bprm, kpos, kmapped_page);
			}
			if (copy_from_user(kaddr+offset, str, bytes_to_copy)) {
				ret = -EFAULT;
				goto out;
			}
		}
	}
	ret = 0;
out:
	if (kmapped_page) {
		flush_kernel_dcache_page(kmapped_page);
		kunmap(kmapped_page);
		put_arg_page(kmapped_page);
	}
	return ret;
}

/*
 * Like copy_strings, but get argv and its values from kernel memory.
 */
int copy_strings_kernel(int argc, const char *const *__argv,
			struct linux_binprm *bprm)
{
	int r;
	mm_segment_t oldfs = get_fs();
	struct user_arg_ptr argv = {
		.ptr.native = (const char __user *const  __user *)__argv,
	};

	set_fs(KERNEL_DS);
	r = copy_strings(argc, argv, bprm);
	set_fs(oldfs);

	return r;
}
EXPORT_SYMBOL(copy_strings_kernel);

#ifdef CONFIG_MMU

/*
 * During bprm_mm_init(), we create a temporary stack at STACK_TOP_MAX.  Once
 * the binfmt code determines where the new stack should reside, we shift it to
 * its final location.  The process proceeds as follows:
 *
 * 1) Use shift to calculate the new vma endpoints.
 * 2) Extend vma to cover both the old and new ranges.  This ensures the
 *    arguments passed to subsequent functions are consistent.
 * 3) Move vma's page tables to the new range.
 * 4) Free up any cleared pgd range.
 * 5) Shrink the vma to cover only the new range.
 */
static int shift_arg_pages(struct vm_area_struct *vma, unsigned long shift)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long old_start = vma->vm_start;
	unsigned long old_end = vma->vm_end;
	unsigned long length = old_end - old_start;
	unsigned long new_start = old_start - shift;
	unsigned long new_end = old_end - shift;
	struct mmu_gather tlb;

	BUG_ON(new_start > new_end);

	/*
	 * ensure there are no vmas between where we want to go
	 * and where we are
	 */
	if (vma != find_vma(mm, new_start))
		return -EFAULT;

	/*
	 * cover the whole range: [new_start, old_end)
	 */
	if (vma_adjust(vma, new_start, old_end, vma->vm_pgoff, NULL))
		return -ENOMEM;

	/*
	 * move the page tables downwards, on failure we rely on
	 * process cleanup to remove whatever mess we made.
	 */
	if (length != move_page_tables(vma, old_start,
				       vma, new_start, length, false))
		return -ENOMEM;

	lru_add_drain();
	tlb_gather_mmu(&tlb, mm, old_start, old_end);
	if (new_end > old_start) {
		/*
		 * when the old and new regions overlap clear from new_end.
		 */
		free_pgd_range(&tlb, new_end, old_end, new_end,
			vma->vm_next ? vma->vm_next->vm_start : USER_PGTABLES_CEILING);
	} else {
		/*
		 * otherwise, clean from old_start; this is done to not touch
		 * the address space in [new_end, old_start) some architectures
		 * have constraints on va-space that make this illegal (IA64) -
		 * for the others its just a little faster.
		 */
		free_pgd_range(&tlb, old_start, old_end, new_end,
			vma->vm_next ? vma->vm_next->vm_start : USER_PGTABLES_CEILING);
	}
	tlb_finish_mmu(&tlb, old_start, old_end);

	/*
	 * Shrink the vma to just the new range.  Always succeeds.
	 */
	vma_adjust(vma, new_start, new_end, vma->vm_pgoff, NULL);

	return 0;
}

/*
 * Finalizes the stack vm_area_struct. The flags and permissions are updated,
 * the stack is optionally relocated, and some extra space is added.
 */
int setup_arg_pages(struct linux_binprm *bprm,
		    unsigned long stack_top,
		    int executable_stack)
{
	unsigned long ret;
	unsigned long stack_shift;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = bprm->vma;
	struct vm_area_struct *prev = NULL;
	unsigned long vm_flags;
	unsigned long stack_base;
	unsigned long stack_size;
	unsigned long stack_expand;
	unsigned long rlim_stack;

#ifdef CONFIG_STACK_GROWSUP
	/* Limit stack size */
	stack_base = rlimit_max(RLIMIT_STACK);
	if (stack_base > STACK_SIZE_MAX)
		stack_base = STACK_SIZE_MAX;

	/* Add space for stack randomization. */
	stack_base += (STACK_RND_MASK << PAGE_SHIFT);

	/* Make sure we didn't let the argument array grow too large. */
	if (vma->vm_end - vma->vm_start > stack_base)
		return -ENOMEM;

	stack_base = PAGE_ALIGN(stack_top - stack_base);

	stack_shift = vma->vm_start - stack_base;
	mm->arg_start = bprm->p - stack_shift;
	bprm->p = vma->vm_end - stack_shift;
#else
	stack_top = arch_align_stack(stack_top);
	stack_top = PAGE_ALIGN(stack_top);

	if (unlikely(stack_top < mmap_min_addr) ||
	    unlikely(vma->vm_end - vma->vm_start >= stack_top - mmap_min_addr))
		return -ENOMEM;

	stack_shift = vma->vm_end - stack_top;

	bprm->p -= stack_shift;
	mm->arg_start = bprm->p;
#endif

	if (bprm->loader)
		bprm->loader -= stack_shift;
	bprm->exec -= stack_shift;

	if (down_write_killable(&mm->mmap_sem))
		return -EINTR;

	vm_flags = VM_STACK_FLAGS;

	/*
	 * Adjust stack execute permissions; explicitly enable for
	 * EXSTACK_ENABLE_X, disable for EXSTACK_DISABLE_X and leave alone
	 * (arch default) otherwise.
	 */
	if (unlikely(executable_stack == EXSTACK_ENABLE_X))
		vm_flags |= VM_EXEC;
	else if (executable_stack == EXSTACK_DISABLE_X)
		vm_flags &= ~VM_EXEC;
	vm_flags |= mm->def_flags;
	vm_flags |= VM_STACK_INCOMPLETE_SETUP;

	ret = mprotect_fixup(vma, &prev, vma->vm_start, vma->vm_end,
			vm_flags);
	if (ret)
		goto out_unlock;
	BUG_ON(prev != vma);

	/* Move stack pages down in memory. */
	if (stack_shift) {
		ret = shift_arg_pages(vma, stack_shift);
		if (ret)
			goto out_unlock;
	}

	/* mprotect_fixup is overkill to remove the temporary stack flags */
	vma->vm_flags &= ~VM_STACK_INCOMPLETE_SETUP;

	stack_expand = 131072UL; /* randomly 32*4k (or 2*64k) pages */
	stack_size = vma->vm_end - vma->vm_start;
	/*
	 * Align this down to a page boundary as expand_stack
	 * will align it up.
	 */
	rlim_stack = rlimit(RLIMIT_STACK) & PAGE_MASK;
#ifdef CONFIG_STACK_GROWSUP
	if (stack_size + stack_expand > rlim_stack)
		stack_base = vma->vm_start + rlim_stack;
	else
		stack_base = vma->vm_end + stack_expand;
#else
	if (stack_size + stack_expand > rlim_stack)
		stack_base = vma->vm_end - rlim_stack;
	else
		stack_base = vma->vm_start - stack_expand;
#endif
	current->mm->start_stack = bprm->p;
	ret = expand_stack(vma, stack_base);
	if (ret)
		ret = -EFAULT;

out_unlock:
	up_write(&mm->mmap_sem);
	return ret;
}
EXPORT_SYMBOL(setup_arg_pages);

#else

/*
 * Transfer the program arguments and environment from the holding pages
 * onto the stack. The provided stack pointer is adjusted accordingly.
 */
int transfer_args_to_stack(struct linux_binprm *bprm,
			   unsigned long *sp_location)
{
	unsigned long index, stop, sp;
	int ret = 0;

	stop = bprm->p >> PAGE_SHIFT;
	sp = *sp_location;

	for (index = MAX_ARG_PAGES - 1; index >= stop; index--) {
		unsigned int offset = index == stop ? bprm->p & ~PAGE_MASK : 0;
		char *src = kmap(bprm->page[index]) + offset;
		sp -= PAGE_SIZE - offset;
		if (copy_to_user((void *) sp, src, PAGE_SIZE - offset) != 0)
			ret = -EFAULT;
		kunmap(bprm->page[index]);
		if (ret)
			goto out;
	}

	*sp_location = sp;

out:
	return ret;
}
EXPORT_SYMBOL(transfer_args_to_stack);

#endif /* CONFIG_MMU */

static struct file *do_open_execat(int fd, struct filename *name, int flags)
{
	struct file *file;
	int err;
	struct open_flags open_exec_flags = {
		.open_flag = O_LARGEFILE | O_RDONLY | __FMODE_EXEC,
		.acc_mode = MAY_EXEC,
		.intent = LOOKUP_OPEN,
		.lookup_flags = LOOKUP_FOLLOW,
	};

	if ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
		return ERR_PTR(-EINVAL);
	if (flags & AT_SYMLINK_NOFOLLOW)
		open_exec_flags.lookup_flags &= ~LOOKUP_FOLLOW;
	if (flags & AT_EMPTY_PATH)
		open_exec_flags.lookup_flags |= LOOKUP_EMPTY;

	file = do_filp_open(fd, name, &open_exec_flags);
	if (IS_ERR(file))
		goto out;

	err = -EACCES;
	if (!S_ISREG(file_inode(file)->i_mode))
		goto exit;

	if (path_noexec(&file->f_path))
		goto exit;

	err = deny_write_access(file);
	if (err)
		goto exit;

	if (name->name[0] != '\0')
		fsnotify_open(file);

out:
	return file;

exit:
	fput(file);
	return ERR_PTR(err);
}

struct file *open_exec(const char *name)
{
	struct filename *filename = getname_kernel(name);
	struct file *f = ERR_CAST(filename);

	if (!IS_ERR(filename)) {
		f = do_open_execat(AT_FDCWD, filename, 0);
		putname(filename);
	}
	return f;
}
EXPORT_SYMBOL(open_exec);

int kernel_read_file(struct file *file, void **buf, loff_t *size,
		     loff_t max_size, enum kernel_read_file_id id)
{
	loff_t i_size, pos;
	ssize_t bytes = 0;
	int ret;

	if (!S_ISREG(file_inode(file)->i_mode) || max_size < 0)
		return -EINVAL;

	ret = security_kernel_read_file(file, id);
	if (ret)
		return ret;

	ret = deny_write_access(file);
	if (ret)
		return ret;

	i_size = i_size_read(file_inode(file));
	if (max_size > 0 && i_size > max_size) {
		ret = -EFBIG;
		goto out;
	}
	if (i_size <= 0) {
		ret = -EINVAL;
		goto out;
	}

	if (id != READING_FIRMWARE_PREALLOC_BUFFER)
		*buf = vmalloc(i_size);
	if (!*buf) {
		ret = -ENOMEM;
		goto out;
	}

	pos = 0;
	while (pos < i_size) {
		bytes = kernel_read(file, *buf + pos, i_size - pos, &pos);
		if (bytes < 0) {
			ret = bytes;
			goto out_free;
		}

		if (bytes == 0)
			break;
	}

	if (pos != i_size) {
		ret = -EIO;
		goto out_free;
	}

	ret = security_kernel_post_read_file(file, *buf, i_size, id);
	if (!ret)
		*size = pos;

out_free:
	if (ret < 0) {
		if (id != READING_FIRMWARE_PREALLOC_BUFFER) {
			vfree(*buf);
			*buf = NULL;
		}
	}

out:
	allow_write_access(file);
	return ret;
}
EXPORT_SYMBOL_GPL(kernel_read_file);

int kernel_read_file_from_path(const char *path, void **buf, loff_t *size,
			       loff_t max_size, enum kernel_read_file_id id)
{
	struct file *file;
	int ret;

	if (!path || !*path)
		return -EINVAL;

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);

	ret = kernel_read_file(file, buf, size, max_size, id);
	fput(file);
	return ret;
}
EXPORT_SYMBOL_GPL(kernel_read_file_from_path);

int kernel_read_file_from_fd(int fd, void **buf, loff_t *size, loff_t max_size,
			     enum kernel_read_file_id id)
{
	struct fd f = fdget(fd);
	int ret = -EBADF;

	if (!f.file)
		goto out;

	ret = kernel_read_file(f.file, buf, size, max_size, id);
out:
	fdput(f);
	return ret;
}
EXPORT_SYMBOL_GPL(kernel_read_file_from_fd);

ssize_t read_code(struct file *file, unsigned long addr, loff_t pos, size_t len)
{
	ssize_t res = vfs_read(file, (void __user *)addr, len, &pos);
	if (res > 0)
		flush_icache_range(addr, addr + len);
	return res;
}
EXPORT_SYMBOL(read_code);

static int exec_mmap(struct mm_struct *mm)
{
	struct task_struct *tsk;
	struct mm_struct *old_mm, *active_mm;

	/* Notify parent that we're no longer interested in the old VM */
	tsk = current;
	old_mm = current->mm;
	exec_mm_release(tsk, old_mm);

	if (old_mm) {
		sync_mm_rss(old_mm);
		/*
		 * Make sure that if there is a core dump in progress
		 * for the old mm, we get out and die instead of going
		 * through with the exec.  We must hold mmap_sem around
		 * checking core_state and changing tsk->mm.
		 */
		down_read(&old_mm->mmap_sem);
		if (unlikely(old_mm->core_state)) {
			up_read(&old_mm->mmap_sem);
			return -EINTR;
		}
	}
	task_lock(tsk);
	active_mm = tsk->active_mm;
	tsk->mm = mm;
	tsk->active_mm = mm;
	activate_mm(active_mm, mm);
	tsk->mm->vmacache_seqnum = 0;
	vmacache_flush(tsk);
	task_unlock(tsk);
	if (old_mm) {
		up_read(&old_mm->mmap_sem);
		BUG_ON(active_mm != old_mm);
		setmax_mm_hiwater_rss(&tsk->signal->maxrss, old_mm);
		mm_update_next_owner(old_mm);
		mmput(old_mm);
		return 0;
	}
	mmdrop(active_mm);
	return 0;
}

/*
 * This function makes sure the current process has its own signal table,
 * so that flush_signal_handlers can later reset the handlers without
 * disturbing other processes.  (Other processes might share the signal
 * table via the CLONE_SIGHAND option to clone().)
 */
static int de_thread(struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;
	struct sighand_struct *oldsighand = tsk->sighand;
	spinlock_t *lock = &oldsighand->siglock;

	if (thread_group_empty(tsk))
		goto no_thread_group;

	/*
	 * Kill all other threads in the thread group.
	 */
	spin_lock_irq(lock);
	if (signal_group_exit(sig)) {
		/*
		 * Another group action in progress, just
		 * return so that the signal is processed.
		 */
		spin_unlock_irq(lock);
		return -EAGAIN;
	}

	sig->group_exit_task = tsk;
	sig->notify_count = zap_other_threads(tsk);
	if (!thread_group_leader(tsk))
		sig->notify_count--;

	while (sig->notify_count) {
		__set_current_state(TASK_KILLABLE);
		spin_unlock_irq(lock);
		schedule();
		if (unlikely(__fatal_signal_pending(tsk)))
			goto killed;
		spin_lock_irq(lock);
	}
	spin_unlock_irq(lock);

	/*
	 * At this point all other threads have exited, all we have to
	 * do is to wait for the thread group leader to become inactive,
	 * and to assume its PID:
	 */
	if (!thread_group_leader(tsk)) {
		struct task_struct *leader = tsk->group_leader;

		for (;;) {
			cgroup_threadgroup_change_begin(tsk);
			write_lock_irq(&tasklist_lock);
			/*
			 * Do this under tasklist_lock to ensure that
			 * exit_notify() can't miss ->group_exit_task
			 */
			sig->notify_count = -1;
			if (likely(leader->exit_state))
				break;
			__set_current_state(TASK_KILLABLE);
			write_unlock_irq(&tasklist_lock);
			cgroup_threadgroup_change_end(tsk);
			schedule();
			if (unlikely(__fatal_signal_pending(tsk)))
				goto killed;
		}

		/*
		 * The only record we have of the real-time age of a
		 * process, regardless of execs it's done, is start_time.
		 * All the past CPU time is accumulated in signal_struct
		 * from sister threads now dead.  But in this non-leader
		 * exec, nothing survives from the original leader thread,
		 * whose birth marks the true age of this process now.
		 * When we take on its identity by switching to its PID, we
		 * also take its birthdate (always earlier than our own).
		 */
		tsk->start_time = leader->start_time;
		tsk->real_start_time = leader->real_start_time;

		BUG_ON(!same_thread_group(leader, tsk));
		BUG_ON(has_group_leader_pid(tsk));
		/*
		 * An exec() starts a new thread group with the
		 * TGID of the previous thread group. Rehash the
		 * two threads with a switched PID, and release
		 * the former thread group leader:
		 */

		/* Become a process group leader with the old leader's pid.
		 * The old leader becomes a thread of the this thread group.
		 * Note: The old leader also uses this pid until release_task
		 *       is called.  Odd but simple and correct.
		 */
		tsk->pid = leader->pid;
		change_pid(tsk, PIDTYPE_PID, task_pid(leader));
		transfer_pid(leader, tsk, PIDTYPE_PGID);
		transfer_pid(leader, tsk, PIDTYPE_SID);

		list_replace_rcu(&leader->tasks, &tsk->tasks);
		list_replace_init(&leader->sibling, &tsk->sibling);

		tsk->group_leader = tsk;
		leader->group_leader = tsk;

		tsk->exit_signal = SIGCHLD;
		leader->exit_signal = -1;

		BUG_ON(leader->exit_state != EXIT_ZOMBIE);
		leader->exit_state = EXIT_DEAD;

		/*
		 * We are going to release_task()->ptrace_unlink() silently,
		 * the tracer can sleep in do_wait(). EXIT_DEAD guarantees
		 * the tracer wont't block again waiting for this thread.
		 */
		if (unlikely(leader->ptrace))
			__wake_up_parent(leader, leader->parent);
		write_unlock_irq(&tasklist_lock);
		cgroup_threadgroup_change_end(tsk);

		release_task(leader);
	}

	sig->group_exit_task = NULL;
	sig->notify_count = 0;

no_thread_group:
	/* we have changed execution domain */
	tsk->exit_signal = SIGCHLD;

#ifdef CONFIG_POSIX_TIMERS
	exit_itimers(sig);
	flush_itimer_signals();
#endif

	if (atomic_read(&oldsighand->count) != 1) {
		struct sighand_struct *newsighand;
		/*
		 * This ->sighand is shared with the CLONE_SIGHAND
		 * but not CLONE_THREAD task, switch to the new one.
		 */
		newsighand = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
		if (!newsighand)
			return -ENOMEM;

		atomic_set(&newsighand->count, 1);
		memcpy(newsighand->action, oldsighand->action,
		       sizeof(newsighand->action));

		write_lock_irq(&tasklist_lock);
		spin_lock(&oldsighand->siglock);
		rcu_assign_pointer(tsk->sighand, newsighand);
		spin_unlock(&oldsighand->siglock);
		write_unlock_irq(&tasklist_lock);

		__cleanup_sighand(oldsighand);
	}

	BUG_ON(!thread_group_leader(tsk));
	return 0;

killed:
	/* protects against exit_notify() and __exit_signal() */
	read_lock(&tasklist_lock);
	sig->group_exit_task = NULL;
	sig->notify_count = 0;
	read_unlock(&tasklist_lock);
	return -EAGAIN;
}

char *__get_task_comm(char *buf, size_t buf_size, struct task_struct *tsk)
{
	task_lock(tsk);
	strncpy(buf, tsk->comm, buf_size);
	task_unlock(tsk);
	return buf;
}
EXPORT_SYMBOL_GPL(__get_task_comm);

/*
 * These functions flushes out all traces of the currently running executable
 * so that a new one can be started
 */

void __set_task_comm(struct task_struct *tsk, const char *buf, bool exec)
{
	task_lock(tsk);
	trace_task_rename(tsk, buf);
	strlcpy(tsk->comm, buf, sizeof(tsk->comm));
	task_unlock(tsk);
	perf_event_comm(tsk, exec);
	mtk_pidmap_update(tsk);
}

/*
 * Calling this is the point of no return. None of the failures will be
 * seen by userspace since either the process is already taking a fatal
 * signal (via de_thread() or coredump), or will have SEGV raised
 * (after exec_mmap()) by search_binary_handlers (see below).
 */
int flush_old_exec(struct linux_binprm * bprm)
{
	int retval;

	/*
	 * Make sure we have a private signal table and that
	 * we are unassociated from the previous thread group.
	 */
	retval = de_thread(current);
	if (retval)
		goto out;

	/*
	 * Must be called _before_ exec_mmap() as bprm->mm is
	 * not visibile until then. This also enables the update
	 * to be lockless.
	 */
	set_mm_exe_file(bprm->mm, bprm->file);

	would_dump(bprm, bprm->file);

	/*
	 * Release all of the old mmap stuff
	 */
	acct_arg_size(bprm, 0);
	retval = exec_mmap(bprm->mm);
	if (retval)
		goto out;

	/*
	 * After clearing bprm->mm (to mark that current is using the
	 * prepared mm now), we have nothing left of the original
	 * process. If anything from here on returns an error, the check
	 * in search_binary_handler() will SEGV current.
	 */
	bprm->mm = NULL;

	set_fs(USER_DS);
	current->flags &= ~(PF_RANDOMIZE | PF_FORKNOEXEC | PF_KTHREAD |
					PF_NOFREEZE | PF_NO_SETAFFINITY);
	flush_thread();
	current->personality &= ~bprm->per_clear;

	/*
	 * We have to apply CLOEXEC before we change whether the process is
	 * dumpable (in setup_new_exec) to avoid a race with a process in userspace
	 * trying to access the should-be-closed file descriptors of a process
	 * undergoing exec(2).
	 */
	do_close_on_exec(current->files);
	return 0;

out:
	return retval;
}
EXPORT_SYMBOL(flush_old_exec);

void would_dump(struct linux_binprm *bprm, struct file *file)
{
	struct inode *inode = file_inode(file);
	if (inode_permission2(file->f_path.mnt, inode, MAY_READ) < 0) {
		struct user_namespace *old, *user_ns;
		bprm->interp_flags |= BINPRM_FLAGS_ENFORCE_NONDUMP;

		/* Ensure mm->user_ns contains the executable */
		user_ns = old = bprm->mm->user_ns;
		while ((user_ns != &init_user_ns) &&
		       !privileged_wrt_inode_uidgid(user_ns, inode))
			user_ns = user_ns->parent;

		if (old != user_ns) {
			bprm->mm->user_ns = get_user_ns(user_ns);
			put_user_ns(old);
		}
	}
}
EXPORT_SYMBOL(would_dump);

void setup_new_exec(struct linux_binprm * bprm)
{
	/*
	 * Once here, prepare_binrpm() will not be called any more, so
	 * the final state of setuid/setgid/fscaps can be merged into the
	 * secureexec flag.
	 */
	bprm->secureexec |= bprm->cap_elevated;

	if (bprm->secureexec) {
		/* Make sure parent cannot signal privileged process. */
		current->pdeath_signal = 0;

		/*
		 * For secureexec, reset the stack limit to sane default to
		 * avoid bad behavior from the prior rlimits. This has to
		 * happen before arch_pick_mmap_layout(), which examines
		 * RLIMIT_STACK, but after the point of no return to avoid
		 * needing to clean up the change on failure.
		 */
		if (current->signal->rlim[RLIMIT_STACK].rlim_cur > _STK_LIM)
			current->signal->rlim[RLIMIT_STACK].rlim_cur = _STK_LIM;
	}

	arch_pick_mmap_layout(current->mm);

	current->sas_ss_sp = current->sas_ss_size = 0;

	/*
	 * Figure out dumpability. Note that this checking only of current
	 * is wrong, but userspace depends on it. This should be testing
	 * bprm->secureexec instead.
	 */
	if (bprm->interp_flags & BINPRM_FLAGS_ENFORCE_NONDUMP ||
	    !(uid_eq(current_euid(), current_uid()) &&
	      gid_eq(current_egid(), current_gid())))
		set_dumpable(current->mm, suid_dumpable);
	else
		set_dumpable(current->mm, SUID_DUMP_USER);

	arch_setup_new_exec();
	perf_event_exec();
	__set_task_comm(current, kbasename(bprm->filename), true);

	/* Set the new mm task size. We have to do that late because it may
	 * depend on TIF_32BIT which is only updated in flush_thread() on
	 * some architectures like powerpc
	 */
	current->mm->task_size = TASK_SIZE;

	/* An exec changes our domain. We are no longer part of the thread
	   group */
	WRITE_ONCE(current->self_exec_id, current->self_exec_id + 1);
	flush_signal_handlers(current, 0);
}
EXPORT_SYMBOL(setup_new_exec);

/*
 * Prepare credentials and lock ->cred_guard_mutex.
 * install_exec_creds() commits the new creds and drops the lock.
 * Or, if exec fails before, free_bprm() should release ->cred and
 * and unlock.
 */
int prepare_bprm_creds(struct linux_binprm *bprm)
{
	if (mutex_lock_interruptible(&current->signal->cred_guard_mutex))
		return -ERESTARTNOINTR;

	bprm->cred = prepare_exec_creds();
	if (likely(bprm->cred))
		return 0;

	mutex_unlock(&current->signal->cred_guard_mutex);
	return -ENOMEM;
}

static void free_bprm(struct linux_binprm *bprm)
{
	free_arg_pages(bprm);
	if (bprm->cred) {
		mutex_unlock(&current->signal->cred_guard_mutex);
		abort_creds(bprm->cred);
	}
	if (bprm->file) {
		allow_write_access(bprm->file);
		fput(bprm->file);
	}
	/* If a binfmt changed the interp, free it. */
	if (bprm->interp != bprm->filename)
		kfree(bprm->interp);
	kfree(bprm);
}

int bprm_change_interp(const char *interp, struct linux_binprm *bprm)
{
	/* If a binfmt changed the interp, free it first. */
	if (bprm->interp != bprm->filename)
		kfree(bprm->interp);
	bprm->interp = kstrdup(interp, GFP_KERNEL);
	if (!bprm->interp)
		return -ENOMEM;
	return 0;
}
EXPORT_SYMBOL(bprm_change_interp);

/*
 * install the new credentials for this executable
 */
void install_exec_creds(struct linux_binprm *bprm)
{
	security_bprm_committing_creds(bprm);

	commit_creds(bprm->cred);
	bprm->cred = NULL;

	/*
	 * Disable monitoring for regular users
	 * when executing setuid binaries. Must
	 * wait until new credentials are committed
	 * by commit_creds() above
	 */
	if (get_dumpable(current->mm) != SUID_DUMP_USER)
		perf_event_exit_task(current);
	/*
	 * cred_guard_mutex must be held at least to this point to prevent
	 * ptrace_attach() from altering our determination of the task's
	 * credentials; any time after this it may be unlocked.
	 */
	security_bprm_committed_creds(bprm);
	mutex_unlock(&current->signal->cred_guard_mutex);
}
EXPORT_SYMBOL(install_exec_creds);

/*
 * determine how safe it is to execute the proposed program
 * - the caller must hold ->cred_guard_mutex to protect against
 *   PTRACE_ATTACH or seccomp thread-sync
 */
static void check_unsafe_exec(struct linux_binprm *bprm)
{
	struct task_struct *p = current, *t;
	unsigned n_fs;

	if (p->ptrace)
		bprm->unsafe |= LSM_UNSAFE_PTRACE;

	/*
	 * This isn't strictly necessary, but it makes it harder for LSMs to
	 * mess up.
	 */
	if (task_no_new_privs(current))
		bprm->unsafe |= LSM_UNSAFE_NO_NEW_PRIVS;

	t = p;
	n_fs = 1;
	spin_lock(&p->fs->lock);
	rcu_read_lock();
	while_each_thread(p, t) {
		if (t->fs == p->fs)
			n_fs++;
	}
	rcu_read_unlock();

	if (p->fs->users > n_fs)
		bprm->unsafe |= LSM_UNSAFE_SHARE;
	else
		p->fs->in_exec = 1;
	spin_unlock(&p->fs->lock);
}

static void bprm_fill_uid(struct linux_binprm *bprm)
{
	struct inode *inode;
	unsigned int mode;
	kuid_t uid;
	kgid_t gid;

	/*
	 * Since this can be called multiple times (via prepare_binprm),
	 * we must clear any previous work done when setting set[ug]id
	 * bits from any earlier bprm->file uses (for example when run
	 * first for a setuid script then again for its interpreter).
	 */
	bprm->cred->euid = current_euid();
	bprm->cred->egid = current_egid();

	if (!mnt_may_suid(bprm->file->f_path.mnt))
		return;

	if (task_no_new_privs(current))
		return;

	inode = bprm->file->f_path.dentry->d_inode;
	mode = READ_ONCE(inode->i_mode);
	if (!(mode & (S_ISUID|S_ISGID)))
		return;

	/* Be careful if suid/sgid is set */
	inode_lock(inode);

	/* reload atomically mode/uid/gid now that lock held */
	mode = inode->i_mode;
	uid = inode->i_uid;
	gid = inode->i_gid;
	inode_unlock(inode);

	/* We ignore suid/sgid if there are no mappings for them in the ns */
	if (!kuid_has_mapping(bprm->cred->user_ns, uid) ||
		 !kgid_has_mapping(bprm->cred->user_ns, gid))
		return;

	if (mode & S_ISUID) {
		bprm->per_clear |= PER_CLEAR_ON_SETID;
		bprm->cred->euid = uid;
	}

	if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
		bprm->per_clear |= PER_CLEAR_ON_SETID;
		bprm->cred->egid = gid;
	}
}

/*
 * Fill the binprm structure from the inode.
 * Check permissions, then read the first 128 (BINPRM_BUF_SIZE) bytes
 *
 * This may be called multiple times for binary chains (scripts for example).
 */
int prepare_binprm(struct linux_binprm *bprm)
{
	int retval;
	loff_t pos = 0;

	bprm_fill_uid(bprm);

	/* fill in binprm security blob */
	retval = security_bprm_set_creds(bprm);
	if (retval)
		return retval;
	bprm->called_set_creds = 1;

	memset(bprm->buf, 0, BINPRM_BUF_SIZE);
	return kernel_read(bprm->file, bprm->buf, BINPRM_BUF_SIZE, &pos);
}

EXPORT_SYMBOL(prepare_binprm);

/*
 * Arguments are '\0' separated strings found at the location bprm->p
 * points to; chop off the first by relocating brpm->p to right after
 * the first '\0' encountered.
 */
int remove_arg_zero(struct linux_binprm *bprm)
{
	int ret = 0;
	unsigned long offset;
	char *kaddr;
	struct page *page;

	if (!bprm->argc)
		return 0;

	do {
		offset = bprm->p & ~PAGE_MASK;
		page = get_arg_page(bprm, bprm->p, 0);
		if (!page) {
			ret = -EFAULT;
			goto out;
		}
		kaddr = kmap_atomic(page);

		for (; offset < PAGE_SIZE && kaddr[offset];
				offset++, bprm->p++)
			;

		kunmap_atomic(kaddr);
		put_arg_page(page);
	} while (offset == PAGE_SIZE);

	bprm->p++;
	bprm->argc--;
	ret = 0;

out:
	return ret;
}
EXPORT_SYMBOL(remove_arg_zero);

#define printable(c) (((c)=='\t') || ((c)=='\n') || (0x20<=(c) && (c)<=0x7e))
/*
 * cycle the list of binary formats handler, until one recognizes the image
 */
int search_binary_handler(struct linux_binprm *bprm)
{
	bool need_retry = IS_ENABLED(CONFIG_MODULES);
	struct linux_binfmt *fmt;
	int retval;

	/* This allows 4 levels of binfmt rewrites before failing hard. */
	if (bprm->recursion_depth > 5)
		return -ELOOP;

	retval = security_bprm_check(bprm);
	if (retval)
		return retval;

	retval = -ENOENT;
 retry:
	read_lock(&binfmt_lock);
	list_for_each_entry(fmt, &formats, lh) {
		if (!try_module_get(fmt->module))
			continue;
		read_unlock(&binfmt_lock);
		bprm->recursion_depth++;
		retval = fmt->load_binary(bprm);
		read_lock(&binfmt_lock);
		put_binfmt(fmt);
		bprm->recursion_depth--;
		if (retval < 0 && !bprm->mm) {
			/* we got to flush_old_exec() and failed after it */
			read_unlock(&binfmt_lock);
			force_sigsegv(SIGSEGV, current);
			return retval;
		}
		if (retval != -ENOEXEC || !bprm->file) {
			read_unlock(&binfmt_lock);
			return retval;
		}
	}
	read_unlock(&binfmt_lock);

	if (need_retry) {
		if (printable(bprm->buf[0]) && printable(bprm->buf[1]) &&
		    printable(bprm->buf[2]) && printable(bprm->buf[3]))
			return retval;
		if (request_module("binfmt-%04x", *(ushort *)(bprm->buf + 2)) < 0)
			return retval;
		need_retry = false;
		goto retry;
	}

	return retval;
}
EXPORT_SYMBOL(search_binary_handler);

#ifdef CONFIG_TALIH_PASS2_BOOT_DIAG
static void __noreturn talih_pass2_stop(int err)
{
	pr_emerg("TALIH_PASS2_DIAG: handoff=%d; stopping at diagnostic boundary\n",
		 err);
	kernel_restart("bootloader");
	panic("TALIH_PASS2_DIAG: restart returned");
}

static int talih_pass2_read_init(struct linux_binprm *bprm, bool recovery)
{
	void *image = NULL;
	loff_t size;
	u32 crc;
	int err;

	if (strcmp(bprm->filename, "/system/bin/init") ||
	    (!recovery && file_inode(bprm->file)->i_sb->s_magic != 0xe0f5e1e2))
		return -EINVAL;

	err = kernel_read_file(bprm->file, &image, &size, SZ_8M,
			       READING_UNKNOWN);
	if (err)
		return err;

	crc = crc32_le(~0U, image, size) ^ ~0U;
	vfree(image);
	if (recovery) {
		pr_info("TALIH_PASS2_DIAG: ramdisk init size=%lld crc32=%08x\n",
			size, crc);
		return size == 1053896 && crc == 0x84195cce ? 0 : -EBADMSG;
	}

	pr_info("TALIH_PASS2_DIAG: EROFS init size=%lld crc32=%08x\n",
		size, crc);
	return size == 3599760 && crc == 0xdcdcab01 ? 0 : -EBADMSG;
}
#endif

#ifdef CONFIG_TALIH_PASS2_SELINUX_DIAG
static bool talih_pass2_selinux_entered;

#ifdef CONFIG_TALIH_PASS2_SECOND_STAGE_DIAG
#define TALIH_PASS2_POLICY_SIZE		1327526

/* 文件偏移与 VA 一致；这些布局由供体 init 的长度和 CRC 约束。 */
#define TALIH_PASS2_CGROUP_VTABLE	0x3590c0UL
#define TALIH_PASS2_CGROUP_THUNK		0x111b20UL
#define TALIH_PASS2_ACTION_CALL_RET	0xe87a8UL

static const struct {
	unsigned long offset;
	const char *name;
} talih_pass2_builtins[] = {
	{ 0x152950UL, "SetupCgroupsAction" },
	{ 0x185390UL, "SetKptrRestrict" },
	{ 0x185e50UL, "TestPerfEventSelinux" },
};

struct talih_pass2_rc_command {
	unsigned int line;
	const char *args[7];
};

/* 主 init.rc 的 early-init 前缀：参数必须逐字匹配，不执行服务。 */
static const struct talih_pass2_rc_command talih_pass2_early_init[] = {
	{ 17, { "write", "/proc/bootprof", "INIT:early-init" } },
	{ 21, { "write", "/proc/sys/kernel/sysrq", "0" } },
	{ 26, { "write", "/proc/sys/kernel/modprobe", "\n" } },
	{ 29, { "restorecon", "/adb_keys" } },
	{ 32, { "restorecon", "/postinstall" } },
	{ 35, { "chown", "root", "system", "/dev/memcg/memory.pressure_level" } },
	{ 36, { "chmod", "0040", "/dev/memcg/memory.pressure_level" } },
	{ 39, { "write", "/proc/sys/vm/swappiness", "100" } },
	{ 40, { "write", "/dev/memcg/memory.swappiness", "100" } },
	{ 43, { "mkdir", "/dev/memcg/freeze-app", "0755", "system", "system" } },
	{ 44, { "write", "/dev/memcg/freeze-app/memory.swappiness", "60" } },
	{ 45, { "mkdir", "/dev/memcg/protected-app", "0755", "system", "system" } },
	{ 49, { "mkdir", "/dev/memcg/apps/", "0755", "system", "system" } },
	{ 51, { "write", "/dev/memcg/apps/memory.swappiness", "100" } },
	{ 55, { "mkdir", "/dev/memcg/system", "0550", "system", "system" } },
	{ 57, { "write", "/dev/memcg/system/memory.swappiness", "100" } },
	{ 61, { "mkdir", "/dev/net", "0755", "root", "root" } },
	{ 62, { "symlink", "../tun", "/dev/net/tun" } },
	{ 65, { "setrlimit", "nice", "40", "40" } },
	{ 68, { "setrlimit", "nofile", "32768", "32768" } },
	{ 71, { "setrlimit", "memlock", "65536", "65536" } },
	{ 74, { "mkdir", "/linkerconfig/bootstrap", "0755" } },
	{ 75, { "mkdir", "/linkerconfig/default", "0755" } },
	{ 79, { "write", "/sys/module/dm_bufio/parameters/max_age_seconds", "86400" } },
	{ 83, { "write", "/sys/module/dm_verity/parameters/prefetch_cluster", "0" } },
	{ 87, { "write", "/linkerconfig/bootstrap/ld.config.txt", "#" } },
	{ 88, { "write", "/linkerconfig/default/ld.config.txt", "#" } },
	{ 89, { "chmod", "644", "/linkerconfig/bootstrap/ld.config.txt" } },
	{ 90, { "chmod", "644", "/linkerconfig/default/ld.config.txt" } },
	{ 93, { "mount", "none", "/linkerconfig/bootstrap", "/linkerconfig", "bind", "rec" } },
};

struct talih_pass2_probe {
	unsigned long offset;
	u32 insn;
	unsigned long pc;
	struct uprobe_consumer consumer;
};

static bool talih_pass2_policy_loaded;
static bool talih_pass2_second_attempted;
static struct mm_struct *talih_pass2_second_mm;
static unsigned long talih_pass2_init_bias;
static unsigned int talih_pass2_next_action;
static unsigned int talih_pass2_rc_errors;
static bool talih_pass2_action_active;
static unsigned long talih_pass2_action;
static unsigned long talih_pass2_command;
static unsigned long talih_pass2_result;
static struct callback_head talih_pass2_check_work;
static struct callback_head talih_pass2_return_work;

void talih_pass2_note_policy_load(size_t size)
{
	if (talih_pass2_selinux_entered)
		talih_pass2_policy_loaded = size == TALIH_PASS2_POLICY_SIZE;
}

static bool talih_pass2_read_user(unsigned long addr, void *buf, size_t size)
{
	addr = untagged_addr(addr);
	return addr && addr <= TASK_SIZE - size &&
	       access_process_vm(current, addr, buf, size, 0) == size;
}

static bool talih_pass2_match_string(unsigned long addr, const char *expected)
{
	union {
		u64 words[3];
		u8 bytes[24];
	} str;
	size_t len = strlen(expected);
	char data[64];

	if (len >= sizeof(data) || !talih_pass2_read_user(addr, &str, sizeof(str)))
		return false;

	/* 供体 libc++ 字符串：短串在首字节后，长串为大小及带标签指针。 */
	if (!(str.bytes[0] & 1))
		return len <= 22 && (str.bytes[0] >> 1) == len &&
		       !memcmp(str.bytes + 1, expected, len + 1);

	return str.words[1] == len &&
	       talih_pass2_read_user(str.words[2], data, len + 1) &&
	       !memcmp(data, expected, len + 1);
}

static bool talih_pass2_match_rc(const struct talih_pass2_rc_command *entry,
				unsigned long action, unsigned long cmd,
				unsigned long begin, unsigned long end)
{
	u32 line;
	unsigned int i;

	if (!talih_pass2_read_user(cmd + 0x50, &line, sizeof(line)) ||
	    line != entry->line ||
	    !talih_pass2_match_string(action + 0x58, "/system/etc/init/hw/init.rc"))
		return false;

	for (i = 0; i < ARRAY_SIZE(entry->args); i++, begin += 24) {
		if (!entry->args[i])
			return begin == end;
		if (end - begin < 24 ||
		    !talih_pass2_match_string(begin, entry->args[i]))
			return false;
	}
	return false;
}

static void talih_pass2_check_action(struct callback_head *work)
{
	unsigned long subcontext, command[5], functor[2], invoke, begin, end;
	unsigned long action = untagged_addr(talih_pass2_action);
	unsigned long cmd = untagged_addr(talih_pass2_command);
	unsigned long bias = talih_pass2_init_bias;
	unsigned int step = talih_pass2_next_action;
	const char *reason;

	/* 供体堆指针带 TBI 标签；GUP 和范围检查使用去标签地址。 */
	reason = "object read";
	if (!action || action > TASK_SIZE - 0x70 ||
	    !cmd || cmd > TASK_SIZE - 0x54 ||
	    !talih_pass2_read_user(action + 0x50, &subcontext, sizeof(subcontext)) ||
	    !talih_pass2_read_user(cmd + 0x20, command, sizeof(command)))
		goto reject;

	reason = "subcontext or argument range";
	begin = untagged_addr(command[3]);
	end = untagged_addr(command[4]);
	if (subcontext || !begin || end > TASK_SIZE || end < begin)
		goto reject;

	if (step >= ARRAY_SIZE(talih_pass2_builtins)) {
		const struct talih_pass2_rc_command *entry;

		entry = &talih_pass2_early_init[step - ARRAY_SIZE(talih_pass2_builtins)];
		reason = "early-init source or arguments";
		if (!command[0] || !talih_pass2_match_rc(entry, action, cmd, begin, end))
			goto reject;
		pr_info("TALIH_PASS2_DIAG: early-init line %u %s admitted\n",
			entry->line, entry->args[0]);
	} else {
		reason = "builtin identity";
		if (end - begin != 24 ||
		    !talih_pass2_read_user(command[0], functor, sizeof(functor)) ||
		    functor[0] != bias + TALIH_PASS2_CGROUP_VTABLE ||
		    functor[1] != bias + talih_pass2_builtins[step].offset ||
		    !talih_pass2_read_user(functor[0] + 0x30, &invoke, sizeof(invoke)) ||
		    invoke != bias + TALIH_PASS2_CGROUP_THUNK)
			goto reject;
		pr_info("TALIH_PASS2_DIAG: builtin %s admitted; tags action=%d args=%d\n",
			talih_pass2_builtins[step].name,
			action != talih_pass2_action, begin != command[3]);
	}
	talih_pass2_action_active = true;
	return;

reject:
	pr_emerg("TALIH_PASS2_DIAG: init action %u rejected: %s\n", step, reason);
	talih_pass2_stop(-ECANCELED);
}

static void talih_pass2_report_mounts(void)
{
	static const char * const paths[] = {
		"/dev/blkio", "/dev/cpuctl", "/dev/cpuset", "/dev/memcg",
		"/sys/fs/cgroup", "/sys/fs/cgroup/apps", "/sys/fs/cgroup/system",
		"/dev/memcg/freeze-app", "/linkerconfig", "/linkerconfig/ld.config.txt",
		"/data", "/metadata",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(paths); i++) {
		struct path path;
		struct super_block *sb;
		int err = kern_path(paths[i], LOOKUP_FOLLOW, &path);

		if (err) {
			pr_info("TALIH_PASS2_DIAG: path %s lookup=%d\n",
				paths[i], err);
			continue;
		}
		sb = path.dentry->d_sb;
		pr_info("TALIH_PASS2_DIAG: path %s fstype=%s ro=%d sb=%s\n",
			paths[i], sb->s_type->name, __mnt_is_readonly(path.mnt),
			sb->s_id);
		path_put(&path);
	}
}

static void talih_pass2_action_return(struct callback_head *work)
{
	unsigned long result = untagged_addr(talih_pass2_result);
	unsigned int step = talih_pass2_next_action;
	u32 tag;

	/* 公共返回点的原指令会覆盖 x19；取断点保存的 Result 地址。 */
	if (!result || result > TASK_SIZE - 0x24 ||
	    !talih_pass2_read_user(result + 0x20, &tag, sizeof(tag)) || tag > 1) {
		pr_emerg("TALIH_PASS2_DIAG: init action %u result invalid\n", step);
		talih_pass2_stop(-EFAULT);
	}

	if (step < ARRAY_SIZE(talih_pass2_builtins)) {
		pr_info("TALIH_PASS2_DIAG: builtin %s returned, result=%u\n",
			talih_pass2_builtins[step].name, tag);
		if (tag) {
			talih_pass2_report_mounts();
			talih_pass2_stop(-ECANCELED);
		}
	} else {
		const struct talih_pass2_rc_command *entry;

		entry = &talih_pass2_early_init[step - ARRAY_SIZE(talih_pass2_builtins)];
		pr_info("TALIH_PASS2_DIAG: early-init line %u %s returned, result=%u\n",
			entry->line, entry->args[0], tag);
		talih_pass2_rc_errors += tag;
	}

	talih_pass2_action_active = false;
	if (++talih_pass2_next_action == ARRAY_SIZE(talih_pass2_builtins) +
	    ARRAY_SIZE(talih_pass2_early_init)) {
		pr_emerg("TALIH_PASS2_DIAG: early-init prefix returned, before ueventd; errors=%u\n",
			 talih_pass2_rc_errors);
		talih_pass2_report_mounts();
		talih_pass2_stop(0);
	}
}

static int talih_pass2_action_hit(struct uprobe_consumer *self,
				  struct pt_regs *regs)
{
	struct talih_pass2_probe *probe;
	struct callback_head *work;

	if (current->mm != READ_ONCE(talih_pass2_second_mm))
		return 0;
	probe = container_of(self, struct talih_pass2_probe, consumer);
	if (task_pid_nr(current) != 1 || instruction_pointer(regs) != probe->pc)
		panic("TALIH_PASS2_DIAG: unexpected init action probe hit");
	if (talih_pass2_next_action >= ARRAY_SIZE(talih_pass2_builtins) +
	    ARRAY_SIZE(talih_pass2_early_init))
		panic("TALIH_PASS2_DIAG: init action after early-init prefix");

	if (probe->offset == 0xe8870UL) {
		if (talih_pass2_action_active)
			panic("TALIH_PASS2_DIAG: nested init action blocked");
		if (regs->regs[30] != talih_pass2_init_bias + TALIH_PASS2_ACTION_CALL_RET)
			panic("TALIH_PASS2_DIAG: unexpected init action caller");
		talih_pass2_action = regs->regs[0];
		talih_pass2_command = regs->regs[1];
		work = &talih_pass2_check_work;
	} else {
		if (!talih_pass2_action_active || regs->regs[30] != probe->pc)
			panic("TALIH_PASS2_DIAG: unverified builtin return blocked");
		talih_pass2_result = regs->regs[19];
		work = &talih_pass2_return_work;
	}

	/* 在持锁回调之外、返回用户态之前检查命令或重启。 */
	if (task_work_add(current, work, true))
		panic("TALIH_PASS2_DIAG: failed to queue builtin probe work");
	return 0;
}

static bool talih_pass2_second_filter(struct uprobe_consumer *self,
				       enum uprobe_filter_ctx ctx,
				       struct mm_struct *mm)
{
	return mm == READ_ONCE(talih_pass2_second_mm);
}

static struct talih_pass2_probe talih_pass2_action_probes[] = {
	{
		.offset = 0xe8870UL,
		.insn = 0xd10383ffU,
		.consumer = {
			.handler = talih_pass2_action_hit,
			.filter = talih_pass2_second_filter,
		},
	}, {
		.offset = 0xe77fcUL,
		.insn = 0xf94003f3U,
		.consumer = {
			.handler = talih_pass2_action_hit,
			.filter = talih_pass2_second_filter,
		},
	},
};

static int talih_pass2_arm_action_probe(struct mm_struct *mm, struct inode *inode,
					struct talih_pass2_probe *probe)
{
	struct vm_area_struct *vma;
	unsigned long addr = 0;
	__le32 insn;
	int ret;

	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		unsigned long delta;

		if (!vma->vm_file || file_inode(vma->vm_file) != inode ||
		    (vma->vm_flags & (VM_EXEC | VM_WRITE)) != VM_EXEC ||
		    vma->vm_pgoff > (probe->offset >> PAGE_SHIFT))
			continue;
		delta = probe->offset - (vma->vm_pgoff << PAGE_SHIFT);
		if (delta + sizeof(insn) <= vma->vm_end - vma->vm_start) {
			addr = vma->vm_start + delta;
			break;
		}
	}
	up_read(&mm->mmap_sem);
	if (addr < probe->offset ||
	    !talih_pass2_read_user(addr, &insn, sizeof(insn)) ||
	    le32_to_cpu(insn) != probe->insn)
		return -ENOEXEC;

	probe->pc = addr;
	ret = uprobe_register(inode, probe->offset, &probe->consumer);
	if (ret)
		return ret;
	if (!talih_pass2_read_user(addr, &insn, sizeof(insn)) ||
	    le32_to_cpu(insn) != UPROBE_SWBP_INSN)
		return -EIO;
	return 0;
}

static int talih_pass2_arm_second_stage(struct file *file)
{
	struct mm_struct *mm = current->mm;
	struct inode *inode;
	unsigned int i;
	int ret;

	if (!mm || !file)
		return -EINVAL;
	inode = file_inode(file);
	init_task_work(&talih_pass2_check_work, talih_pass2_check_action);
	init_task_work(&talih_pass2_return_work, talih_pass2_action_return);
	WRITE_ONCE(talih_pass2_second_mm, mm);
	for (i = 0; i < ARRAY_SIZE(talih_pass2_action_probes); i++) {
		struct talih_pass2_probe *probe = &talih_pass2_action_probes[i];
		unsigned long bias;

		ret = talih_pass2_arm_action_probe(mm, inode, probe);
		if (ret)
			return ret;
		bias = probe->pc - probe->offset;
		if (i && bias != talih_pass2_init_bias)
			return -ENOEXEC;
		talih_pass2_init_bias = bias;
	}
	pr_info("TALIH_PASS2_DIAG: startup builtin gate and return probe armed\n");
	return 0;
}
#endif

static bool talih_pass2_match_args(struct linux_binprm *bprm,
				  const char *args, size_t size)
{
	unsigned long pos = bprm->p;

	if (bprm->argc != 2 || strcmp(bprm->filename, "/system/bin/init"))
		return false;

	/* 从已复制到新进程栈上的参数读取，不再访问原用户指针。 */
	while (size) {
		size_t offset = offset_in_page(pos);
		size_t count = min(size, PAGE_SIZE - offset);
		struct page *page = get_arg_page(bprm, pos, 0);
		const char *addr;
		bool match;

		if (!page)
			return false;
		addr = kmap(page);
		match = !memcmp(addr + offset, args, count);
		kunmap(page);
		put_arg_page(page);
		if (!match)
			return false;
		pos += count;
		args += count;
		size -= count;
	}
	return true;
}

static bool talih_pass2_check_selinux_stage(struct linux_binprm *bprm)
{
	static const char setup[] = "/system/bin/init\0selinux_setup";
	static const char next[] = "/system/bin/init\0second_stage";

	if (talih_pass2_selinux_entered) {
		if (talih_pass2_match_args(bprm, next, sizeof(next))) {
#ifdef CONFIG_TALIH_PASS2_SECOND_STAGE_DIAG
			if (talih_pass2_policy_loaded &&
			    !talih_pass2_second_attempted) {
				talih_pass2_second_attempted = true;
				return true;
			}
#endif
			pr_emerg("TALIH_PASS2_DIAG: second_stage blocked before exec\n");
		} else {
			pr_emerg("TALIH_PASS2_DIAG: unexpected PID 1 exec blocked\n");
		}
		talih_pass2_stop(-ECANCELED);
	}
	if (!talih_pass2_match_args(bprm, setup, sizeof(setup)))
		talih_pass2_stop(-EINVAL);
	return false;
}

static unsigned int talih_pass2_recovery_stage;

static bool talih_pass2_is_recovery(void)
{
	return get_boot_mode() == RECOVERY_BOOT &&
	       !strstr(saved_command_line, "androidboot.force_normal_boot=");
}

static void talih_pass2_check_recovery_stage(struct linux_binprm *bprm)
{
	static const char setup[] = "/system/bin/init\0selinux_setup";
	static const char next[] = "/system/bin/init\0second_stage";
	struct file *exe;
	bool same_path;

	if (talih_pass2_recovery_stage == 0) {
		if (!talih_pass2_match_args(bprm, setup, sizeof(setup)))
			talih_pass2_stop(-EINVAL);
	} else if (talih_pass2_recovery_stage == 1) {
		if (!talih_pass2_match_args(bprm, next, sizeof(next)))
			talih_pass2_stop(-EINVAL);
	} else {
		talih_pass2_stop(-ECANCELED);
	}

	/* /init 和这两次恢复态交棒必须解析到同一个 ramdisk 文件。 */
	exe = get_mm_exe_file(current->mm);
	if (!exe)
		talih_pass2_stop(-ENOENT);
	same_path = path_equal(&exe->f_path, &bprm->file->f_path);
	fput(exe);
	if (!same_path)
		talih_pass2_stop(-EXDEV);
}
#endif

static int exec_binprm(struct linux_binprm *bprm)
{
	pid_t old_pid, old_vpid;
	int ret;
#ifdef CONFIG_TALIH_PASS2_BOOT_DIAG
	bool stop_before_userspace = task_pid_nr(current) == 1 && current->mm;
	bool recovery = false;
#ifdef CONFIG_TALIH_PASS2_SELINUX_DIAG
	bool second_stage = false;
#endif

	if (stop_before_userspace) {
#ifdef CONFIG_TALIH_PASS2_SELINUX_DIAG
		recovery = talih_pass2_is_recovery();
		if (recovery)
			talih_pass2_check_recovery_stage(bprm);
		else
			second_stage = talih_pass2_check_selinux_stage(bprm);
#endif
		ret = talih_pass2_read_init(bprm, recovery);
		if (ret)
			talih_pass2_stop(ret);
	}
#endif

	/* Need to fetch pid before load_binary changes it */
	old_pid = current->pid;
	rcu_read_lock();
	old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
	rcu_read_unlock();

	ret = search_binary_handler(bprm);
#ifdef CONFIG_TALIH_PASS2_BOOT_DIAG
	if (stop_before_userspace) {
#ifdef CONFIG_TALIH_PASS2_SELINUX_DIAG
		if (ret < 0)
			talih_pass2_stop(ret);
		if (recovery) {
			talih_pass2_recovery_stage++;
			pr_info("TALIH_PASS2_DIAG: entering recovery %s\n",
				talih_pass2_recovery_stage == 1 ? "selinux_setup" :
				"second_stage");
		} else if (second_stage) {
#ifdef CONFIG_TALIH_PASS2_SECOND_STAGE_DIAG
			ret = talih_pass2_arm_second_stage(bprm->file);
			if (ret) {
				pr_emerg("TALIH_PASS2_DIAG: cgroup probes not armed\n");
				talih_pass2_stop(ret);
			}
#else
			talih_pass2_stop(-EOPNOTSUPP);
#endif
		} else {
			talih_pass2_selinux_entered = true;
			pr_info("TALIH_PASS2_DIAG: entering selinux_setup\n");
		}
#else
		talih_pass2_stop(ret);
#endif
	}
#endif
	if (ret >= 0) {
		audit_bprm(bprm);
		trace_sched_process_exec(current, old_pid, bprm);
		ptrace_event(PTRACE_EVENT_EXEC, old_vpid);
		proc_exec_connector(current);
	}

	return ret;
}

/*
 * sys_execve() executes a new program.
 */
static int do_execveat_common(int fd, struct filename *filename,
			      struct user_arg_ptr argv,
			      struct user_arg_ptr envp,
			      int flags)
{
	char *pathbuf = NULL;
	struct linux_binprm *bprm;
	struct file *file;
	struct files_struct *displaced;
	int retval;

	if (IS_ERR(filename))
		return PTR_ERR(filename);

#ifdef CONFIG_KSU_SUSFS
	/* Mark user app processes (uid >= 10000) for SUSFS hiding paths.
	 * Zygote spawns apps with uid already set before exec, so this
	 * covers every app process incl. isolated ones. */
	if (unlikely(current_uid().val >= 10000))
		current->susfs_task_state |= TASK_STRUCT_NON_ROOT_USER_APP_PROC;
#endif

	/*
	 * We move the actual failure in case of RLIMIT_NPROC excess from
	 * set*uid() to execve() because too many poorly written programs
	 * don't check setuid() return code.  Here we additionally recheck
	 * whether NPROC limit is still exceeded.
	 */
	if ((current->flags & PF_NPROC_EXCEEDED) &&
	    atomic_read(&current_user()->processes) > rlimit(RLIMIT_NPROC)) {
		retval = -EAGAIN;
		goto out_ret;
	}

	/* We're below the limit (still or again), so we don't want to make
	 * further execve() calls fail. */
	current->flags &= ~PF_NPROC_EXCEEDED;

	retval = unshare_files(&displaced);
	if (retval)
		goto out_ret;

	retval = -ENOMEM;
	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
	if (!bprm)
		goto out_files;

	retval = prepare_bprm_creds(bprm);
	if (retval)
		goto out_free;

	check_unsafe_exec(bprm);
	current->in_execve = 1;

	file = do_open_execat(fd, filename, flags);
	retval = PTR_ERR(file);
	if (IS_ERR(file))
		goto out_unmark;

	sched_exec();

	bprm->file = file;
	if (fd == AT_FDCWD || filename->name[0] == '/') {
		bprm->filename = filename->name;
	} else {
		if (filename->name[0] == '\0')
			pathbuf = kasprintf(GFP_KERNEL, "/dev/fd/%d", fd);
		else
			pathbuf = kasprintf(GFP_KERNEL, "/dev/fd/%d/%s",
					    fd, filename->name);
		if (!pathbuf) {
			retval = -ENOMEM;
			goto out_unmark;
		}
		/*
		 * Record that a name derived from an O_CLOEXEC fd will be
		 * inaccessible after exec. Relies on having exclusive access to
		 * current->files (due to unshare_files above).
		 */
		if (close_on_exec(fd, rcu_dereference_raw(current->files->fdt)))
			bprm->interp_flags |= BINPRM_FLAGS_PATH_INACCESSIBLE;
		bprm->filename = pathbuf;
	}
	bprm->interp = bprm->filename;

	retval = bprm_mm_init(bprm);
	if (retval)
		goto out_unmark;

	bprm->argc = count(argv, MAX_ARG_STRINGS);
	if ((retval = bprm->argc) < 0)
		goto out;

	bprm->envc = count(envp, MAX_ARG_STRINGS);
	if ((retval = bprm->envc) < 0)
		goto out;

	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;

	retval = copy_strings_kernel(1, &bprm->filename, bprm);
	if (retval < 0)
		goto out;

	bprm->exec = bprm->p;
	retval = copy_strings(bprm->envc, envp, bprm);
	if (retval < 0)
		goto out;

	retval = copy_strings(bprm->argc, argv, bprm);
	if (retval < 0)
		goto out;

	retval = exec_binprm(bprm);
	if (retval < 0)
		goto out;

	/* execve succeeded */
	current->fs->in_exec = 0;
	current->in_execve = 0;
	membarrier_execve(current);
	acct_update_integrals(current);
	task_numa_free(current, false);
	free_bprm(bprm);
	kfree(pathbuf);
	putname(filename);
	if (displaced)
		put_files_struct(displaced);
	return retval;

out:
	if (bprm->mm) {
		acct_arg_size(bprm, 0);
		mmput(bprm->mm);
	}

out_unmark:
	current->fs->in_exec = 0;
	current->in_execve = 0;

out_free:
	free_bprm(bprm);
	kfree(pathbuf);

out_files:
	if (displaced)
		reset_files_struct(displaced);
out_ret:
	putname(filename);
	return retval;
}

int do_execve(struct filename *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
#endif
	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}

int do_execveat(int fd, struct filename *filename,
		const char __user *const __user *__argv,
		const char __user *const __user *__envp,
		int flags)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };

	return do_execveat_common(fd, filename, argv, envp, flags);
}

#ifdef CONFIG_COMPAT
static int compat_do_execve(struct filename *filename,
	const compat_uptr_t __user *__argv,
	const compat_uptr_t __user *__envp)
{
	struct user_arg_ptr argv = {
		.is_compat = true,
		.ptr.compat = __argv,
	};
	struct user_arg_ptr envp = {
		.is_compat = true,
		.ptr.compat = __envp,
	};
	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}

static int compat_do_execveat(int fd, struct filename *filename,
			      const compat_uptr_t __user *__argv,
			      const compat_uptr_t __user *__envp,
			      int flags)
{
	struct user_arg_ptr argv = {
		.is_compat = true,
		.ptr.compat = __argv,
	};
	struct user_arg_ptr envp = {
		.is_compat = true,
		.ptr.compat = __envp,
	};
	return do_execveat_common(fd, filename, argv, envp, flags);
}
#endif

void set_binfmt(struct linux_binfmt *new)
{
	struct mm_struct *mm = current->mm;

	if (mm->binfmt)
		module_put(mm->binfmt->module);

	mm->binfmt = new;
	if (new)
		__module_get(new->module);
}
EXPORT_SYMBOL(set_binfmt);

/*
 * set_dumpable stores three-value SUID_DUMP_* into mm->flags.
 */
void set_dumpable(struct mm_struct *mm, int value)
{
	unsigned long old, new;

	if (WARN_ON((unsigned)value > SUID_DUMP_ROOT))
		return;

	do {
		old = ACCESS_ONCE(mm->flags);
		new = (old & ~MMF_DUMPABLE_MASK) | value;
	} while (cmpxchg(&mm->flags, old, new) != old);
}

SYSCALL_DEFINE3(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	return do_execve(getname(filename), argv, envp);
}

SYSCALL_DEFINE5(execveat,
		int, fd, const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp,
		int, flags)
{
	int lookup_flags = (flags & AT_EMPTY_PATH) ? LOOKUP_EMPTY : 0;

	return do_execveat(fd,
			   getname_flags(filename, lookup_flags, NULL),
			   argv, envp, flags);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE3(execve, const char __user *, filename,
	const compat_uptr_t __user *, argv,
	const compat_uptr_t __user *, envp)
{
	return compat_do_execve(getname(filename), argv, envp);
}

COMPAT_SYSCALL_DEFINE5(execveat, int, fd,
		       const char __user *, filename,
		       const compat_uptr_t __user *, argv,
		       const compat_uptr_t __user *, envp,
		       int,  flags)
{
	int lookup_flags = (flags & AT_EMPTY_PATH) ? LOOKUP_EMPTY : 0;

	return compat_do_execveat(fd,
				  getname_flags(filename, lookup_flags, NULL),
				  argv, envp, flags);
}
#endif
