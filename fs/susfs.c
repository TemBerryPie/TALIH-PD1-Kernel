#include <linux/version.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/namei.h>
#include <linux/list.h>
#include <linux/init_task.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/fdtable.h>
#include <linux/statfs.h>
#include <linux/susfs.h>
#include "mount.h"

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern int path_umount(struct path *path, int flags);
#endif

static spinlock_t susfs_spin_lock;

extern bool susfs_is_current_ksu_domain(void);

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
bool susfs_is_log_enabled __read_mostly = true;
#define SUSFS_LOGI(fmt, ...) if (susfs_is_log_enabled) pr_info("susfs:[%u][%d][%s] " fmt, current_uid().val, current->pid, __func__, ##__VA_ARGS__)
#define SUSFS_LOGE(fmt, ...) if (susfs_is_log_enabled) pr_err("susfs:[%u][%d][%s]" fmt, current_uid().val, current->pid, __func__, ##__VA_ARGS__)
#else
#define SUSFS_LOGI(fmt, ...) 
#define SUSFS_LOGE(fmt, ...) 
#endif

/* sus_path */
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
static DEFINE_HASHTABLE(SUS_PATH_HLIST, 10);
static int susfs_update_sus_path_inode(char *target_pathname) {
	struct path p;
	struct inode *inode = NULL;
	const char *dev_type;

	if (kern_path(target_pathname, LOOKUP_FOLLOW, &p)) {
		SUSFS_LOGE("Failed opening file '%s'\n", target_pathname);
		return 1;
	}

	// - We don't allow paths of which filesystem type is "tmpfs" or "fuse".
	//   For tmpfs, because its starting inode->i_ino will begin with 1 again,
	//   so it will cause wrong comparison in function susfs_sus_ino_for_filldir64()
	//   For fuse, which is almost storage related, sus_path should not handle any paths of
	//   which filesystem is "fuse" as well, since app can write to "fuse" and lookup files via
	//   like binder / system API (you can see the uid is changed to 1000)/
	// - so sus_path should be applied only on read-only filesystem like "erofs" or "f2fs", but not "tmpfs" or "fuse",
	//   people may rely on HMA for /data isolation instead.
	dev_type = p.mnt->mnt_sb->s_type->name;
	if (!strcmp(dev_type, "tmpfs") ||
		!strcmp(dev_type, "fuse")) {
		SUSFS_LOGE("target_pathname: '%s' cannot be added since its filesystem type is '%s'\n",
						target_pathname, dev_type);
		path_put(&p);
		return 1;
	}

	inode = d_inode(p.dentry);
	if (!inode) {
		SUSFS_LOGE("inode is NULL\n");
		path_put(&p);
		return 1;
	}

	if (!(inode->i_state & INODE_STATE_SUS_PATH)) {
		spin_lock(&inode->i_lock);
		inode->i_state |= INODE_STATE_SUS_PATH;
		spin_unlock(&inode->i_lock);
	}
	path_put(&p);
	return 0;
}

int susfs_add_sus_path(struct st_susfs_sus_path* __user user_info) {
	struct st_susfs_sus_path info;
	struct st_susfs_sus_path_hlist *new_entry, *tmp_entry;
	struct hlist_node *tmp_node;
	int bkt;
	bool update_hlist = false;

	if (copy_from_user(&info, user_info, sizeof(info))) {
		SUSFS_LOGE("failed copying from userspace\n");
		return 1;
	}

	spin_lock(&susfs_spin_lock);
	hash_for_each_safe(SUS_PATH_HLIST, bkt, tmp_node, tmp_entry, node) {
	if (!strcmp(tmp_entry->target_pathname, info.target_pathname)) {
			hash_del(&tmp_entry->node);
			kfree(tmp_entry);
			update_hlist = true;
			break;
		}
	}
	spin_unlock(&susfs_spin_lock);

	new_entry = kmalloc(sizeof(struct st_susfs_sus_path_hlist), GFP_KERNEL);
	if (!new_entry) {
		SUSFS_LOGE("no enough memory\n");
		return 1;
	}

	new_entry->target_ino = info.target_ino;
	strncpy(new_entry->target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME-1);
	if (susfs_update_sus_path_inode(new_entry->target_pathname)) {
		kfree(new_entry);
		return 1;
	}
	spin_lock(&susfs_spin_lock);
	hash_add(SUS_PATH_HLIST, &new_entry->node, info.target_ino);
	if (update_hlist) {
		SUSFS_LOGI("target_ino: '%lu', target_pathname: '%s' is successfully updated to SUS_PATH_HLIST\n",
				new_entry->target_ino, new_entry->target_pathname);	
	} else {
		SUSFS_LOGI("target_ino: '%lu', target_pathname: '%s' is successfully added to SUS_PATH_HLIST\n",
				new_entry->target_ino, new_entry->target_pathname);
	}
	spin_unlock(&susfs_spin_lock);
	return 0;
}

int susfs_sus_ino_for_filldir64(unsigned long ino) {
	struct st_susfs_sus_path_hlist *entry;

	hash_for_each_possible(SUS_PATH_HLIST, entry, node, ino) {
		if (entry->target_ino == ino)
			return 1;
	}
	return 0;
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH

/* sus_mount */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
static LIST_HEAD(LH_SUS_MOUNT);
static void susfs_update_sus_mount_inode(char *target_pathname) {
	struct mount *mnt = NULL;
	struct path p;
	struct inode *inode = NULL;
	int err = 0;

	err = kern_path(target_pathname, LOOKUP_FOLLOW, &p);
	if (err) {
		SUSFS_LOGE("Failed opening file '%s'\n", target_pathname);
		return;
	}

	/* It is important to check if the mount has a legit peer group id, if so we cannot add them to sus_mount,
	 * since there are chances that the mount is a legit mountpoint, and it can be misued by other susfs functions in future.
	 * And by doing this it won't affect the sus_mount check as other susfs functions check by mnt->mnt_id
	 * instead of INODE_STATE_SUS_MOUNT.
	 */
	mnt = real_mount(p.mnt);
	if (mnt->mnt_group_id > 0 && // 0 means no peer group
		mnt->mnt_group_id < DEFAULT_SUS_MNT_GROUP_ID) {
		SUSFS_LOGE("skip setting SUS_MOUNT inode state for path '%s' since its source mount has a legit peer group id\n", target_pathname);
		return;
	}

	inode = d_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		SUSFS_LOGE("inode is NULL\n");
		return;
	}

	if (!(inode->i_state & INODE_STATE_SUS_MOUNT)) {
		spin_lock(&inode->i_lock);
		inode->i_state |= INODE_STATE_SUS_MOUNT;
		spin_unlock(&inode->i_lock);
	}
	path_put(&p);
}

int susfs_add_sus_mount(struct st_susfs_sus_mount* __user user_info) {
	struct st_susfs_sus_mount_list *cursor = NULL, *temp = NULL;
	struct st_susfs_sus_mount_list *new_list = NULL;
	struct st_susfs_sus_mount info;

	if (copy_from_user(&info, user_info, sizeof(info))) {
		SUSFS_LOGE("failed copying from userspace\n");
		return 1;
	}

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef CONFIG_MIPS
	info.target_dev = new_decode_dev(info.target_dev);
#else
	info.target_dev = huge_decode_dev(info.target_dev);
#endif /* CONFIG_MIPS */
#else
	info.target_dev = old_decode_dev(info.target_dev);
#endif /* defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64) */

	list_for_each_entry_safe(cursor, temp, &LH_SUS_MOUNT, list) {
		if (unlikely(!strcmp(cursor->info.target_pathname, info.target_pathname))) {
			spin_lock(&susfs_spin_lock);
			memcpy(&cursor->info, &info, sizeof(info));
			susfs_update_sus_mount_inode(cursor->info.target_pathname);
			SUSFS_LOGI("target_pathname: '%s', target_dev: '%lu', is successfully updated to LH_SUS_MOUNT\n",
						cursor->info.target_pathname, cursor->info.target_dev);
			spin_unlock(&susfs_spin_lock);
			return 0;
		}
	}

	new_list = kmalloc(sizeof(struct st_susfs_sus_mount_list), GFP_KERNEL);
	if (!new_list) {
		SUSFS_LOGE("no enough memory\n");
		return 1;
	}

	memcpy(&new_list->info, &info, sizeof(info));
	susfs_update_sus_mount_inode(new_list->info.target_pathname);

	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_spin_lock);
	list_add_tail(&new_list->list, &LH_SUS_MOUNT);
	SUSFS_LOGI("target_pathname: '%s', target_dev: '%lu', is successfully added to LH_SUS_MOUNT\n",
				new_list->info.target_pathname, new_list->info.target_dev);
	spin_unlock(&susfs_spin_lock);
	return 0;
}

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
int susfs_auto_add_sus_bind_mount(const char *pathname, struct path *path_target) {
	struct mount *mnt;
	struct inode *inode;

	mnt = real_mount(path_target->mnt);
	if (mnt->mnt_group_id > 0 && // 0 means no peer group
		mnt->mnt_group_id < DEFAULT_SUS_MNT_GROUP_ID) {
		SUSFS_LOGE("skip setting SUS_MOUNT inode state for path '%s' since its source mount has a legit peer group id\n", pathname);
		// return 0 here as we still want it to be added to try_umount list
		return 0;
	}
	inode = path_target->dentry->d_inode;
	if (!inode) return 1;
	if (!(inode->i_state & INODE_STATE_SUS_MOUNT)) {
		spin_lock(&inode->i_lock);
		inode->i_state |= INODE_STATE_SUS_MOUNT;
		spin_unlock(&inode->i_lock);
		SUSFS_LOGI("set SUS_MOUNT inode state for source bind mount path '%s'\n", pathname);
	}
	return 0;
}
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
void susfs_auto_add_sus_ksu_default_mount(const char __user *to_pathname) {
	char *pathname = NULL;
	struct path path;
	struct inode *inode;

	pathname = kmalloc(SUSFS_MAX_LEN_PATHNAME, GFP_KERNEL);
	if (!pathname) {
		SUSFS_LOGE("no enough memory\n");
		return;
	}
	// Here we need to re-retrieve the struct path as we want the new struct path, not the old one
	if (strncpy_from_user(pathname, to_pathname, SUSFS_MAX_LEN_PATHNAME-1) < 0) {
		SUSFS_LOGE("strncpy_from_user()\n");
		goto out_free_pathname;
		return;
	}
	if ((!strncmp(pathname, "/data/adb/modules", 17) ||
		 !strncmp(pathname, "/debug_ramdisk", 14) ||
		 !strncmp(pathname, "/system", 7) ||
		 !strncmp(pathname, "/system_ext", 11) ||
		 !strncmp(pathname, "/vendor", 7) ||
		 !strncmp(pathname, "/product", 8) ||
		 !strncmp(pathname, "/odm", 4)) &&
		 !kern_path(pathname, LOOKUP_FOLLOW, &path)) {
		goto set_inode_sus_mount;
	}
	goto out_free_pathname;
set_inode_sus_mount:
	inode = path.dentry->d_inode;
	if (!inode) {
		goto out_path_put;
		return;
	}
	if (!(inode->i_state & INODE_STATE_SUS_MOUNT)) {
		spin_lock(&inode->i_lock);
		inode->i_state |= INODE_STATE_SUS_MOUNT;
		spin_unlock(&inode->i_lock);
		SUSFS_LOGI("set SUS_MOUNT inode state for default KSU mount path '%s'\n", pathname);
	}
out_path_put:
	path_put(&path);
out_free_pathname:
	kfree(pathname);
}
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

/* sus_kstat */
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
static DEFINE_HASHTABLE(SUS_KSTAT_HLIST, 10);
static int susfs_update_sus_kstat_inode(char *target_pathname) {
	struct path p;
	struct inode *inode = NULL;
	int err = 0;

	err = kern_path(target_pathname, LOOKUP_FOLLOW, &p);
	if (err) {
		SUSFS_LOGE("Failed opening file '%s'\n", target_pathname);
		return 1;
	}

	// We don't allow path of which filesystem type is "tmpfs", because its inode->i_ino is starting from 1 again,
	// which will cause wrong comparison in function susfs_sus_ino_for_filldir64()
	if (strcmp(p.mnt->mnt_sb->s_type->name, "tmpfs") == 0) {
		SUSFS_LOGE("target_pathname: '%s' cannot be added since its filesystem is 'tmpfs'\n", target_pathname);
		path_put(&p);
		return 1;
	}

	inode = d_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		SUSFS_LOGE("inode is NULL\n");
		return 1;
	}

	if (!(inode->i_state & INODE_STATE_SUS_KSTAT)) {
		spin_lock(&inode->i_lock);
		inode->i_state |= INODE_STATE_SUS_KSTAT;
		spin_unlock(&inode->i_lock);
	}
	path_put(&p);
	return 0;
}

int susfs_add_sus_kstat(struct st_susfs_sus_kstat* __user user_info) {
	struct st_susfs_sus_kstat info;
	struct st_susfs_sus_kstat_hlist *new_entry, *tmp_entry;
	struct hlist_node *tmp_node;
	int bkt;
	bool update_hlist = false;

	if (copy_from_user(&info, user_info, sizeof(info))) {
		SUSFS_LOGE("failed copying from userspace\n");
		return 1;
	}

	if (strlen(info.target_pathname) == 0) {
		SUSFS_LOGE("target_pathname is an empty string\n");
		return 1;
	}

	spin_lock(&susfs_spin_lock);
	hash_for_each_safe(SUS_KSTAT_HLIST, bkt, tmp_node, tmp_entry, node) {
		if (!strcmp(tmp_entry->info.target_pathname, info.target_pathname)) {
			hash_del(&tmp_entry->node);
			kfree(tmp_entry);
			update_hlist = true;
			break;
		}
	}
	spin_unlock(&susfs_spin_lock);

	new_entry = kmalloc(sizeof(struct st_susfs_sus_kstat_hlist), GFP_KERNEL);
	if (!new_entry) {
		SUSFS_LOGE("no enough memory\n");
		return 1;
	}

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef CONFIG_MIPS
	info.spoofed_dev = new_decode_dev(info.spoofed_dev);
#else
	info.spoofed_dev = huge_decode_dev(info.spoofed_dev);
#endif /* CONFIG_MIPS */
#else
	info.spoofed_dev = old_decode_dev(info.spoofed_dev);
#endif /* defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64) */

	new_entry->target_ino = info.target_ino;
	memcpy(&new_entry->info, &info, sizeof(info));

	if (susfs_update_sus_kstat_inode(new_entry->info.target_pathname)) {
		kfree(new_entry);
		return 1;
	}

	spin_lock(&susfs_spin_lock);
	hash_add(SUS_KSTAT_HLIST, &new_entry->node, info.target_ino);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	if (update_hlist) {
		SUSFS_LOGI("is_statically: '%d', target_ino: '%lu', target_pathname: '%s', spoofed_ino: '%lu', spoofed_dev: '%lu', spoofed_nlink: '%u', spoofed_size: '%llu', spoofed_atime_tv_sec: '%ld', spoofed_mtime_tv_sec: '%ld', spoofed_ctime_tv_sec: '%ld', spoofed_atime_tv_nsec: '%ld', spoofed_mtime_tv_nsec: '%ld', spoofed_ctime_tv_nsec: '%ld', spoofed_blksize: '%lu', spoofed_blocks: '%llu', is successfully added to SUS_KSTAT_HLIST\n",
				new_entry->info.is_statically, new_entry->info.target_ino, new_entry->info.target_pathname,
				new_entry->info.spoofed_ino, new_entry->info.spoofed_dev,
				new_entry->info.spoofed_nlink, new_entry->info.spoofed_size,
				new_entry->info.spoofed_atime_tv_sec, new_entry->info.spoofed_mtime_tv_sec, new_entry->info.spoofed_ctime_tv_sec,
				new_entry->info.spoofed_atime_tv_nsec, new_entry->info.spoofed_mtime_tv_nsec, new_entry->info.spoofed_ctime_tv_nsec,
				new_entry->info.spoofed_blksize, new_entry->info.spoofed_blocks);
	} else {
		SUSFS_LOGI("is_statically: '%d', target_ino: '%lu', target_pathname: '%s', spoofed_ino: '%lu', spoofed_dev: '%lu', spoofed_nlink: '%u', spoofed_size: '%llu', spoofed_atime_tv_sec: '%ld', spoofed_mtime_tv_sec: '%ld', spoofed_ctime_tv_sec: '%ld', spoofed_atime_tv_nsec: '%ld', spoofed_mtime_tv_nsec: '%ld', spoofed_ctime_tv_nsec: '%ld', spoofed_blksize: '%lu', spoofed_blocks: '%llu', is successfully updated to SUS_KSTAT_HLIST\n",
				new_entry->info.is_statically, new_entry->info.target_ino, new_entry->info.target_pathname,
				new_entry->info.spoofed_ino, new_entry->info.spoofed_dev,
				new_entry->info.spoofed_nlink, new_entry->info.spoofed_size,
				new_entry->info.spoofed_atime_tv_sec, new_entry->info.spoofed_mtime_tv_sec, new_entry->info.spoofed_ctime_tv_sec,
				new_entry->info.spoofed_atime_tv_nsec, new_entry->info.spoofed_mtime_tv_nsec, new_entry->info.spoofed_ctime_tv_nsec,
				new_entry->info.spoofed_blksize, new_entry->info.spoofed_blocks);
	}
#else
	if (update_hlist) {
		SUSFS_LOGI("is_statically: '%d', target_ino: '%lu', target_pathname: '%s', spoofed_ino: '%lu', spoofed_dev: '%lu', spoofed_nlink: '%u', spoofed_size: '%u', spoofed_atime_tv_sec: '%ld', spoofed_mtime_tv_sec: '%ld', spoofed_ctime_tv_sec: '%ld', spoofed_atime_tv_nsec: '%ld', spoofed_mtime_tv_nsec: '%ld', spoofed_ctime_tv_nsec: '%ld', spoofed_blksize: '%lu', spoofed_blocks: '%llu', is successfully added to SUS_KSTAT_HLIST\n",
				new_entry->info.is_statically, new_entry->info.target_ino, new_entry->info.target_pathname,
				new_entry->info.spoofed_ino, new_entry->info.spoofed_dev,
				new_entry->info.spoofed_nlink, new_entry->info.spoofed_size,
				new_entry->info.spoofed_atime_tv_sec, new_entry->info.spoofed_mtime_tv_sec, new_entry->info.spoofed_ctime_tv_sec,
				new_entry->info.spoofed_atime_tv_nsec, new_entry->info.spoofed_mtime_tv_nsec, new_entry->info.spoofed_ctime_tv_nsec,
				new_entry->info.spoofed_blksize, new_entry->info.spoofed_blocks);
	} else {
		SUSFS_LOGI("is_statically: '%d', target_ino: '%lu', target_pathname: '%s', spoofed_ino: '%lu', spoofed_dev: '%lu', spoofed_nlink: '%u', spoofed_size: '%u', spoofed_atime_tv_sec: '%ld', spoofed_mtime_tv_sec: '%ld', spoofed_ctime_tv_sec: '%ld', spoofed_atime_tv_nsec: '%ld', spoofed_mtime_tv_nsec: '%ld', spoofed_ctime_tv_nsec: '%ld', spoofed_blksize: '%lu', spoofed_blocks: '%llu', is successfully updated to SUS_KSTAT_HLIST\n",
				new_entry->info.is_statically, new_entry->info.target_ino, new_entry->info.target_pathname,
				new_entry->info.spoofed_ino, new_entry->info.spoofed_dev,
				new_entry->info.spoofed_nlink, new_entry->info.spoofed_size,
				new_entry->info.spoofed_atime_tv_sec, new_entry->info.spoofed_mtime_tv_sec, new_entry->info.spoofed_ctime_tv_sec,
				new_entry->info.spoofed_atime_tv_nsec, new_entry->info.spoofed_mtime_tv_nsec, new_entry->info.spoofed_ctime_tv_nsec,
				new_entry->info.spoofed_blksize, new_entry->info.spoofed_blocks);
	}
#endif
	spin_unlock(&susfs_spin_lock);
	return 0;
}

int susfs_update_sus_kstat(struct st_susfs_sus_kstat* __user user_info) {
	struct st_susfs_sus_kstat info;
	struct st_susfs_sus_kstat_hlist *new_entry, *tmp_entry;
	struct hlist_node *tmp_node;
	int bkt;
	int err = 0;

	if (copy_from_user(&info, user_info, sizeof(info))) {
		SUSFS_LOGE("failed copying from userspace\n");
		return 1;
	}

	spin_lock(&susfs_spin_lock);
	hash_for_each_safe(SUS_KSTAT_HLIST, bkt, tmp_node, tmp_entry, node) {
		if (!strcmp(tmp_entry->info.target_pathname, info.target_pathname)) {
			if (susfs_update_sus_kstat_inode(tmp_entry->info.target_pathname)) {
				err = 1;
				goto out_spin_unlock;
			}
			new_entry = kmalloc(sizeof(struct st_susfs_sus_kstat_hlist), GFP_KERNEL);
			if (!new_entry) {
				SUSFS_LOGE("no enough memory\n");
				err = 1;
				goto out_spin_unlock;
			}
			memcpy(&new_entry->info, &tmp_entry->info, sizeof(tmp_entry->info));
			SUSFS_LOGI("updating target_ino from '%lu' to '%lu' for pathname: '%s' in SUS_KSTAT_HLIST\n",
							new_entry->info.target_ino, info.target_ino, info.target_pathname);
			new_entry->target_ino = info.target_ino;
			new_entry->info.target_ino = info.target_ino;
			if (info.spoofed_size > 0) {
				SUSFS_LOGI("updating spoofed_size from '%lld' to '%lld' for pathname: '%s' in SUS_KSTAT_HLIST\n",
								new_entry->info.spoofed_size, info.spoofed_size, info.target_pathname);
				new_entry->info.spoofed_size = info.spoofed_size;
			}
			if (info.spoofed_blocks > 0) {
				SUSFS_LOGI("updating spoofed_blocks from '%llu' to '%llu' for pathname: '%s' in SUS_KSTAT_HLIST\n",
								new_entry->info.spoofed_blocks, info.spoofed_blocks, info.target_pathname);
				new_entry->info.spoofed_blocks = info.spoofed_blocks;
			}
			hash_del(&tmp_entry->node);
			kfree(tmp_entry);
			hash_add(SUS_KSTAT_HLIST, &new_entry->node, info.target_ino);
			goto out_spin_unlock;
		}
	}
out_spin_unlock:
	spin_unlock(&susfs_spin_lock);
	return err;
}

void susfs_sus_ino_for_generic_fillattr(unsigned long ino, struct kstat *stat) {
	struct st_susfs_sus_kstat_hlist *entry;

	hash_for_each_possible(SUS_KSTAT_HLIST, entry, node, ino) {
		if (entry->target_ino == ino) {
			stat->dev = entry->info.spoofed_dev;
			stat->ino = entry->info.spoofed_ino;
			stat->nlink = entry->info.spoofed_nlink;
			stat->size = entry->info.spoofed_size;
			stat->atime.tv_sec = entry->info.spoofed_atime_tv_sec;
			stat->atime.tv_nsec = entry->info.spoofed_atime_tv_nsec;
			stat->mtime.tv_sec = entry->info.spoofed_mtime_tv_sec;
			stat->mtime.tv_nsec = entry->info.spoofed_mtime_tv_nsec;
			stat->ctime.tv_sec = entry->info.spoofed_ctime_tv_sec;
			stat->ctime.tv_nsec = entry->info.spoofed_ctime_tv_nsec;
			stat->blocks = entry->info.spoofed_blocks;
			stat->blksize = entry->info.spoofed_blksize;
			return;
		}
	}
}

void susfs_sus_ino_for_show_map_vma(unsigned long ino, dev_t *out_dev, unsigned long *out_ino) {
	struct st_susfs_sus_kstat_hlist *entry;

	hash_for_each_possible(SUS_KSTAT_HLIST, entry, node, ino) {
		if (entry->target_ino == ino) {
			*out_dev = entry->info.spoofed_dev;
			*out_ino = entry->info.spoofed_ino;
			return;
		}
	}
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT

/* try_umount */
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
/* 4.14 simplified umount: unmount the path in the current mount namespace. */
void ksu_try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid) {
	struct path path;

	(void)check_mnt;
	(void)uid;
	if (!kern_path(mnt, 0, &path)) {
		path_umount(&path, flags);
	}
}
static LIST_HEAD(LH_TRY_UMOUNT_PATH);
int susfs_add_try_umount(struct st_susfs_try_umount* __user user_info) {
	struct st_susfs_try_umount_list *cursor = NULL, *temp = NULL;
	struct st_susfs_try_umount_list *new_list = NULL;
	struct st_susfs_try_umount info;

	if (copy_from_user(&info, user_info, sizeof(info))) {
		SUSFS_LOGE("failed copying from userspace\n");
		return 1;
	}

	list_for_each_entry_safe(cursor, temp, &LH_TRY_UMOUNT_PATH, list) {
		if (unlikely(!strcmp(info.target_pathname, cursor->info.target_pathname))) {
			SUSFS_LOGE("target_pathname: '%s' is already created in LH_TRY_UMOUNT_PATH\n", info.target_pathname);
			return 1;
		}
	}

	new_list = kmalloc(sizeof(struct st_susfs_try_umount_list), GFP_KERNEL);
	if (!new_list) {
		SUSFS_LOGE("no enough memory\n");
		return 1;
	}

	memcpy(&new_list->info, &info, sizeof(info));

	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_spin_lock);
	list_add_tail(&new_list->list, &LH_TRY_UMOUNT_PATH);
	spin_unlock(&susfs_spin_lock);
	SUSFS_LOGI("target_pathname: '%s', mnt_mode: %d, is successfully added to LH_TRY_UMOUNT_PATH\n", new_list->info.target_pathname, new_list->info.mnt_mode);
	return 0;
}

void susfs_try_umount(uid_t target_uid) {
	struct st_susfs_try_umount_list *cursor = NULL;

	// We should umount in reversed order
	list_for_each_entry_reverse(cursor, &LH_TRY_UMOUNT_PATH, list) {
		if (cursor->info.mnt_mode == TRY_UMOUNT_DEFAULT) {
			ksu_try_umount(cursor->info.target_pathname, false, 0, target_uid);
		} else if (cursor->info.mnt_mode == TRY_UMOUNT_DETACH) {
			ksu_try_umount(cursor->info.target_pathname, false, MNT_DETACH, target_uid);
		} else {
			SUSFS_LOGE("failed umounting '%s' for uid: %d, mnt_mode '%d' not supported\n",
							cursor->info.target_pathname, target_uid, cursor->info.mnt_mode);
		}
	}
}

#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
void susfs_auto_add_try_umount_for_bind_mount(struct path *path) {
	struct st_susfs_try_umount_list *cursor = NULL, *temp = NULL;
	struct st_susfs_try_umount_list *new_list = NULL;
	char *pathname = NULL, *dpath = NULL;
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
	bool is_magic_mount_path = false;
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	if (path->dentry->d_inode->i_state & INODE_STATE_SUS_KSTAT) {
		SUSFS_LOGI("skip adding path to try_umount list as its inode is flagged INODE_STATE_SUS_KSTAT already\n");
		return;
	}
#endif

	pathname = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!pathname) {
		SUSFS_LOGE("no enough memory\n");
		return;
	}

	dpath = d_path(path, pathname, PAGE_SIZE);
	if (!dpath) {
		SUSFS_LOGE("dpath is NULL\n");
		goto out_free_pathname;
	}

#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
	if (strstr(dpath, MAGIC_MOUNT_WORKDIR)) {
		is_magic_mount_path = true;
	}
#endif

	list_for_each_entry_safe(cursor, temp, &LH_TRY_UMOUNT_PATH, list) {
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
		if (is_magic_mount_path && strstr(dpath, cursor->info.target_pathname)) {
			goto out_free_pathname;
		}
#endif
		if (unlikely(!strcmp(dpath, cursor->info.target_pathname))) {
			SUSFS_LOGE("target_pathname: '%s', ino: %lu, is already created in LH_TRY_UMOUNT_PATH\n",
							dpath, path->dentry->d_inode->i_ino);
			goto out_free_pathname;
		}
	}

	new_list = kmalloc(sizeof(struct st_susfs_try_umount_list), GFP_KERNEL);
	if (!new_list) {
		SUSFS_LOGE("no enough memory\n");
		goto out_free_pathname;
	}

#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
	if (is_magic_mount_path) {
		strncpy(new_list->info.target_pathname, dpath + strlen(MAGIC_MOUNT_WORKDIR), SUSFS_MAX_LEN_PATHNAME-1);
		goto out_add_to_list;
	}
#endif
	strncpy(new_list->info.target_pathname, dpath, SUSFS_MAX_LEN_PATHNAME-1);

#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
out_add_to_list:
#endif

	new_list->info.mnt_mode = TRY_UMOUNT_DETACH;

	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_spin_lock);
	list_add_tail(&new_list->list, &LH_TRY_UMOUNT_PATH);
	spin_unlock(&susfs_spin_lock);
	SUSFS_LOGI("target_pathname: '%s', ino: %lu, mnt_mode: %d, is successfully added to LH_TRY_UMOUNT_PATH\n",
					new_list->info.target_pathname, path->dentry->d_inode->i_ino, new_list->info.mnt_mode);
out_free_pathname:
	kfree(pathname);
}
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT

/* spoof_uname */
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
static spinlock_t susfs_uname_spin_lock;
static struct st_susfs_uname my_uname;
static void susfs_my_uname_init(void) {
	memset(&my_uname, 0, sizeof(my_uname));
}

int susfs_set_uname(struct st_susfs_uname* __user user_info) {
	struct st_susfs_uname info;

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_uname))) {
		SUSFS_LOGE("failed copying from userspace.\n");
		return 1;
	}

	spin_lock(&susfs_uname_spin_lock);
	if (!strcmp(info.release, "default")) {
		strncpy(my_uname.release, utsname()->release, __NEW_UTS_LEN);
	} else {
		strncpy(my_uname.release, info.release, __NEW_UTS_LEN);
	}
	if (!strcmp(info.version, "default")) {
		strncpy(my_uname.version, utsname()->version, __NEW_UTS_LEN);
	} else {
		strncpy(my_uname.version, info.version, __NEW_UTS_LEN);
	}
	spin_unlock(&susfs_uname_spin_lock);
	SUSFS_LOGI("setting spoofed release: '%s', version: '%s'\n",
				my_uname.release, my_uname.version);
	return 0;
}

void susfs_spoof_uname(struct new_utsname* tmp) {
	if (unlikely(my_uname.release[0] == '\0' || spin_is_locked(&susfs_uname_spin_lock)))
		return;
	strncpy(tmp->release, my_uname.release, __NEW_UTS_LEN);
	strncpy(tmp->version, my_uname.version, __NEW_UTS_LEN);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME

/* set_log */
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
void susfs_set_log(bool enabled) {
	spin_lock(&susfs_spin_lock);
	susfs_is_log_enabled = enabled;
	spin_unlock(&susfs_spin_lock);
	if (susfs_is_log_enabled) {
		pr_info("susfs: enable logging to kernel");
	} else {
		pr_info("susfs: disable logging to kernel");
	}
}
#endif // #ifdef CONFIG_KSU_SUSFS_ENABLE_LOG

/* spoof_cmdline_or_bootconfig */
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
static char *fake_cmdline_or_bootconfig = NULL;
int susfs_set_cmdline_or_bootconfig(char* __user user_fake_cmdline_or_bootconfig) {
	int res;

	if (!fake_cmdline_or_bootconfig) {
		// 4096 is enough I guess
		fake_cmdline_or_bootconfig = kmalloc(SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE, GFP_KERNEL);
		if (!fake_cmdline_or_bootconfig) {
			SUSFS_LOGE("no enough memory\n");
			return -ENOMEM;
		}
	}

	spin_lock(&susfs_spin_lock);
	memset(fake_cmdline_or_bootconfig, 0, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE);
	res = strncpy_from_user(fake_cmdline_or_bootconfig, user_fake_cmdline_or_bootconfig, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE-1);
	spin_unlock(&susfs_spin_lock);

	if (res > 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
		SUSFS_LOGI("fake_cmdline_or_bootconfig is set, length of string: %lu\n", strlen(fake_cmdline_or_bootconfig));
#else
		SUSFS_LOGI("fake_cmdline_or_bootconfig is set, length of string: %u\n", strlen(fake_cmdline_or_bootconfig));
#endif
		return 0;
	}
	SUSFS_LOGI("failed setting fake_cmdline_or_bootconfig\n");
	return res;
}

int susfs_spoof_cmdline_or_bootconfig(struct seq_file *m) {
	if (fake_cmdline_or_bootconfig != NULL) {
		seq_puts(m, fake_cmdline_or_bootconfig);
		return 0;
	}
	return 1;
}
#endif

/* open_redirect */
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
static DEFINE_HASHTABLE(OPEN_REDIRECT_HLIST, 10);
static int susfs_update_open_redirect_inode(struct st_susfs_open_redirect_hlist *new_entry) {
	struct path path_target;
	struct inode *inode_target;
	int err = 0;

	err = kern_path(new_entry->target_pathname, LOOKUP_FOLLOW, &path_target);
	if (err) {
		SUSFS_LOGE("Failed opening file '%s'\n", new_entry->target_pathname);
		return err;
	}

	inode_target = d_inode(path_target.dentry);
	if (!inode_target) {
		SUSFS_LOGE("inode_target is NULL\n");
		err = 1;
		goto out_path_put_target;
	}

	spin_lock(&inode_target->i_lock);
	inode_target->i_state |= INODE_STATE_OPEN_REDIRECT;
	spin_unlock(&inode_target->i_lock);

out_path_put_target:
	path_put(&path_target);
	return err;
}

int susfs_add_open_redirect(struct st_susfs_open_redirect* __user user_info) {
	struct st_susfs_open_redirect info;
	struct st_susfs_open_redirect_hlist *new_entry, *tmp_entry;
	struct hlist_node *tmp_node;
	int bkt;
	bool update_hlist = false;

	if (copy_from_user(&info, user_info, sizeof(info))) {
		SUSFS_LOGE("failed copying from userspace\n");
		return 1;
	}

	spin_lock(&susfs_spin_lock);
	hash_for_each_safe(OPEN_REDIRECT_HLIST, bkt, tmp_node, tmp_entry, node) {
		if (!strcmp(tmp_entry->target_pathname, info.target_pathname)) {
			hash_del(&tmp_entry->node);
			kfree(tmp_entry);
			update_hlist = true;
			break;
		}
	}
	spin_unlock(&susfs_spin_lock);

	new_entry = kmalloc(sizeof(struct st_susfs_open_redirect_hlist), GFP_KERNEL);
	if (!new_entry) {
		SUSFS_LOGE("no enough memory\n");
		return 1;
	}

	new_entry->target_ino = info.target_ino;
	strncpy(new_entry->target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME-1);
	strncpy(new_entry->redirected_pathname, info.redirected_pathname, SUSFS_MAX_LEN_PATHNAME-1);
	if (susfs_update_open_redirect_inode(new_entry)) {
		SUSFS_LOGE("failed adding path '%s' to OPEN_REDIRECT_HLIST\n", new_entry->target_pathname);
		kfree(new_entry);
		return 1;
	}

	spin_lock(&susfs_spin_lock);
	hash_add(OPEN_REDIRECT_HLIST, &new_entry->node, info.target_ino);
	if (update_hlist) {
		SUSFS_LOGI("target_ino: '%lu', target_pathname: '%s', redirected_pathname: '%s', is successfully updated to OPEN_REDIRECT_HLIST\n",
				new_entry->target_ino, new_entry->target_pathname, new_entry->redirected_pathname);	
	} else {
		SUSFS_LOGI("target_ino: '%lu', target_pathname: '%s' redirected_pathname: '%s', is successfully added to OPEN_REDIRECT_HLIST\n",
				new_entry->target_ino, new_entry->target_pathname, new_entry->redirected_pathname);
	}
	spin_unlock(&susfs_spin_lock);
	return 0;
}

struct filename* susfs_get_redirected_path(unsigned long ino) {
	struct st_susfs_open_redirect_hlist *entry;

	hash_for_each_possible(OPEN_REDIRECT_HLIST, entry, node, ino) {
		if (entry->target_ino == ino) {
			SUSFS_LOGI("Redirect for ino: %lu\n", ino);
			return getname_kernel(entry->redirected_pathname);
		}
	}
	return ERR_PTR(-ENOENT);
}
#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT

/* sus_su */
#ifdef CONFIG_KSU_SUSFS_SUS_SU
bool susfs_is_sus_su_hooks_enabled __read_mostly = false;
static int susfs_sus_su_working_mode = 0;

/* Non-kprobe sus_su for 4.14: mark the su inodes with INODE_STATE_SUS_PATH
 * so the existing sus_path hooks hide them from user app processes. */
static const char *sus_su_paths[] = {
	"/system/bin/su",
	"/system/xbin/su",
	"/system/bin/ksu_susfs",
	"/debug_ramdisk/ksu/bin/su",
	NULL,
};

static void susfs_set_su_inodes_state(unsigned long state)
{
	int i;

	for (i = 0; sus_su_paths[i]; i++) {
		struct path p;

		if (kern_path(sus_su_paths[i], LOOKUP_FOLLOW, &p))
			continue;
		if (p.dentry && p.dentry->d_inode) {
			if (state)
				p.dentry->d_inode->i_state |= INODE_STATE_SUS_PATH;
			else
				p.dentry->d_inode->i_state &= ~INODE_STATE_SUS_PATH;
		}
		path_put(&p);
	}
}

void ksu_susfs_enable_sus_su(void) {
	susfs_set_su_inodes_state(INODE_STATE_SUS_PATH);
}

void ksu_susfs_disable_sus_su(void) {
	susfs_set_su_inodes_state(0);
}

void susfs_show_sus_su_working_mode(void __user **user_info) {
	struct st_susfs_sus_su_working_mode info = {0};

	info.mode = susfs_sus_su_working_mode;
	info.err = 0;
	if (copy_to_user((struct st_susfs_sus_su_working_mode __user*)*user_info, &info, sizeof(info)))
		info.err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE -> ret: %d, mode: %d\n", info.err, info.mode);
}

void susfs_is_sus_su_ready(void __user **user_info) {
	struct st_susfs_sus_su_ready info = {0};

	info.ready = susfs_is_sus_su_hooks_enabled ? 1 : 0;
	info.err = 0;
	if (copy_to_user((struct st_susfs_sus_su_ready __user*)*user_info, &info, sizeof(info)))
		info.err = -EFAULT;
	SUSFS_LOGI("CMD_SUSFS_IS_SUS_SU_READY -> ret: %d, ready: %d\n", info.err, info.ready);
}

int susfs_get_sus_su_working_mode(void) {
	return susfs_sus_su_working_mode;
}

int susfs_sus_su(struct st_sus_su* __user user_info) {
	struct st_sus_su info;
	int last_working_mode = susfs_sus_su_working_mode;

	if (copy_from_user(&info, user_info, sizeof(struct st_sus_su))) {
		SUSFS_LOGE("failed copying from userspace\n");
		return 1;
	}

	if (info.mode == SUS_SU_WITH_HOOKS) {
		if (last_working_mode == SUS_SU_WITH_HOOKS) {
			SUSFS_LOGE("current sus_su mode is already %d\n", SUS_SU_WITH_HOOKS);
			return 1;
		}
		if (last_working_mode != SUS_SU_DISABLED) {
			SUSFS_LOGE("please make sure the current sus_su mode is %d first\n", SUS_SU_DISABLED);
			return 2;
		}
		ksu_susfs_enable_sus_su();
		susfs_sus_su_working_mode = SUS_SU_WITH_HOOKS;
		susfs_is_sus_su_hooks_enabled = true;
		SUSFS_LOGI("core kprobe hooks for ksu are disabled!\n");
		SUSFS_LOGI("non-kprobe hook sus_su is enabled!\n");
		SUSFS_LOGI("sus_su mode: %d\n", SUS_SU_WITH_HOOKS);
		return 0;
	} else if (info.mode == SUS_SU_DISABLED) {
		if (last_working_mode == SUS_SU_DISABLED) {
			SUSFS_LOGE("current sus_su mode is already %d\n", SUS_SU_DISABLED);
			return 1;
		}
		susfs_is_sus_su_hooks_enabled = false;
		ksu_susfs_disable_sus_su();
		susfs_sus_su_working_mode = SUS_SU_DISABLED;
		if (last_working_mode == SUS_SU_WITH_HOOKS) {
			SUSFS_LOGI("core kprobe hooks for ksu are enabled!\n");
			goto out;
		}
out:
		if (copy_to_user(user_info, &info, sizeof(info)))
			SUSFS_LOGE("copy_to_user() failed\n");
		return 0;
	} else if (info.mode == SUS_SU_WITH_OVERLAY) {
		SUSFS_LOGE("sus_su mode %d is deprecated\n", SUS_SU_WITH_OVERLAY);
		return 1;
	}
	return 1;
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_SU

/* susfs_init */
extern struct work_struct susfs_extra_works;
static void susfs_run_extra_works(struct work_struct *work);

void susfs_init(void) {
	spin_lock_init(&susfs_spin_lock);
	INIT_WORK(&susfs_extra_works, susfs_run_extra_works);
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	spin_lock_init(&susfs_uname_spin_lock);
	susfs_my_uname_init();
#endif
	SUSFS_LOGI("susfs is initialized! version: " SUSFS_VERSION " \n");
}

/* No module exit is needed becuase it should never be a loadable kernel module */
//void __init susfs_exit(void)

/* ---- SUSFS v2.2.0 feature set (ported from gki-android16-6.12) ---- */

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
static DEFINE_MUTEX(susfs_mutex_lock_sus_path);
static LIST_HEAD(LH_SUS_PATH_LOOP);

void susfs_add_sus_path_loop(void __user **user_info) {
	struct st_susfs_sus_path_list *new_list = NULL;
	struct st_susfs_sus_path info = {0};

	if (copy_from_user(&info, (struct st_susfs_sus_path __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}

	if (*info.target_pathname == '\0') {
		SUSFS_LOGE("target_pathname cannot be empty\n");
		info.err = -EINVAL;
		goto out_copy_to_user;
	}

	new_list = kzalloc(sizeof(struct st_susfs_sus_path_list), GFP_KERNEL);
	if (!new_list) {
		info.err = -ENOMEM;
		goto out_copy_to_user;
	}
	strncpy(new_list->target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME - 1);
	mutex_lock(&susfs_mutex_lock_sus_path);
	list_add_tail(&new_list->list, &LH_SUS_PATH_LOOP);
	mutex_unlock(&susfs_mutex_lock_sus_path);
	SUSFS_LOGI("target_pathname: '%s', is successfully added to LH_SUS_PATH_LOOP\n",
			new_list->target_pathname);
	info.err = 0;
out_copy_to_user:
	if (copy_to_user(&((struct st_susfs_sus_path __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_ADD_SUS_PATH_LOOP -> ret: %d\n", info.err);
}

static void susfs_run_sus_path_loop(void) {
	struct st_susfs_sus_path_list *cursor = NULL;

	mutex_lock(&susfs_mutex_lock_sus_path);
	list_for_each_entry(cursor, &LH_SUS_PATH_LOOP, list) {
		susfs_update_sus_path_inode(cursor->target_pathname);
	}
	mutex_unlock(&susfs_mutex_lock_sus_path);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
DEFINE_STATIC_KEY_FALSE(susfs_is_hide_sus_mnts_for_non_su_procs_enabled);

void susfs_set_hide_sus_mnts_for_non_su_procs(void __user **user_info) {
	struct st_susfs_hide_sus_mnts_for_non_su_procs info = {0};

	if (copy_from_user(&info, (struct st_susfs_hide_sus_mnts_for_non_su_procs __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}

	if (info.enabled) {
		static_branch_enable(&susfs_is_hide_sus_mnts_for_non_su_procs_enabled);
	} else {
		static_branch_disable(&susfs_is_hide_sus_mnts_for_non_su_procs_enabled);
	}

	SUSFS_LOGI("susfs_is_hide_sus_mnts_for_non_su_procs_enabled: %d\n",
			static_key_enabled(&susfs_is_hide_sus_mnts_for_non_su_procs_enabled));
	info.err = 0;
out_copy_to_user:
	if (copy_to_user(&((struct st_susfs_hide_sus_mnts_for_non_su_procs __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS -> ret: %d\n", info.err);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

/* sus_map */
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
void susfs_add_sus_map(void __user **user_info) {
	struct st_susfs_sus_map info = {0};
	struct path path;
	struct inode *inode = NULL;

	if (copy_from_user(&info, (struct st_susfs_sus_map __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}

	info.err = kern_path(info.target_pathname, LOOKUP_FOLLOW, &path);
	if (info.err) {
		SUSFS_LOGE("failed opening file '%s'\n", info.target_pathname);
		goto out_copy_to_user;
	}

	inode = d_inode(path.dentry);
	if (!inode) {
		SUSFS_LOGE("inode is NULL\n");
		info.err = -ENOENT;
		goto out_path_put_path;
	}

	spin_lock(&inode->i_lock);
	inode->i_state |= INODE_STATE_SUS_MAP;
	spin_unlock(&inode->i_lock);
	SUSFS_LOGI("pathname: '%s', ino: %lu is flagged as INODE_STATE_SUS_MAP\n",
			info.target_pathname, inode->i_ino);
	info.err = 0;
out_path_put_path:
	path_put(&path);
out_copy_to_user:
	if (copy_to_user(&((struct st_susfs_sus_map __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_ADD_SUS_MAP -> ret: %d\n", info.err);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP

/* susfs avc log spoofing */
DEFINE_STATIC_KEY_FALSE(susfs_is_avc_log_spoofing_enabled);
extern u32 susfs_ksu_sid;
extern u32 susfs_priv_app_sid;
extern u32 susfs_get_sid_from_name(const char *secctx_name);

void susfs_set_avc_log_spoofing(void __user **user_info) {
	struct st_susfs_avc_log_spoofing info = {0};

	if (copy_from_user(&info, (struct st_susfs_avc_log_spoofing __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}

	if (info.enabled) {
		if (!susfs_ksu_sid)
			susfs_ksu_sid = susfs_get_sid_from_name("u:r:ksu:s0");
		if (!susfs_priv_app_sid)
			susfs_priv_app_sid = susfs_get_sid_from_name("u:r:priv_app:s0:c512,c768");
		if (susfs_ksu_sid && susfs_priv_app_sid)
			static_branch_enable(&susfs_is_avc_log_spoofing_enabled);
		SUSFS_LOGI("enabling susfs_avc_log_spoofing (ksu_sid=%u priv_app_sid=%u)\n",
				susfs_ksu_sid, susfs_priv_app_sid);
	} else {
		static_branch_disable(&susfs_is_avc_log_spoofing_enabled);
		SUSFS_LOGI("disabling susfs_avc_log_spoofing\n");
	}

	info.err = 0;
out_copy_to_user:
	if (copy_to_user(&((struct st_susfs_avc_log_spoofing __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING -> ret: %d\n", info.err);
}

/* get susfs enabled features */
static int copy_config_to_buf(const char *config_string, char *buf_ptr, size_t *copied_size, size_t bufsize) {
	size_t tmp_size = strlen(config_string);

	*copied_size += tmp_size;
	if (*copied_size >= bufsize) {
		return -EINVAL;
	}
	strcat(buf_ptr, config_string);
	return 0;
}

void susfs_get_enabled_features(void __user **user_info) {
	struct st_susfs_enabled_features *info = NULL;
	size_t copied_size = 0;
	char *buf_ptr = NULL;

	info = kzalloc(sizeof(struct st_susfs_enabled_features), GFP_KERNEL);
	if (!info) {
		int err = -ENOMEM;
		(void)copy_to_user(&((struct st_susfs_enabled_features __user*)*user_info)->err, &err, sizeof(err));
		return;
	}

	if (copy_from_user(info, (struct st_susfs_enabled_features __user*)*user_info, sizeof(struct st_susfs_enabled_features))) {
		info->err = -EFAULT;
		goto out_copy_to_user;
	}

	buf_ptr = info->enabled_features;

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_SUS_PATH\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_SUS_MOUNT\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_SUS_KSTAT\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_TRY_UMOUNT\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_SPOOF_UNAME\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_ENABLE_LOG\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_OPEN_REDIRECT\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_SUS_MAP\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
#endif
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_ENABLE_AVC_LOG_SPOOFING\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;
	buf_ptr = info->enabled_features + copied_size;
	info->err = copy_config_to_buf("CONFIG_KSU_SUSFS_START_SDCARD_MONITOR\n", buf_ptr, &copied_size, SUSFS_ENABLED_FEATURES_SIZE);
	if (info->err) goto out_copy_to_user;

	info->err = 0;
out_copy_to_user:
	if (copy_to_user((struct st_susfs_enabled_features __user*)*user_info, info, sizeof(struct st_susfs_enabled_features))) {
		info->err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_SHOW_ENABLED_FEATURES -> ret: %d\n", info->err);
	kfree(info);
}

void susfs_show_variant(void __user **user_info) {
	struct st_susfs_variant info = {0};

	if (copy_from_user(&info, (struct st_susfs_variant __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	strncpy(info.susfs_variant, "kernel-4.14", sizeof(info.susfs_variant) - 1);
#else
	strncpy(info.susfs_variant, "kernel-4.14", sizeof(info.susfs_variant) - 1);
#endif
	info.err = 0;
	SUSFS_LOGI("CMD_SUSFS_SHOW_VARIANT -> ret: %d, variant: %s\n", info.err, info.susfs_variant);
out_copy_to_user:
	if (copy_to_user((struct st_susfs_variant __user*)*user_info, &info, sizeof(info))) {
		info.err = -EFAULT;
	}
}

void susfs_show_version(void __user **user_info) {
	struct st_susfs_version info = {0};

	if (copy_from_user(&info, (struct st_susfs_version __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}
	strncpy(info.susfs_version, SUSFS_VERSION, sizeof(info.susfs_version) - 1);
	info.err = 0;
	SUSFS_LOGI("CMD_SUSFS_SHOW_VERSION -> ret: %d, version: %s\n", info.err, info.susfs_version);
out_copy_to_user:
	if (copy_to_user((struct st_susfs_version __user*)*user_info, &info, sizeof(info))) {
		info.err = -EFAULT;
	}
}

/* ---- v2.2.0 new-style API wrappers over the 4.14 implementations ---- */

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
void susfs_add_sus_path_new(void __user **user_info) {
	struct st_susfs_sus_path info = {0};
	int ret;

	if (copy_from_user(&info, (struct st_susfs_sus_path __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	ret = susfs_add_sus_path(&info);
	info.err = ret;
out:
	if (copy_to_user(&((struct st_susfs_sus_path __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_ADD_SUS_PATH -> ret: %d\n", info.err);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
void susfs_add_sus_kstat_new(void __user **user_info) {
	struct st_susfs_sus_kstat info = {0};
	int ret;

	if (copy_from_user(&info, (struct st_susfs_sus_kstat __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	ret = susfs_add_sus_kstat(&info);
	info.err = ret;
out:
	if (copy_to_user(&((struct st_susfs_sus_kstat __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_ADD_SUS_KSTAT -> ret: %d\n", info.err);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
void susfs_update_sus_kstat_new(void __user **user_info) {
	struct st_susfs_sus_kstat info = {0};
	int ret;

	if (copy_from_user(&info, (struct st_susfs_sus_kstat __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	ret = susfs_update_sus_kstat(&info);
	info.err = ret;
out:
	if (copy_to_user(&((struct st_susfs_sus_kstat __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\n", info.err);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
void susfs_set_uname_new(void __user **user_info) {
	struct st_susfs_uname info = {0};
	int ret;

	if (copy_from_user(&info, (struct st_susfs_uname __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	ret = susfs_set_uname(&info);
	info.err = ret;
out:
	if (copy_to_user(&((struct st_susfs_uname __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_SET_UNAME -> ret: %d\n", info.err);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
void susfs_enable_log(void __user **user_info) {
	susfs_set_log(true);
}
#endif // #ifdef CONFIG_KSU_SUSFS_ENABLE_LOG

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
void susfs_set_cmdline_or_bootconfig_new(void __user **user_info) {
	char *fake = NULL;
	int err = -EFAULT;

	fake = kmalloc(SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE, GFP_KERNEL);
	if (!fake) {
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user(fake, *user_info, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE)) {
		goto out;
	}
	err = susfs_set_cmdline_or_bootconfig((char __user *)fake);
	kfree(fake);
	fake = NULL;
out:
	if (fake)
		kfree(fake);
	if (copy_to_user(&((struct st_susfs_spoof_cmdline_or_bootconfig __user*)*user_info)->err, &err, sizeof(err))) {
		err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n", err);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
void susfs_add_open_redirect_new(void __user **user_info) {
	struct st_susfs_open_redirect info = {0};
	int ret;

	if (copy_from_user(&info, (struct st_susfs_open_redirect __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	ret = susfs_add_open_redirect(&info);
	info.err = ret;
out:
	if (copy_to_user(&((struct st_susfs_open_redirect __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_ADD_OPEN_REDIRECT -> ret: %d\n", info.err);
}
#endif // #ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
void susfs_add_sus_mount_new(void __user **user_info) {
	struct st_susfs_sus_mount info = {0};
	int ret;

	if (copy_from_user(&info, (struct st_susfs_sus_mount __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	ret = susfs_add_sus_mount(&info);
	info.err = ret;
out:
	if (copy_to_user(&((struct st_susfs_sus_mount __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_ADD_SUS_MOUNT -> ret: %d\n", info.err);
}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

/* sdcard monitor (v2.2.0, adapted to 4.14 fsnotify) */
#include <linux/fsnotify_backend.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define SDCARD_ANDROID_PATH "/data/media/0/Android"

static struct fsnotify_group *susfs_fsnotify_g;
static unsigned long sdcard_cleanup_scheduled;
static struct delayed_work sdcard_cleanup_dwork;

static void susfs_sdcard_cleanup_fn(struct work_struct *work)
{
	SUSFS_LOGI("sdcard cleanup: running sus_path_loop refresh\n");
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	susfs_run_sus_path_loop();
#endif
	clear_bit(0, &sdcard_cleanup_scheduled);
}

static int susfs_handle_sdcard_event(struct fsnotify_group *group, struct inode *inode,
				     struct fsnotify_mark *mark, struct fsnotify_mark *vfsmount_mark,
				     u32 mask, const void *data, int data_type,
				     const unsigned char *file_name, u32 cookie,
				     struct fsnotify_iter_info *iter_info)
{
	if (!file_name)
		return 0;

	if (strlen(file_name) != 7 || memcmp(file_name, "Android", 7))
		return 0;

	if (test_and_set_bit(0, &sdcard_cleanup_scheduled))
		return 0;

	SUSFS_LOGI("'%s' detected, mask: 0x%x\n", SDCARD_ANDROID_PATH, mask);
	SUSFS_LOGI("deferring cleanup for 5 seconds\n");
	queue_delayed_work(system_wq, &sdcard_cleanup_dwork, 5 * HZ);
	return 0;
}

static const struct fsnotify_ops susfs_fsnotify_ops = {
	.handle_event = susfs_handle_sdcard_event,
};

struct susfs_watch_dir {
	const char *path;
	u32 mask;
	struct path kpath;
	struct inode *inode;
	struct fsnotify_mark *mark;
};

static struct susfs_watch_dir susfs_g_watch = { .path = "/data/media/0", .mask = FS_CREATE | FS_MOVE | FS_EVENT_ON_CHILD };

static int susfs_add_mark_on_inode(struct inode *inode, u32 mask, struct fsnotify_mark **out)
{
	struct fsnotify_mark *m;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	fsnotify_init_mark(m, susfs_fsnotify_g);
	m->mask = mask;

	if (fsnotify_add_mark(m, inode, NULL, 0)) {
		fsnotify_put_mark(m);
		return -EINVAL;
	}
	*out = m;
	return 0;
}

static int susfs_watch_one_dir(struct susfs_watch_dir *wd)
{
	int ret = kern_path(wd->path, LOOKUP_FOLLOW, &wd->kpath);
	if (ret) {
		SUSFS_LOGI("path not ready: %s (%d)\n", wd->path, ret);
		return ret;
	}
	wd->inode = d_inode(wd->kpath.dentry);
	ihold(wd->inode);

	ret = susfs_add_mark_on_inode(wd->inode, wd->mask, &wd->mark);
	if (ret) {
		SUSFS_LOGE("Add mark failed for %s (%d)\n", wd->path, ret);
		path_put(&wd->kpath);
		iput(wd->inode);
		wd->inode = NULL;
		return ret;
	}
	SUSFS_LOGI("watching %s\n", wd->path);
	return 0;
}

static int susfs_sdcard_monitor_fn(void *data)
{
	SUSFS_LOGI("start monitoring path '%s' using fsnotify\n", SDCARD_ANDROID_PATH);

	INIT_DELAYED_WORK(&sdcard_cleanup_dwork, susfs_sdcard_cleanup_fn);

	susfs_fsnotify_g = fsnotify_alloc_group(&susfs_fsnotify_ops);
	if (IS_ERR(susfs_fsnotify_g)) {
		return PTR_ERR(susfs_fsnotify_g);
	}

	return susfs_watch_one_dir(&susfs_g_watch);
}

void susfs_start_sdcard_monitor_fn(void) {
	static bool started = false;

	if (started)
		return;
	started = true;
	if (IS_ERR(kthread_run(susfs_sdcard_monitor_fn, NULL, "susfs_sdcard_monitor"))) {
		SUSFS_LOGE("failed to create thread susfs_sdcard_monitor\n");
	}
}

/* v2.2.0 sdcard monitor command handlers */
#ifdef CONFIG_KSU_SUSFS_SUS_SDCARD_MONITOR
static char susfs_android_data_root_path[SUSFS_MAX_LEN_PATHNAME];
static char susfs_sdcard_root_path[SUSFS_MAX_LEN_PATHNAME];

static void susfs_add_sus_path_loop_internal(const char *pathname)
{
	struct st_susfs_sus_path_list *new_list = NULL;

	if (!pathname || !*pathname)
		return;
	new_list = kzalloc(sizeof(struct st_susfs_sus_path_list), GFP_KERNEL);
	if (!new_list)
		return;
	strncpy(new_list->target_pathname, pathname, SUSFS_MAX_LEN_PATHNAME - 1);
	mutex_lock(&susfs_mutex_lock_sus_path);
	list_add_tail(&new_list->list, &LH_SUS_PATH_LOOP);
	mutex_unlock(&susfs_mutex_lock_sus_path);
	SUSFS_LOGI("path '%s' added to LH_SUS_PATH_LOOP\n", pathname);
}

void susfs_set_android_data_root_path(void __user **user_info) {
	struct st_susfs_set_android_data_root_path info = {0};

	if (copy_from_user(&info, (struct st_susfs_set_android_data_root_path __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}
	if (*info.android_data_root_path == '\0') {
		SUSFS_LOGE("android_data_root_path cannot be empty\n");
		info.err = -EINVAL;
		goto out_copy_to_user;
	}
	strncpy(susfs_android_data_root_path, info.android_data_root_path, SUSFS_MAX_LEN_PATHNAME - 1);
	/* The sdcard Android dir to hide: <data_root>/media/0/Android */
	{
		char sdcard_android_path[SUSFS_MAX_LEN_PATHNAME];
		snprintf(sdcard_android_path, sizeof(sdcard_android_path),
			 "%s/media/0/Android", susfs_android_data_root_path);
		susfs_add_sus_path_loop_internal(sdcard_android_path);
	}
	info.err = 0;
	SUSFS_LOGI("android_data_root_path: %s\n", susfs_android_data_root_path);
	susfs_start_sdcard_monitor_fn();
out_copy_to_user:
	if (copy_to_user(&((struct st_susfs_set_android_data_root_path __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH -> ret: %d\n", info.err);
}

void susfs_set_sdcard_root_path(void __user **user_info) {
	struct st_susfs_set_sdcard_root_path info = {0};

	if (copy_from_user(&info, (struct st_susfs_set_sdcard_root_path __user*)*user_info, sizeof(info))) {
		info.err = -EFAULT;
		goto out_copy_to_user;
	}
	if (*info.sdcard_root_path == '\0') {
		SUSFS_LOGE("sdcard_root_path cannot be empty\n");
		info.err = -EINVAL;
		goto out_copy_to_user;
	}
	strncpy(susfs_sdcard_root_path, info.sdcard_root_path, SUSFS_MAX_LEN_PATHNAME - 1);
	{
		char sdcard_android_path[SUSFS_MAX_LEN_PATHNAME];
		snprintf(sdcard_android_path, sizeof(sdcard_android_path),
			 "%s/Android", susfs_sdcard_root_path);
		susfs_add_sus_path_loop_internal(sdcard_android_path);
	}
	info.err = 0;
	SUSFS_LOGI("sdcard_root_path: %s\n", susfs_sdcard_root_path);
	susfs_start_sdcard_monitor_fn();
out_copy_to_user:
	if (copy_to_user(&((struct st_susfs_set_sdcard_root_path __user*)*user_info)->err, &info.err, sizeof(info.err))) {
		info.err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_SET_SDCARD_ROOT_PATH -> ret: %d\n", info.err);
}
#endif /* CONFIG_KSU_SUSFS_SUS_SDCARD_MONITOR */

/* v2.2.0 umount command handlers */
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern void susfs_run_try_umount_for_current_mnt_ns(void);

void susfs_run_umount_for_current_mnt_ns(void __user **user_info) {
	int err = 0;

	susfs_run_try_umount_for_current_mnt_ns();
	if (copy_to_user((int __user*)*user_info, &err, sizeof(err))) {
		err = -EFAULT;
	}
	SUSFS_LOGI("CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS -> ret: %d\n", err);
}

void susfs_umount_for_zygote_iso_service(void __user **user_info) {
	susfs_try_umount(current_uid().val);
	SUSFS_LOGI("CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE done\n");
}
#endif /* CONFIG_KSU_SUSFS_TRY_UMOUNT */

struct work_struct susfs_extra_works;
EXPORT_SYMBOL(susfs_extra_works);

static void susfs_run_extra_works(struct work_struct *work) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	susfs_run_sus_path_loop();
#endif
}
