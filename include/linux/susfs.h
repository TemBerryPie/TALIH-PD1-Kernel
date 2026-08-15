#ifndef KSU_SUSFS_H
#define KSU_SUSFS_H

#include <linux/version.h>
#include <linux/jump_label.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/hashtable.h>
#include <linux/path.h>
#include <linux/susfs_def.h>

#define SUSFS_VERSION "v2.2.0"
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
#define SUSFS_VARIANT "NON-GKI"
#else
#define SUSFS_VARIANT "GKI"
#endif

/*********/
/* MACRO */
/*********/
#define getname_safe(name) (name == NULL ? ERR_PTR(-EINVAL) : getname(name))
#define putname_safe(name) (IS_ERR(name) ? NULL : putname(name))

/**********/
/* STRUCT */
/**********/
/* sus_path */
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
struct st_susfs_sus_path {
	unsigned long                    target_ino;
	char                             target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int                              err;
};

struct st_susfs_sus_path_hlist {
	unsigned long                    target_ino;
	char                             target_pathname[SUSFS_MAX_LEN_PATHNAME];
	struct hlist_node                node;
};
#endif

/* sus_mount */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
struct st_susfs_sus_mount {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	unsigned long           target_dev;
	int                     err;
};

struct st_susfs_sus_mount_list {
	struct list_head                        list;
	struct st_susfs_sus_mount               info;
};
#endif

/* sus_kstat */
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
struct st_susfs_sus_kstat {
	int                     is_statically;
	unsigned long           target_ino; // the ino after bind mounted or overlayed
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	unsigned long           spoofed_ino;
	unsigned long           spoofed_dev;
	unsigned int            spoofed_nlink;
	long long               spoofed_size;
	long                    spoofed_atime_tv_sec;
	long                    spoofed_mtime_tv_sec;
	long                    spoofed_ctime_tv_sec;
	long                    spoofed_atime_tv_nsec;
	long                    spoofed_mtime_tv_nsec;
	long                    spoofed_ctime_tv_nsec;
	unsigned long           spoofed_blksize;
	unsigned long long      spoofed_blocks;
	int                     err;
};

struct st_susfs_sus_kstat_hlist {
	unsigned long                           target_ino;
	struct st_susfs_sus_kstat               info;
	struct hlist_node                       node;
};
#endif

/* try_umount */
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
struct st_susfs_try_umount {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int                     mnt_mode;
};

struct st_susfs_try_umount_list {
	struct list_head                        list;
	struct st_susfs_try_umount              info;
};
#endif

/* spoof_uname */
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
struct st_susfs_uname {
	char        release[__NEW_UTS_LEN+1];
	char        version[__NEW_UTS_LEN+1];
	int         err;
};
#endif

/* open_redirect */
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
struct st_susfs_open_redirect {
	unsigned long                    target_ino;
	char                             target_pathname[SUSFS_MAX_LEN_PATHNAME];
	char                             redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
	int                              err;
};

struct st_susfs_open_redirect_hlist {
	unsigned long                    target_ino;
	char                             target_pathname[SUSFS_MAX_LEN_PATHNAME];
	char                             redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
	struct hlist_node                node;
};
#endif

/* sus_su */
#ifdef CONFIG_KSU_SUSFS_SUS_SU
struct st_sus_su {
	int         mode;
};

struct st_susfs_sus_su_working_mode {
	int         mode;
	int         err;
};

struct st_susfs_sus_su_ready {
	int         ready;
	int         err;
};
#endif

/* sdcard monitor */
#ifdef CONFIG_KSU_SUSFS_SUS_SDCARD_MONITOR
struct st_susfs_set_android_data_root_path {
	char        android_data_root_path[SUSFS_MAX_LEN_PATHNAME];
	int         err;
};

struct st_susfs_set_sdcard_root_path {
	char        sdcard_root_path[SUSFS_MAX_LEN_PATHNAME];
	int         err;
};
#endif

/***********************/
/* FORWARD DECLARATION */
/***********************/
/* sus_path */
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
int susfs_add_sus_path(struct st_susfs_sus_path* __user user_info);
int susfs_sus_ino_for_filldir64(unsigned long ino);
#endif
/* sus_mount */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
int susfs_add_sus_mount(struct st_susfs_sus_mount* __user user_info);
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
int susfs_auto_add_sus_bind_mount(const char *pathname, struct path *path_target);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
void susfs_auto_add_sus_ksu_default_mount(const char __user *to_pathname);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

/* hide_sus_mnts_for_non_su_procs (v2.2.0) */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
struct st_susfs_hide_sus_mnts_for_non_su_procs {
	bool                    enabled;
	int                     err;
};
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

/* sus_path_loop list (v2.2.0) */
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
struct st_susfs_sus_path_list {
	struct list_head                list;
	char                            target_pathname[SUSFS_MAX_LEN_PATHNAME];
};
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH

/* sus_map (v2.2.0) */
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
struct st_susfs_sus_map {
	char                    target_pathname[SUSFS_MAX_LEN_PATHNAME];
	int                     err;
};
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP

/* avc log spoofing (v2.2.0) */
struct st_susfs_avc_log_spoofing {
	bool                    enabled;
	int                     err;
};

/* get enabled features (v2.2.0) */
struct st_susfs_enabled_features {
	char                    enabled_features[SUSFS_ENABLED_FEATURES_SIZE];
	int                     err;
};

/* show variant (v2.2.0) */
struct st_susfs_variant {
	char                    susfs_variant[16];
	int                     err;
};

/* show version (v2.2.0) */
struct st_susfs_version {
	char                    susfs_version[16];
	int                     err;
};

/* sus_kstat */
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
int susfs_add_sus_kstat(struct st_susfs_sus_kstat* __user user_info);
int susfs_update_sus_kstat(struct st_susfs_sus_kstat* __user user_info);
void susfs_sus_ino_for_generic_fillattr(unsigned long ino, struct kstat *stat);
void susfs_sus_ino_for_show_map_vma(unsigned long ino, dev_t *out_dev, unsigned long *out_ino);
#endif
/* try_umount */
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
int susfs_add_try_umount(struct st_susfs_try_umount* __user user_info);
void susfs_try_umount(uid_t target_uid);
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
void susfs_auto_add_try_umount_for_bind_mount(struct path *path);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
/* spoof_uname */
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
int susfs_set_uname(struct st_susfs_uname* __user user_info);
void susfs_spoof_uname(struct new_utsname* tmp);
#endif
/* set_log */
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
void susfs_set_log(bool enabled);
#endif
/* spoof_cmdline_or_bootconfig */
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
struct st_susfs_spoof_cmdline_or_bootconfig {
	char    fake_cmdline_or_bootconfig[SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];
	int     err;
};
int susfs_set_cmdline_or_bootconfig(char* __user user_fake_boot_config);
int susfs_spoof_cmdline_or_bootconfig(struct seq_file *m);
#endif
/* open_redirect */
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
int susfs_add_open_redirect(struct st_susfs_open_redirect* __user user_info);
struct filename* susfs_get_redirected_path(unsigned long ino);
#endif
/* sus_su */
#ifdef CONFIG_KSU_SUSFS_SUS_SU
int susfs_get_sus_su_working_mode(void);
int susfs_sus_su(struct st_sus_su* __user user_info);
void susfs_show_sus_su_working_mode(void __user **user_info);
void susfs_is_sus_su_ready(void __user **user_info);
#endif
/* susfs_init */
void susfs_init(void);

#endif

/* ReSukiSU expects the newer susfs umount-state API; the 4.14
 * backport has no umount state machine, so stub these out. */
bool susfs_is_current_proc_umounted(void);
bool susfs_is_current_proc_umounted_app(void);
void susfs_set_current_proc_umounted(void);

/* ReSukiSU newer-API declarations (stubbed in the 4.14 backport) */
void susfs_enable_log(void __user **user_info);
void susfs_show_version(void __user **user_info);
void susfs_add_sus_path_loop(void __user **user_info);
void susfs_set_hide_sus_mnts_for_non_su_procs(void __user **user_info);
void susfs_add_sus_map(void __user **user_info);
void susfs_start_sdcard_monitor_fn(void);
void susfs_run_umount_for_current_mnt_ns(void __user **user_info);
void susfs_set_android_data_root_path(void __user **user_info);
void susfs_set_sdcard_root_path(void __user **user_info);
void susfs_umount_for_zygote_iso_service(void __user **user_info);
void susfs_enable_avc_log_spoofing(void __user **user_info);

void susfs_get_enabled_features(void __user **user_info);
void susfs_show_variant(void __user **user_info);
void susfs_set_avc_log_spoofing(void __user **user_info);

/* ---- v2.2.0 externs ---- */
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
void susfs_set_cmdline_or_bootconfig_new(void __user **user_info);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
void susfs_add_sus_path_loop(void __user **user_info);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
void susfs_set_hide_sus_mnts_for_non_su_procs(void __user **user_info);
extern struct static_key_false susfs_is_hide_sus_mnts_for_non_su_procs_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
void susfs_add_sus_map(void __user **user_info);
#endif
extern struct static_key_false susfs_is_avc_log_spoofing_enabled;
extern u32 susfs_ksu_sid;
extern u32 susfs_priv_app_sid;
void susfs_set_avc_log_spoofing(void __user **user_info);
void susfs_get_enabled_features(void __user **user_info);
void susfs_show_variant(void __user **user_info);
void susfs_show_version(void __user **user_info);
void susfs_start_sdcard_monitor_fn(void);
