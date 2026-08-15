/* SPDX-License-Identifier: GPL-2.0 */
/*  Himax Android Driver Sample Code for MTK kernel 4.4 platform
 *
 *  Copyright (C) 2019 Himax Corporation.
 *
 *  This software is licensed under the terms of the GNU General Public
 *  License version 2,  as published by the Free Software Foundation,  and
 *  may be copied,  distributed,  and modified under those terms.
 *
 *  This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifndef HIMAX_PLATFORM_H
#define HIMAX_PLATFORM_H

#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/gpio.h>
#include <linux/types.h>
#include <linux/i2c.h>
#include <linux/atomic.h>

#include <linux/dma-mapping.h>
#include <linux/kthread.h>
/* #include <linux/rtpm_prio.h> */
#include "tpd.h"

#define CONFIG_OF_TOUCH
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>

#define MTK
#define MTK_KERNEL_44
#define HIMAX_SPI_FIFO_POLLING
/* #define MTK_INT_NOT_WORK_WORKAROUND */
#if !defined(CONFIG_TOUCHSCREEN_MTK)
	#error Please check if need to enable HX_CONFIG_FB or not
#endif
/*#define HX_CONFIG_FB*/ /* Need Enable if mtk_tpd not support suspend/resume */

extern struct device *g_device;
#if defined(CONFIG_TOUCHSCREEN_HIMAX_DEBUG)
#define D(x...) dev_dbg(g_device, "[HXTP] " x)
#define I(x...) dev_info(g_device, "[HXTP] " x)
#define W(x...) dev_warn(g_device, "[HXTP][WARNING] " x)
#define E(x...) dev_err(g_device, "[HXTP][ERROR] " x)
#define DIF(x...) \
do { \
	if (debug_flag) \
		dev_info(g_device, "[HXTP][DEBUG] " x); \
} while (0)
#else
#define D(x...)
#define I(x...)
#define W(x...)
#define E(x...)
#define DIF(x...)
#endif

#define HIMAX_I2C_RETRY_TIMES 10
/*use for MTK platform bring up more easily*/
#define HIMAX_common_NAME "generic"
/*suggest for real project, change to the name*/
/* #define HIMAX_common_NAME "himax_tp" */

extern struct tpd_device *tpd;
extern struct himax_ic_data *ic_data;
extern struct himax_ts_data *private_ts;

/* ---- tb8788p1 touch trace (flood-safe) ----------------------------------
 * The touch IRQ storm floods dmesg (4454+ checksum lines) which trips the
 * kernel printk_ratelimit and silently drops our HXTR prints; the old
 * "print first N times" static counters also ran out of budget during boot
 * before the user ever touched. These atomic counters count forever and are
 * read on demand via `cat /proc/android_touch/hxtrace` AFTER touching the
 * panel. No printk in the IRQ/bus hot path. */
struct himax_trace {
	atomic_long_t ts_work_enter;	/* himax_ts_work() actually ran */
	atomic_long_t ts_path[4];	/* himax_ts_work_status() result index */
	atomic_long_t get_fail;		/* HX_TS_GET_DATA_FAIL */
	atomic_long_t op_done;		/* himax_ts_operation() completed */
	atomic_long_t bus_rd;		/* all bus reads */
	atomic_long_t bus_rd_ev;	/* bus reads with cmd 0x30 (event stack) */
	atomic_long_t bus_wr;		/* all bus writes */
	atomic_long_t cksum_ok;
	atomic_long_t cksum_fail;	/* checksum mismatch */
	atomic_long_t cksum_allzero;	/* all-zero event frame */
	/* last-observed values (informational; hot paths are mutex-serialized) */
	int last_rd_cmd;		/* cmd of the last bus read */
	int last_rd_len;
	int last_cksum;			/* last computed checksum & 0xff */
	int last_ev_len;
	int last_ev_res;
	u8  last_ev[16];		/* head of the last 0x30 event read */
};
extern struct himax_trace g_hxtrace;

int himax_chip_common_init(void);
void himax_chip_common_deinit(void);

void himax_ts_work(struct himax_ts_data *ts);
enum hrtimer_restart himax_ts_timer_func(struct hrtimer *timer);

static DECLARE_WAIT_QUEUE_HEAD(waiter);

struct himax_i2c_platform_data {
	int abs_x_min;
	int abs_x_max;
	int abs_x_fuzz;
	int abs_y_min;
	int abs_y_max;
	int abs_y_fuzz;
	int abs_pressure_min;
	int abs_pressure_max;
	int abs_pressure_fuzz;
	int abs_width_min;
	int abs_width_max;
	int screenWidth;
	int screenHeight;
	uint8_t fw_version;
	uint8_t tw_id;
	uint8_t powerOff3V3;
	uint8_t cable_config[2];
	uint8_t protocol_type;
	int gpio_irq;
	int gpio_reset;
	int gpio_3v3_en;
	int (*power)(int on);
	void (*reset)(void);
	struct himax_virtual_key *virtual_key;
	struct kobject *vk_obj;
	struct kobj_attribute *vk2Use;

	struct himax_config *hx_config;
	int hx_config_size;
};

extern int himax_bus_read(uint8_t command, uint8_t *data,
		uint32_t length, uint8_t toRetry);
extern int himax_bus_write(uint8_t command, uint8_t *data,
		uint32_t length, uint8_t toRetry);
extern int himax_bus_write_command(uint8_t command,
		uint8_t toRetry);
extern void himax_int_enable(int enable);
extern int himax_ts_register_interrupt(void);
int himax_ts_unregister_interrupt(void);
extern uint8_t himax_int_gpio_read(int pinnum);

extern int himax_gpio_power_config(struct himax_i2c_platform_data *pdata);
void himax_gpio_power_deconfig(struct himax_i2c_platform_data *pdata);
extern int of_get_himax85xx_platform_data(struct device *dev);

#if defined(HX_CONFIG_FB)
extern int fb_notifier_callback(struct notifier_block *self,
		unsigned long event, void *data);
#endif

#if !defined(HX_USE_KSYM)
extern struct tpd_device *tpd;
#endif

#endif
