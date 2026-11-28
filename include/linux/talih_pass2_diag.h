/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TALIH_PASS2_DIAG_H
#define _LINUX_TALIH_PASS2_DIAG_H

#include <linux/types.h>

#ifdef CONFIG_TALIH_PASS2_SECOND_STAGE_DIAG
void talih_pass2_note_policy_load(size_t size);
bool talih_pass2_service_window(void);
#else
static inline void talih_pass2_note_policy_load(size_t size)
{
}

static inline bool talih_pass2_service_window(void)
{
	return false;
}
#endif

#endif
