/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_LSE_EMULATE_H
#define __ASM_LSE_EMULATE_H

#ifndef __ASSEMBLY__

struct pt_regs;

#if IS_ENABLED(CONFIG_ARM64_LSE_EMULATE)

/*
 * Narrow bridges called from arch/arm64/mm/fault.c.  Both return 1 when the
 * exception belonged to an active LSE emulation attempt and has been fully
 * consumed (PC redirected to the attempt fixup); 0 means "not ours", and the
 * original fault path must run.
 */
int lse_emu_mem_abort_hook(unsigned long addr, unsigned int esr,
			   struct pt_regs *regs);
int lse_emu_debug_hook(unsigned long addr, unsigned int esr,
		       struct pt_regs *regs);

#ifdef CONFIG_HAVE_HW_BREAKPOINT
/* Watchpoint suppression for the debug bridge; hw_breakpoint.c. */
void lse_emu_wp_suppress(void);
void lse_emu_wp_restore(void);
#else
static inline void lse_emu_wp_suppress(void) {}
static inline void lse_emu_wp_restore(void) {}
#endif

#else /* !CONFIG_ARM64_LSE_EMULATE */

static inline int lse_emu_mem_abort_hook(unsigned long addr,
					 unsigned int esr,
					 struct pt_regs *regs)
{
	return 0;
}

static inline int lse_emu_debug_hook(unsigned long addr,
				     unsigned int esr,
				     struct pt_regs *regs)
{
	return 0;
}

static inline void lse_emu_wp_suppress(void) {}
static inline void lse_emu_wp_restore(void) {}

#endif /* CONFIG_ARM64_LSE_EMULATE */

#endif /* __ASSEMBLY__ */
#endif /* __ASM_LSE_EMULATE_H */
