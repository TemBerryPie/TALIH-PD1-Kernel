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

#endif /* CONFIG_ARM64_LSE_EMULATE */

#endif /* __ASSEMBLY__ */
#endif /* __ASM_LSE_EMULATE_H */
