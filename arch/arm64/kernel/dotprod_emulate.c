// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/irqflags.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

#include <asm/cpufeature.h>
#include <asm/fpsimd.h>
#include <asm/hwcap.h>
#include <asm/traps.h>

#include "dotprod_emulate.h"

static int udot_emu_handler(struct pt_regs *regs, u32 instr)
{
	unsigned int rd = instr & 31;
	unsigned int rn = (instr >> 5) & 31;
	unsigned int rm = (instr >> 16) & 31;
	unsigned int lanes = instr & BIT(30) ? 4 : 2;
	struct fpsimd_state state;

	if (!user_mode(regs) || compat_user_mode(regs) || irqs_disabled() ||
	    (instr & UDOT_VECTOR_MASK) != UDOT_VECTOR_VAL)
		return 1;

	/* 从 CPU 同步后使用栈副本，避免软中断保存旧寄存器时覆盖结果。 */
	preempt_disable();
	fpsimd_preserve_current_state();
	state = current->thread.fpsimd_state;
	state.vregs[rd] = udot_vector_accumulate(state.vregs[rd],
						state.vregs[rn], state.vregs[rm],
						lanes);
	fpsimd_update_current_state(&state);
	preempt_enable();

	arm64_skip_faulting_instruction(regs, 4);
	if (task_pid_nr(current) == 1)
		pr_info_once("TALIH_PASS2_DIAG: emulated vector UDOT in PID 1\n");
	return 0;
}
NOKPROBE_SYMBOL(udot_emu_handler);

static struct undef_hook udot_emu_hook = {
	.instr_mask = UDOT_VECTOR_MASK,
	.instr_val = UDOT_VECTOR_VAL,
	.pstate_mask = PSR_MODE_MASK | PSR_MODE32_BIT,
	.pstate_val = PSR_MODE_EL0t,
	.fn = udot_emu_handler,
};

static int __init udot_emu_init(void)
{
	if (!(elf_hwcap & HWCAP_ASIMD) || (elf_hwcap & HWCAP_ASIMDDP))
		return 0;

	register_undef_hook(&udot_emu_hook);
	return 0;
}
late_initcall(udot_emu_init);
