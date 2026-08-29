// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

#include <asm/ptrace.h>
#include <asm/traps.h>
#include <asm/uaccess.h>

#define LSE_MAX_LOOPS 128

#define __LSE_SWP(name, type, suffix, reg)				\
static int lse_swp_##name(type __user *_uaddr, type src, type *oldp)	\
{									\
	int ret = 0;							\
	unsigned int loops = LSE_MAX_LOOPS;				\
	type old, new;							\
	type __user *uaddr = __uaccess_mask_ptr(_uaddr);		\
									\
	if (!access_ok(VERIFY_WRITE, _uaddr, sizeof(type)))		\
		return -EFAULT;						\
									\
	uaccess_enable();						\
	asm volatile(							\
	"	prfm	pstl1strm, %2\n"				\
	"1:	ldaxr" suffix "	%" reg "1, %2\n"			\
	"	mov	%" reg "3, %" reg "5\n"				\
	"2:	stlxr" suffix "	%w0, %" reg "3, %2\n"		\
	"	cbz	%w0, 3f\n"					\
	"	sub	%w4, %w4, %w0\n"				\
	"	cbnz	%w4, 1b\n"					\
	"	mov	%w0, %w7\n"					\
	"3:\n"								\
	"	dmb	ish\n"						\
	"	.pushsection	.fixup,\"ax\"\n"			\
	"	.align	2\n"						\
	"4:	mov	%w0, %w6\n"					\
	"	b	3b\n"						\
	"	.popsection\n"						\
		_ASM_EXTABLE(1b, 4b)					\
		_ASM_EXTABLE(2b, 4b)					\
	: "+r" (ret), "=&r" (old), "+Q" (*uaddr), "=&r" (new),	\
	  "+r" (loops)							\
	: "r" (src), "Ir" (-EFAULT), "Ir" (-EAGAIN)			\
	: "memory");							\
	uaccess_disable();						\
									\
	if (!ret)							\
		*oldp = old;						\
	return ret;							\
}

__LSE_SWP(b, u8, "b", "w")
__LSE_SWP(h, u16, "h", "w")
__LSE_SWP(w, u32, "", "w")
__LSE_SWP(x, u64, "", "x")

static int lse_swp_handler(struct pt_regs *regs, u32 insn)
{
	unsigned int size = insn >> 30;
	unsigned int rs = (insn >> 16) & 0x1f;
	unsigned int rn = (insn >> 5) & 0x1f;
	unsigned int rt = insn & 0x1f;
	u64 old = 0;
	int ret;

	if (size > 3)
		return 1;

	switch (size) {
	case 0:
		ret = lse_swp_b((u8 __user *)regs->regs[rn],
				(u8)regs->regs[rs], (u8 *)&old);
		break;
	case 1:
		ret = lse_swp_h((u16 __user *)regs->regs[rn],
				(u16)regs->regs[rs], (u16 *)&old);
		break;
	case 2:
		ret = lse_swp_w((u32 __user *)regs->regs[rn],
				(u32)regs->regs[rs], (u32 *)&old);
		break;
	case 3:
	default:
		ret = lse_swp_x((u64 __user *)regs->regs[rn],
				regs->regs[rs], &old);
		break;
	}

	if (ret)
		return 1;

	regs->regs[rt] = old;
	arm64_skip_faulting_instruction(regs, 4);
	return 0;
}

static struct undef_hook lse_swp_hook = {
	.instr_mask	= 0x3f208000,
	.instr_val	= 0x38208000,
	.pstate_mask	= PSR_MODE_MASK,
	.pstate_val	= PSR_MODE_EL0t,
	.fn		= lse_swp_handler,
};

static int __init lse_emulate_init(void)
{
	register_undef_hook(&lse_swp_hook);
	return 0;
}
core_initcall(lse_emulate_init);
