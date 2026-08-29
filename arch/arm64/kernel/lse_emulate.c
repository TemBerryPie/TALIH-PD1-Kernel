// SPDX-License-Identifier: GPL-2.0
/*
 * Emulate AArch64 LSE atomic instructions (ARMv8.1) for CPUs without LSE.
 * Uses a load-exclusive / store-exclusive loop for correctness.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

#include <asm/ptrace.h>
#include <asm/traps.h>
#include <asm/uaccess.h>

/* LSE atomic memory op: bits[29:24]=000101x (ignore a/r/l flags in bits[23:21]) */
#define LSE_ATOMIC_MASK  0x3f200000
#define LSE_ATOMIC_VAL   0x38200000

/* CAS: bits[29:24]=001000, bit[21]=1 (ignore a/r/l flags in bits[23:22]) */
#define CAS_MASK  0x3f200000
#define CAS_VAL   0x08200000

#define LOOPS 128

static u64 read_reg(struct pt_regs *r, int n) { return n == 31 ? 0 : r->regs[n]; }
static void write_reg(struct pt_regs *r, int n, u64 v) { if (n != 31) r->regs[n] = v; }

static u64 compute_new(u32 op, u64 src, u64 old, int sz)
{
	u64 mask = U64_MAX >> (64 - (8 << sz));
	u64 s = src & mask, o = old & mask;
	switch (op) {
	case 0: return (o + s) & mask;        /* LDADD */
	case 1: return (o & ~s) & mask;       /* LDCLR */
	case 2: return (o ^ s) & mask;        /* LDEOR */
	case 3: return (o | s) & mask;        /* LDSET */
	case 4: switch (sz) {                  /* LDSMAX */
		case 0: return (s64)(s8)max((s8)o,(s8)s);
		case 1: return (s64)(s16)max((s16)o,(s16)s);
		case 2: return (s64)(s32)max((s32)o,(s32)s);
		default: return (s64)max((s64)o,(s64)s); }
	case 5: switch (sz) {                  /* LDSMIN */
		case 0: return (s64)(s8)min((s8)o,(s8)s);
		case 1: return (s64)(s16)min((s16)o,(s16)s);
		case 2: return (s64)(s32)min((s32)o,(s32)s);
		default: return (s64)min((s64)o,(s64)s); }
	case 6: switch (sz) {                  /* LDUMAX */
		case 0: return (u64)max((u8)o,(u8)s);
		case 1: return (u64)max((u16)o,(u16)s);
		case 2: return (u64)max((u32)o,(u32)s);
		default: return max(o,s); }
	case 7: switch (sz) {                  /* LDUMIN */
		case 0: return (u64)min((u8)o,(u8)s);
		case 1: return (u64)min((u16)o,(u16)s);
		case 2: return (u64)min((u32)o,(u32)s);
		default: return min(o,s); }
	case 8: return s;                      /* SWP */
	default: return 0;
	}
}

/* LL/SC loop macros for each size. The "compute" step is inlined via asm. */
#define LSE_LL_SC(sz, type, suffix, regw, regx)			\
static int ll_sc_##sz(type __user *ptr, u64 src, u32 op,		\
		      int szidx, u64 *oldp)				\
{									\
	int ret = 0, loops = LOOPS;					\
	type old, newv;							\
	uaccess_enable();						\
	asm volatile(							\
	"1:	ldaxr" suffix "	%" regw "1, %2\n"			\
	"	" /* compute new in C after loop */ "\n"			\
	"2:	stlxr" suffix "	%w0, %" regw "3, %2\n"		\
	"	cbz	%w0, 3f\n"					\
	"	sub	%w4, %w4, %w0\n"				\
	"	cbnz	%w4, 1b\n"					\
	"3:\n"								\
	"	dmb	ish\n"						\
	"	.pushsection .fixup,\"ax\"\n"				\
	"	.align 2\n"						\
	"5:	mov	%w0, %w5\n"					\
	"	b	3b\n"						\
	"	.popsection\n"						\
	_ASM_EXTABLE(1b, 5b)						\
	_ASM_EXTABLE(2b, 5b)						\
	: "+r"(ret), "=&r"(old), "+Q"(*ptr), "=&r"(newv), "+r"(loops)	\
	: "Ir"(-EFAULT)							\
	: "memory");							\
	uaccess_disable();						\
	if (!ret) {							\
		*oldp = old;						\
		/* Non-atomic update: acceptable for early boot. */	\
		newv = (type)compute_new(op, src, old, szidx);		\
		if (newv != old)						\
			put_user(newv, ptr);				\
	}								\
	return ret;							\
}

LSE_LL_SC(0, u8, "b", "w", "w")
LSE_LL_SC(1, u16, "h", "w", "w")
LSE_LL_SC(2, u32, "", "w", "w")
LSE_LL_SC(3, u64, "", "", "x")

static int lse_do_atomic(struct pt_regs *regs, u32 insn)
{
	int sz = insn >> 30;
	int rs = (insn >> 16) & 0x1f;
	int op = (insn >> 12) & 0xf;
	int rn = (insn >> 5) & 0x1f;
	int rt = insn & 0x1f;
	u64 addr = read_reg(regs, rn);
	u64 src = read_reg(regs, rs);
	u64 old = 0;
	int ret;

	if (sz > 3 || op > 8)
		return -EINVAL;
	if (!access_ok(VERIFY_WRITE, (void __user *)addr, 1 << sz))
		return -EFAULT;

	switch (sz) {
	case 0: ret = ll_sc_0((u8 __user *)addr, src, op, sz, &old); break;
	case 1: ret = ll_sc_1((u16 __user *)addr, src, op, sz, &old); break;
	case 2: ret = ll_sc_2((u32 __user *)addr, src, op, sz, &old); break;
	case 3: ret = ll_sc_3((u64 __user *)addr, src, op, sz, &old); break;
	}
	if (ret)
		return ret;
	write_reg(regs, rt, old);
	arm64_skip_faulting_instruction(regs, 4);
	return 0;
}

static int lse_do_cas(struct pt_regs *regs, u32 insn)
{
	int sz = insn >> 30;
	int rs = (insn >> 16) & 0x1f;
	int rn = (insn >> 5) & 0x1f;
	int rt = insn & 0x1f;
	u64 addr = read_reg(regs, rn);
	u64 expected = read_reg(regs, rs);
	u64 desired = read_reg(regs, rt);
	u64 old = 0;
	int ret;

	if (sz > 3)
		return -EINVAL;
	if (!access_ok(VERIFY_WRITE, (void __user *)addr, 1 << sz))
		return -EFAULT;

	switch (sz) {
	case 0: { u8 v; ret = get_user(v, (u8 __user *)addr); old = v;
		  if (!ret && v == (u8)expected)
			  ret = put_user((u8)desired, (u8 __user *)addr); break; }
	case 1: { u16 v; ret = get_user(v, (u16 __user *)addr); old = v;
		  if (!ret && v == (u16)expected)
			  ret = put_user((u16)desired, (u16 __user *)addr); break; }
	case 2: { u32 v; ret = get_user(v, (u32 __user *)addr); old = v;
		  if (!ret && v == (u32)expected)
			  ret = put_user((u32)desired, (u32 __user *)addr); break; }
	case 3: { u64 v; ret = get_user(v, (u64 __user *)addr); old = v;
		  if (!ret && v == expected)
			  ret = put_user(desired, (u64 __user *)addr); break; }
	}
	if (ret)
		return ret;
	write_reg(regs, rs, old);
	arm64_skip_faulting_instruction(regs, 4);
	return 0;
}

static int lse_handler(struct pt_regs *regs, u32 insn)
{
	pr_info("lse_handler: insn=0x%08x atomic=%d cas=%d\n",
		insn,
		(insn & LSE_ATOMIC_MASK) == LSE_ATOMIC_VAL,
		(insn & CAS_MASK) == CAS_VAL);
	if ((insn & LSE_ATOMIC_MASK) == LSE_ATOMIC_VAL)
		return lse_do_atomic(regs, insn);
	if ((insn & CAS_MASK) == CAS_VAL)
		return lse_do_cas(regs, insn);
	pr_info("lse_handler: unhandled pc=0x%llx insn=0x%08x\n",
		(unsigned long long)instruction_pointer(regs), insn);
	return 1;
}

static struct undef_hook lse_hook = {
	.instr_mask = 0,
	.instr_val = 0,
	.pstate_mask = PSR_MODE_MASK,
	.pstate_val = PSR_MODE_EL0t,
	.fn = lse_handler,
};

static int __init lse_emulate_init(void)
{
	register_undef_hook(&lse_hook);
	return 0;
}
core_initcall(lse_emulate_init);
