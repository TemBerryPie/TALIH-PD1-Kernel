// SPDX-License-Identifier: GPL-2.0
/*
 * Emulate AArch64 LSE atomic instructions (ARMv8.1) for CPUs without LSE.
 * Uses get_user/put_user for simplicity; safe during early boot (single core).
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

#include <asm/ptrace.h>
#include <asm/traps.h>
#include <asm/uaccess.h>

#define LSE_ATOMIC_MASK  0x3f200000
#define LSE_ATOMIC_VAL   0x38200000
#define CAS_MASK         0x3f200000
#define CAS_VAL          0x08200000

static u64 read_reg(struct pt_regs *r, int n) { return n == 31 ? 0 : r->regs[n]; }
static void write_reg(struct pt_regs *r, int n, u64 v) { if (n != 31) r->regs[n] = v; }

static u64 compute_new(u32 op, u64 src, u64 old, int sz)
{
	u64 mask = U64_MAX >> (64 - (8 << sz));
	u64 s = src & mask, o = old & mask;
	switch (op) {
	case 0: return (o + s) & mask;
	case 1: return (o & ~s) & mask;
	case 2: return (o ^ s) & mask;
	case 3: return (o | s) & mask;
	case 4: switch (sz) {
		case 0: return (s64)(s8)max((s8)o,(s8)s);
		case 1: return (s64)(s16)max((s16)o,(s16)s);
		case 2: return (s64)(s32)max((s32)o,(s32)s);
		default: return (s64)max((s64)o,(s64)s); }
	case 5: switch (sz) {
		case 0: return (s64)(s8)min((s8)o,(s8)s);
		case 1: return (s64)(s16)min((s16)o,(s16)s);
		case 2: return (s64)(s32)min((s32)o,(s32)s);
		default: return (s64)min((s64)o,(s64)s); }
	case 6: switch (sz) {
		case 0: return (u64)max((u8)o,(u8)s);
		case 1: return (u64)max((u16)o,(u16)s);
		case 2: return (u64)max((u32)o,(u32)s);
		default: return max(o,s); }
	case 7: switch (sz) {
		case 0: return (u64)min((u8)o,(u8)s);
		case 1: return (u64)min((u16)o,(u16)s);
		case 2: return (u64)min((u32)o,(u32)s);
		default: return min(o,s); }
	case 8: return s;
	default: return 0;
	}
}

static int lse_do_atomic(struct pt_regs *regs, u32 insn)
{
	int sz = insn >> 30;
	int rs = (insn >> 16) & 0x1f;
	int op = (insn >> 12) & 0xf;
	int rn = (insn >> 5) & 0x1f;
	int rt = insn & 0x1f;
	u64 addr = read_reg(regs, rn);
	u64 src = read_reg(regs, rs);
	u64 old = 0, newv;
	int ret;

	if (sz > 3 || op > 8)
		return -EINVAL;
	if (!access_ok(VERIFY_WRITE, (void __user *)addr, 1 << sz))
		return -EFAULT;

	switch (sz) {
	case 0: { u8 v; ret = get_user(v, (u8 __user *)addr); old = v; break; }
	case 1: { u16 v; ret = get_user(v, (u16 __user *)addr); old = v; break; }
	case 2: { u32 v; ret = get_user(v, (u32 __user *)addr); old = v; break; }
	case 3: { u64 v; ret = get_user(v, (u64 __user *)addr); old = v; break; }
	}
	if (ret)
		return ret;

	newv = compute_new(op, src, old, sz);

	if (newv != old) {
		switch (sz) {
		case 0: ret = put_user((u8)newv, (u8 __user *)addr); break;
		case 1: ret = put_user((u16)newv, (u16 __user *)addr); break;
		case 2: ret = put_user((u32)newv, (u32 __user *)addr); break;
		case 3: ret = put_user(newv, (u64 __user *)addr); break;
		}
		if (ret)
			return ret;
	}

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
	if ((insn & LSE_ATOMIC_MASK) == LSE_ATOMIC_VAL)
		return lse_do_atomic(regs, insn);
	if ((insn & CAS_MASK) == CAS_VAL)
		return lse_do_cas(regs, insn);
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
