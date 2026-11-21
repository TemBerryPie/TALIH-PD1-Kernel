// SPDX-License-Identifier: GPL-2.0
/*
 * Clean-room emulation of AArch64 LSE atomic instructions and LDAPR for
 * ARMv8.0-only cores (no LSE, no RCpc, no LSE2).
 *
 * Spec: LSE_EMULATION_DESIGN.md (MT8788 用户态 LSE / LDAPR 内核模拟正确性蓝图).
 * This file is written from that specification; the pre-existing
 * get_user/put_user-based implementation is deliberately not reused
 * (see design §5 for the list of its defects).
 *
 * Hot-path context: the donor userland contains 1062 statically-encoded LSE /
 * LDAPR instruction sites (linker64 ~700, libc.so ~362).  Every one of them
 * traps into this file on first execution; nothing is patched or rewritten in
 * user code pages.  The per-trap cost is dominated by the exception entry,
 * the decode below, the VMA permission/cacheability validation and the
 * LL/SC attempt (design §7.4: plan estimate 0.5...5 us per trap).
 *
 * Correctness model (design §0/§3/§4):
 *  - only AArch64 EL0, only naturally aligned Normal WB / Inner-Shareable
 *    mappings of the current mm; device / non-WB mappings are rejected with
 *    SIGBUS rather than emulated unsafely;
 *  - every commit is a hardware LL/SC exclusive transaction on the user VA
 *    with SW-TTBR0-PAN uaccess enabled, so it participates in the same
 *    hardware atomicity domain as native LDXR/STXR on the other cores and
 *    with the kernel futex paths.  There is no software lock;
 *  - CASP failure returns are verified by a same-value exclusive store
 *    (STXP validation) so no torn 128-bit pair can ever be observed;
 *  - ordering: LDAXR/STLXR/LDAR native forms per design §3.1 table, plus a
 *    post-commit DMB ISH for the fully ordered (A+R) RMW/CAS/CASP forms;
 *  - every possibly-faulting instruction has an __ex_table entry; a fault
 *    during the attempt never commits anything and is forwarded as the
 *    original EL0 data abort (real FSC/FAR, EC=DABT_LOW, IL=1, ISV=0);
 *  - illegal encodings are not intercepted (hook returns unhandled and the
 *    standard SIGILL/ILL_ILLOPC path runs with the PC left alone);
 *  - HWCAP_ATOMICS / HWCAP_LRCPC are NOT advertised and the ID registers
 *    are not modified: only statically-encoded sites trap here.
 */

#include <linux/extable.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/perf_event.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <asm/esr.h>
#include <asm/extable.h>
#include <asm/lse_emulate.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>
#include <asm/system_misc.h>
#include <asm/traps.h>

#ifdef CONFIG_HAVE_HW_BREAKPOINT
#include <linux/hw_breakpoint.h>
#include <asm/hw_breakpoint.h>
#endif

/* Status codes shared with the LL/SC assembly helpers. */
#define LSE_EMU_COMMITTED	1	/* STXR/STLXR verified successful */
#define LSE_EMU_RETRY		2	/* batch exhausted, no commit */
#define LSE_EMU_FAULT		3	/* extable fixup, no commit */

/* Events recorded in the active context by the narrow fault/debug bridges. */
#define LSE_EMU_EV_NONE		0
#define LSE_EMU_EV_FAULT	1
#define LSE_EMU_EV_DEBUG	2

/* Bounded batch size per attempt (design §3.4: 16...32, tunable). */
#define LSE_EMU_ATTEMPTS	16

/* Instruction families. */
#define LSE_FAM_RMW		0	/* LDADD/LDCLR/LDEOR/LDSET/LDSMAX/
					 * LDSMIN/LDUMAX/LDUMIN/SWP (+ST alias) */
#define LSE_FAM_CAS		1	/* CAS/B/H/W */
#define LSE_FAM_CASP		2	/* CASP (2x32 or 2x64 pair) */
#define LSE_FAM_LDAPR		3	/* LDAPR/B/H/W (RCpc acquire load) */

struct lse_emu_desc {
	u8	fam;		/* LSE_FAM_* */
	u8	size;		/* RMW/CAS/LDAPR: 0..3 = 8/16/32/64-bit.
				 * CASP: 0 = 2x32 (8B), 1 = 2x64 (16B). */
	u8	op;		/* RMW op 0..8 */
	u8	a;		/* acquire bit */
	u8	r;		/* release bit */
	u8	rs;		/* i[20:16] source / expected / pair base */
	u8	rn;		/* i[9:5]  base (31 = SP) */
	u8	rt;		/* i[4:0]  destination / desired / pair base */
	u32	bytes;		/* total memory footprint of the access */
};

/*
 * Snapshot of everything the helpers need.  Filled before any window is
 * opened; pt_regs is only written back on a verified commit (design §2.2:
 * "进入助手前快照地址、所有源/expected/desired；允许 Rs/Rt/Rn 重合").
 */
struct lse_emu_req {
	u64	addr;		/* masked user pointer */
	u64	src;		/* RMW source, masked to width */
	u64	exp;		/* CAS expected / CASP E0 or concat(E1,E0) */
	u64	exp1;		/* CASP64 E1 */
	u64	des;		/* CAS desired / CASP D0 or concat(D1,D0) */
	u64	des1;		/* CASP64 D1 */
	u64	old;		/* out: old value (or CASP32 64-bit concat) */
	u64	old1;		/* out: CASP64 old high half */
	u32	status;		/* out: LSE_EMU_* */
	u32	op;		/* RMW op for the helpers */
	u32	a, r, al;	/* ordering flags for the helpers */
};

/*
 * Active emulation context.  `active` is set just before the bounded LL/SC
 * attempt and cleared again before preempt is re-enabled, so it never spans
 * a slow path; the narrow bridges in do_mem_abort()/do_debug_exception()
 * consult it (design §4.2/§6).
 */
struct lse_emu_ctx {
	u8	active;
	u8	ev;		/* LSE_EMU_EV_* for the current attempt */
	u32	esr;		/* inner syndrome (FSC) or debug ESR */
	unsigned long addr;	/* data address (FAR) of the inner event */
};
static DEFINE_PER_CPU(struct lse_emu_ctx, lse_emu_ctx);

/*
 * The LL/SC helper bodies below are the only code that may fault while the
 * context is active.  They are bracketed by assembler markers so the fault
 * bridge can verify the inner PC exactly; the bracket is validated at init
 * time against the helper entry points and emulation is disabled if the
 * compiler ever places anything in between.
 */
extern char __lse_emu_text_start[], __lse_emu_text_end[];

asm(".pushsection .text\n"
    ".align	2\n"
    "__lse_emu_text_start:\n"
    ".popsection\n");

/* Forward declaration: no header carries this prototype in 4.14. */
asmlinkage void do_mem_abort(unsigned long addr, unsigned int esr,
			     struct pt_regs *regs);

static bool lse_emu_enabled = true;

/* ------------------------------------------------------------------ */
/* Decode: exact whitelist, 172 combinations (design §2.1)            */
/* ------------------------------------------------------------------ */

/*
 * RMW (9 ops x 4 sizes x 4 orderings = 144):
 *   mask = 0x3f20fc00, value = 0x38200000 | (op << 12);
 *   size = i[31:30], A = i[23], R = i[22], i[11:10] must be 00.
 *   op 0..8 only; op 12 with Rs=31, A=1, R=0 is LDAPR (checked below), op
 *   9..11/13..15 and everything else are not in this whitelist.
 *
 * CAS/B/H/W (4 sizes x 4 orderings = 16):
 *   mask = 0x3fa07c00, value = 0x08a07c00;
 *   size = i[31:30], A = i[22], R = i[15], i[23] = 1, i[14:10] = 11111.
 *
 * CASP (2 sizes x 4 orderings = 8):
 *   mask = 0xbfa07c00, value = 0x08207c00;
 *   i[31] = 0 (separates CASP from LDXP/STXP/LDAXP/STLXP, which always
 *   have i[31] = 1), i[23] = 0, sz = i[30], A = i[22], R = i[15],
 *   i[14:10] = 11111; Rs and Rt must both be even (Rs/Rt = 30 is legal:
 *   second half is ZR; first register 31 or any odd number is illegal).
 *
 * LDAPR/B/H/W (4):
 *   mask = 0x3ffffc00, value = 0x38bfc000;
 *   Rs fixed 31, op fixed 12, i[23:22] = 10.  Must be identified
 *   independently of the RMW family (generic op=12 must NOT reject it).
 */
static bool lse_emu_decode(u32 insn, struct lse_emu_desc *d)
{
	u32 op = (insn >> 12) & 0xf;

	memset(d, 0, sizeof(*d));

	/* RMW family */
	if ((insn & 0x3f20fc00) == (0x38200000u | (op << 12)) && op <= 8) {
		d->fam   = LSE_FAM_RMW;
		d->op    = op;
		d->size  = insn >> 30;
		d->a     = (insn >> 23) & 1;
		d->r     = (insn >> 22) & 1;
		d->rs    = (insn >> 16) & 0x1f;
		d->rn    = (insn >> 5) & 0x1f;
		d->rt    = insn & 0x1f;
		d->bytes = 1U << d->size;
		return true;
	}

	/* CAS family */
	if ((insn & 0x3fa07c00) == 0x08a07c00) {
		d->fam   = LSE_FAM_CAS;
		d->size  = insn >> 30;
		d->a     = (insn >> 22) & 1;
		d->r     = (insn >> 15) & 1;
		d->rs    = (insn >> 16) & 0x1f;
		d->rn    = (insn >> 5) & 0x1f;
		d->rt    = insn & 0x1f;
		d->bytes = 1U << d->size;
		return true;
	}

	/* CASP family (no CASPB/CASPH exist; sz=0 -> 2x32, sz=1 -> 2x64) */
	if ((insn & 0xbfa07c00) == 0x08207c00) {
		u32 rs = (insn >> 16) & 0x1f;
		u32 rt = insn & 0x1f;

		/* pair registers: both even, neither may be the pair base 31 */
		if ((rs & 1) || (rt & 1) || rs == 31 || rt == 31)
			return false;
		d->fam   = LSE_FAM_CASP;
		d->size  = (insn >> 30) & 1;
		d->a     = (insn >> 22) & 1;
		d->r     = (insn >> 15) & 1;
		d->rs    = rs;
		d->rn    = (insn >> 5) & 0x1f;
		d->rt    = rt;
		d->bytes = 8U << d->size;
		return true;
	}

	/* LDAPR family */
	if ((insn & 0x3ffffc00) == 0x38bfc000) {
		d->fam   = LSE_FAM_LDAPR;
		d->size  = insn >> 30;
		d->rs    = (insn >> 16) & 0x1f;	/* fixed 31 */
		d->rn    = (insn >> 5) & 0x1f;
		d->rt    = insn & 0x1f;
		d->bytes = 1U << d->size;
		return true;
	}

	return false;
}

/* ------------------------------------------------------------------ */
/* Register access helpers                                            */
/* ------------------------------------------------------------------ */

/* Data operand: register 31 reads zero (XZR/WZR). */
static inline u64 lse_emu_read_data(struct pt_regs *regs, int n)
{
	return n == 31 ? 0 : regs->regs[n];
}

/* Base address operand: register 31 reads SP. */
static inline u64 lse_emu_read_base(struct pt_regs *regs, int n)
{
	return n == 31 ? regs->sp : regs->regs[n];
}

/* Data destination: register 31 discards. */
static inline void lse_emu_write_data(struct pt_regs *regs, int n, u64 v)
{
	if (n != 31)
		regs->regs[n] = v;
}

static inline u64 lse_emu_width_mask(u32 bytes)
{
	/* bytes may be 16 (CASP pair): clamp instead of shifting by 128. */
	return bytes >= 8 ? ~0ULL : ((1ULL << (bytes * 8)) - 1);
}

/* ------------------------------------------------------------------ */
/* LL/SC helpers (design §3.3).  One asm block per family/size; the   */
/* acquire/release forms are selected inside the block so that the    */
/* whole bounded batch stays one closed region with no C call, no     */
/* spill and no barrier between the exclusive load and store.         */
/* ------------------------------------------------------------------ */

static noinline notrace void lse_emu_rmw_8(struct lse_emu_req *q)
{
	u32 old, val, st, status, t1, t2, cnt;

	asm volatile(
	"	clrex\n"
	"	mov	%w[cnt], #16\n"
	"1:	cbz	%w[af], 2f\n"
	"61:	ldaxrb	%w[old], [%[addr]]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxrb	%w[old], [%[addr]]\n"
	"4:	cmp	%w[op], #0\n"
	"	b.eq	40f\n"
	"	cmp	%w[op], #1\n"
	"	b.eq	41f\n"
	"	cmp	%w[op], #2\n"
	"	b.eq	42f\n"
	"	cmp	%w[op], #3\n"
	"	b.eq	43f\n"
	"	cmp	%w[op], #4\n"
	"	b.eq	44f\n"
	"	cmp	%w[op], #5\n"
	"	b.eq	45f\n"
	"	cmp	%w[op], #6\n"
	"	b.eq	46f\n"
	"	cmp	%w[op], #7\n"
	"	b.eq	47f\n"
	"	mov	%w[val], %w[src]\n"
	"	b	6f\n"
	"40:	add	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"41:	bic	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"42:	eor	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"43:	orr	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"44:	sxtb	%w[t1], %w[old]\n"
	"	sxtb	%w[t2], %w[src]\n"
	"	cmp	%w[t1], %w[t2]\n"
	"	csel	%w[val], %w[old], %w[src], ge\n"
	"	b	6f\n"
	"45:	sxtb	%w[t1], %w[old]\n"
	"	sxtb	%w[t2], %w[src]\n"
	"	cmp	%w[t1], %w[t2]\n"
	"	csel	%w[val], %w[old], %w[src], le\n"
	"	b	6f\n"
	"46:	cmp	%w[old], %w[src]\n"
	"	csel	%w[val], %w[old], %w[src], hs\n"
	"	b	6f\n"
	"47:	cmp	%w[old], %w[src]\n"
	"	csel	%w[val], %w[old], %w[src], ls\n"
	"6:	cbz	%w[rf], 8f\n"
	"63:	stlxrb	%w[st], %w[val], [%[addr]]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxrb	%w[st], %w[val], [%[addr]]\n"
	"9:	cbnz	%w[st], 20f\n"
	"	cbz	%w[al], 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"20:	sub	%w[cnt], %w[cnt], #1\n"
	"	cbnz	%w[cnt], 1b\n"
	"	clrex\n"
	"	mov	%w[status], #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [val] "=&r" (val), [st] "=&r" (st),
	  [status] "=&r" (status), [t1] "=&r" (t1), [t2] "=&r" (t2),
	  [cnt] "=&r" (cnt)
	: [addr] "r" (q->addr), [src] "r" ((u32)q->src), [op] "r" (q->op),
	  [af] "r" (q->a), [rf] "r" (q->r), [al] "r" (q->al)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_rmw_8);

static noinline notrace void lse_emu_rmw_16(struct lse_emu_req *q)
{
	u32 old, val, st, status, t1, t2, cnt;

	asm volatile(
	"	clrex\n"
	"	mov	%w[cnt], #16\n"
	"1:	cbz	%w[af], 2f\n"
	"61:	ldaxrh	%w[old], [%[addr]]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxrh	%w[old], [%[addr]]\n"
	"4:	cmp	%w[op], #0\n"
	"	b.eq	40f\n"
	"	cmp	%w[op], #1\n"
	"	b.eq	41f\n"
	"	cmp	%w[op], #2\n"
	"	b.eq	42f\n"
	"	cmp	%w[op], #3\n"
	"	b.eq	43f\n"
	"	cmp	%w[op], #4\n"
	"	b.eq	44f\n"
	"	cmp	%w[op], #5\n"
	"	b.eq	45f\n"
	"	cmp	%w[op], #6\n"
	"	b.eq	46f\n"
	"	cmp	%w[op], #7\n"
	"	b.eq	47f\n"
	"	mov	%w[val], %w[src]\n"
	"	b	6f\n"
	"40:	add	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"41:	bic	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"42:	eor	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"43:	orr	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"44:	sxth	%w[t1], %w[old]\n"
	"	sxth	%w[t2], %w[src]\n"
	"	cmp	%w[t1], %w[t2]\n"
	"	csel	%w[val], %w[old], %w[src], ge\n"
	"	b	6f\n"
	"45:	sxth	%w[t1], %w[old]\n"
	"	sxth	%w[t2], %w[src]\n"
	"	cmp	%w[t1], %w[t2]\n"
	"	csel	%w[val], %w[old], %w[src], le\n"
	"	b	6f\n"
	"46:	cmp	%w[old], %w[src]\n"
	"	csel	%w[val], %w[old], %w[src], hs\n"
	"	b	6f\n"
	"47:	cmp	%w[old], %w[src]\n"
	"	csel	%w[val], %w[old], %w[src], ls\n"
	"6:	cbz	%w[rf], 8f\n"
	"63:	stlxrh	%w[st], %w[val], [%[addr]]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxrh	%w[st], %w[val], [%[addr]]\n"
	"9:	cbnz	%w[st], 20f\n"
	"	cbz	%w[al], 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"20:	sub	%w[cnt], %w[cnt], #1\n"
	"	cbnz	%w[cnt], 1b\n"
	"	clrex\n"
	"	mov	%w[status], #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [val] "=&r" (val), [st] "=&r" (st),
	  [status] "=&r" (status), [t1] "=&r" (t1), [t2] "=&r" (t2),
	  [cnt] "=&r" (cnt)
	: [addr] "r" (q->addr), [src] "r" ((u32)q->src), [op] "r" (q->op),
	  [af] "r" (q->a), [rf] "r" (q->r), [al] "r" (q->al)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_rmw_16);

static noinline notrace void lse_emu_rmw_32(struct lse_emu_req *q)
{
	u32 old, val, st, status, t1, t2, cnt;

	asm volatile(
	"	clrex\n"
	"	mov	%w[cnt], #16\n"
	"1:	cbz	%w[af], 2f\n"
	"61:	ldaxr	%w[old], [%[addr]]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxr	%w[old], [%[addr]]\n"
	"4:	cmp	%w[op], #0\n"
	"	b.eq	40f\n"
	"	cmp	%w[op], #1\n"
	"	b.eq	41f\n"
	"	cmp	%w[op], #2\n"
	"	b.eq	42f\n"
	"	cmp	%w[op], #3\n"
	"	b.eq	43f\n"
	"	cmp	%w[op], #4\n"
	"	b.eq	44f\n"
	"	cmp	%w[op], #5\n"
	"	b.eq	45f\n"
	"	cmp	%w[op], #6\n"
	"	b.eq	46f\n"
	"	cmp	%w[op], #7\n"
	"	b.eq	47f\n"
	"	mov	%w[val], %w[src]\n"
	"	b	6f\n"
	"40:	add	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"41:	bic	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"42:	eor	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"43:	orr	%w[val], %w[old], %w[src]\n"
	"	b	6f\n"
	"44:	cmp	%w[old], %w[src]\n"
	"	csel	%w[val], %w[old], %w[src], ge\n"
	"	b	6f\n"
	"45:	cmp	%w[old], %w[src]\n"
	"	csel	%w[val], %w[old], %w[src], le\n"
	"	b	6f\n"
	"46:	cmp	%w[old], %w[src]\n"
	"	csel	%w[val], %w[old], %w[src], hs\n"
	"	b	6f\n"
	"47:	cmp	%w[old], %w[src]\n"
	"	csel	%w[val], %w[old], %w[src], ls\n"
	"6:	cbz	%w[rf], 8f\n"
	"63:	stlxr	%w[st], %w[val], [%[addr]]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxr	%w[st], %w[val], [%[addr]]\n"
	"9:	cbnz	%w[st], 20f\n"
	"	cbz	%w[al], 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"20:	sub	%w[cnt], %w[cnt], #1\n"
	"	cbnz	%w[cnt], 1b\n"
	"	clrex\n"
	"	mov	%w[status], #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [val] "=&r" (val), [st] "=&r" (st),
	  [status] "=&r" (status), [t1] "=&r" (t1), [t2] "=&r" (t2),
	  [cnt] "=&r" (cnt)
	: [addr] "r" (q->addr), [src] "r" ((u32)q->src), [op] "r" (q->op),
	  [af] "r" (q->a), [rf] "r" (q->r), [al] "r" (q->al)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_rmw_32);

static noinline notrace void lse_emu_rmw_64(struct lse_emu_req *q)
{
	u64 old, val;
	u32 st, status, cnt;

	asm volatile(
	"	clrex\n"
	"	mov	%w[cnt], #16\n"
	"1:	cbz	%w[af], 2f\n"
	"61:	ldaxr	%[old], [%[addr]]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxr	%[old], [%[addr]]\n"
	"4:	cmp	%w[op], #0\n"
	"	b.eq	40f\n"
	"	cmp	%w[op], #1\n"
	"	b.eq	41f\n"
	"	cmp	%w[op], #2\n"
	"	b.eq	42f\n"
	"	cmp	%w[op], #3\n"
	"	b.eq	43f\n"
	"	cmp	%w[op], #4\n"
	"	b.eq	44f\n"
	"	cmp	%w[op], #5\n"
	"	b.eq	45f\n"
	"	cmp	%w[op], #6\n"
	"	b.eq	46f\n"
	"	cmp	%w[op], #7\n"
	"	b.eq	47f\n"
	"	mov	%[val], %[src]\n"
	"	b	6f\n"
	"40:	add	%[val], %[old], %[src]\n"
	"	b	6f\n"
	"41:	bic	%[val], %[old], %[src]\n"
	"	b	6f\n"
	"42:	eor	%[val], %[old], %[src]\n"
	"	b	6f\n"
	"43:	orr	%[val], %[old], %[src]\n"
	"	b	6f\n"
	"44:	cmp	%[old], %[src]\n"
	"	csel	%[val], %[old], %[src], ge\n"
	"	b	6f\n"
	"45:	cmp	%[old], %[src]\n"
	"	csel	%[val], %[old], %[src], le\n"
	"	b	6f\n"
	"46:	cmp	%[old], %[src]\n"
	"	csel	%[val], %[old], %[src], hs\n"
	"	b	6f\n"
	"47:	cmp	%[old], %[src]\n"
	"	csel	%[val], %[old], %[src], ls\n"
	"6:	cbz	%w[rf], 8f\n"
	"63:	stlxr	%w[st], %[val], [%[addr]]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxr	%w[st], %[val], [%[addr]]\n"
	"9:	cbnz	%w[st], 20f\n"
	"	cbz	%w[al], 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"20:	sub	%w[cnt], %w[cnt], #1\n"
	"	cbnz	%w[cnt], 1b\n"
	"	clrex\n"
	"	mov	%w[status], #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [val] "=&r" (val), [st] "=&r" (st),
	  [status] "=&r" (status), [cnt] "=&r" (cnt)
	: [addr] "r" (q->addr), [src] "r" (q->src), [op] "r" (q->op),
	  [af] "r" (q->a), [rf] "r" (q->r), [al] "r" (q->al)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_rmw_64);

/*
 * CAS scalar, all widths; also used for CASP with sz=0 where the pair is
 * emulated as one 64-bit exclusive transaction on the 8-byte aligned pair
 * (design §3.3 CASP_32: CAS_scalar_64 on concat(E1,E0)/concat(D1,D0)).
 * A compare failure still writes the old value back through the exclusive
 * store: the write permission check and the store event must not be skipped
 * (design §2.2/§3.4).
 */
static noinline notrace void lse_emu_cas_8(struct lse_emu_req *q)
{
	u32 old, val, st, status, cnt;

	asm volatile(
	"	clrex\n"
	"	mov	%w[cnt], #16\n"
	"1:	cbz	%w[af], 2f\n"
	"61:	ldaxrb	%w[old], [%[addr]]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxrb	%w[old], [%[addr]]\n"
	"4:	cmp	%w[old], %w[exp]\n"
	"	csel	%w[val], %w[des], %w[old], eq\n"
	"6:	cbz	%w[rf], 8f\n"
	"63:	stlxrb	%w[st], %w[val], [%[addr]]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxrb	%w[st], %w[val], [%[addr]]\n"
	"9:	cbnz	%w[st], 20f\n"
	"	cbz	%w[al], 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"20:	sub	%w[cnt], %w[cnt], #1\n"
	"	cbnz	%w[cnt], 1b\n"
	"	clrex\n"
	"	mov	%w[status], #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [val] "=&r" (val), [st] "=&r" (st),
	  [status] "=&r" (status), [cnt] "=&r" (cnt)
	: [addr] "r" (q->addr), [exp] "r" ((u32)q->exp), [des] "r" ((u32)q->des),
	  [af] "r" (q->a), [rf] "r" (q->r), [al] "r" (q->al)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_cas_8);

static noinline notrace void lse_emu_cas_16(struct lse_emu_req *q)
{
	u32 old, val, st, status, cnt;

	asm volatile(
	"	clrex\n"
	"	mov	%w[cnt], #16\n"
	"1:	cbz	%w[af], 2f\n"
	"61:	ldaxrh	%w[old], [%[addr]]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxrh	%w[old], [%[addr]]\n"
	"4:	cmp	%w[old], %w[exp]\n"
	"	csel	%w[val], %w[des], %w[old], eq\n"
	"6:	cbz	%w[rf], 8f\n"
	"63:	stlxrh	%w[st], %w[val], [%[addr]]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxrh	%w[st], %w[val], [%[addr]]\n"
	"9:	cbnz	%w[st], 20f\n"
	"	cbz	%w[al], 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"20:	sub	%w[cnt], %w[cnt], #1\n"
	"	cbnz	%w[cnt], 1b\n"
	"	clrex\n"
	"	mov	%w[status], #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [val] "=&r" (val), [st] "=&r" (st),
	  [status] "=&r" (status), [cnt] "=&r" (cnt)
	: [addr] "r" (q->addr), [exp] "r" ((u32)q->exp), [des] "r" ((u32)q->des),
	  [af] "r" (q->a), [rf] "r" (q->r), [al] "r" (q->al)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_cas_16);

static noinline notrace void lse_emu_cas_32(struct lse_emu_req *q)
{
	u32 old, val, st, status, cnt;

	asm volatile(
	"	clrex\n"
	"	mov	%w[cnt], #16\n"
	"1:	cbz	%w[af], 2f\n"
	"61:	ldaxr	%w[old], [%[addr]]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxr	%w[old], [%[addr]]\n"
	"4:	cmp	%w[old], %w[exp]\n"
	"	csel	%w[val], %w[des], %w[old], eq\n"
	"6:	cbz	%w[rf], 8f\n"
	"63:	stlxr	%w[st], %w[val], [%[addr]]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxr	%w[st], %w[val], [%[addr]]\n"
	"9:	cbnz	%w[st], 20f\n"
	"	cbz	%w[al], 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"20:	sub	%w[cnt], %w[cnt], #1\n"
	"	cbnz	%w[cnt], 1b\n"
	"	clrex\n"
	"	mov	%w[status], #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [val] "=&r" (val), [st] "=&r" (st),
	  [status] "=&r" (status), [cnt] "=&r" (cnt)
	: [addr] "r" (q->addr), [exp] "r" ((u32)q->exp), [des] "r" ((u32)q->des),
	  [af] "r" (q->a), [rf] "r" (q->r), [al] "r" (q->al)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_cas_32);

/* CAS 64-bit / CASP 2x32 (pair emulated as one 64-bit transaction). */
static noinline notrace void lse_emu_cas_64(struct lse_emu_req *q)
{
	u64 old, val;
	u32 st, status, cnt;

	asm volatile(
	"	clrex\n"
	"	mov	%w[cnt], #16\n"
	"1:	cbz	%w[af], 2f\n"
	"61:	ldaxr	%[old], [%[addr]]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxr	%[old], [%[addr]]\n"
	"4:	cmp	%[old], %[exp]\n"
	"	csel	%[val], %[des], %[old], eq\n"
	"6:	cbz	%w[rf], 8f\n"
	"63:	stlxr	%w[st], %[val], [%[addr]]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxr	%w[st], %[val], [%[addr]]\n"
	"9:	cbnz	%w[st], 20f\n"
	"	cbz	%w[al], 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"20:	sub	%w[cnt], %w[cnt], #1\n"
	"	cbnz	%w[cnt], 1b\n"
	"	clrex\n"
	"	mov	%w[status], #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [val] "=&r" (val), [st] "=&r" (st),
	  [status] "=&r" (status), [cnt] "=&r" (cnt)
	: [addr] "r" (q->addr), [exp] "r" (q->exp), [des] "r" (q->des),
	  [af] "r" (q->a), [rf] "r" (q->r), [al] "r" (q->al)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_cas_64);

/*
 * CASP with sz=1: 2x64, 16-byte aligned, 128-bit footprint.  v8.0 LDXP is
 * not a single-copy atomic load, so a mismatch is answered by a same-value
 * STXP whose success validates the whole 128-bit reservation before the
 * old pair is reported (design §3.4: the validation may not be skipped).
 */
static noinline notrace void lse_emu_casp_64(struct lse_emu_req *q)
{
	u64 old0, old1, val0, val1, t1, t2;
	u32 st, status, cnt;

	asm volatile(
	"	clrex\n"
	"	mov	%w[cnt], #16\n"
	"1:	cbz	%w[af], 2f\n"
	"61:	ldaxp	%[old0], %[old1], [%[addr]]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxp	%[old0], %[old1], [%[addr]]\n"
	"4:	cmp	%[old0], %[exp0]\n"
	"	cset	%[t1], ne\n"
	"	cmp	%[old1], %[exp1]\n"
	"	cset	%[t2], ne\n"
	"	orr	%[t1], %[t1], %[t2]\n"
	"	cmp	%[t1], xzr\n"
	"	csel	%[val0], %[des0], %[old0], eq\n"
	"	csel	%[val1], %[des1], %[old1], eq\n"
	"6:	cbz	%w[rf], 8f\n"
	"63:	stlxp	%w[st], %[val0], %[val1], [%[addr]]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxp	%w[st], %[val0], %[val1], [%[addr]]\n"
	"9:	cbnz	%w[st], 20f\n"
	"	cbz	%w[al], 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"20:	sub	%w[cnt], %w[cnt], #1\n"
	"	cbnz	%w[cnt], 1b\n"
	"	clrex\n"
	"	mov	%w[status], #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	: [old0] "=&r" (old0), [old1] "=&r" (old1), [val0] "=&r" (val0),
	  [val1] "=&r" (val1), [t1] "=&r" (t1), [t2] "=&r" (t2),
	  [st] "=&r" (st), [status] "=&r" (status), [cnt] "=&r" (cnt)
	: [addr] "r" (q->addr), [exp0] "r" (q->exp), [exp1] "r" (q->exp1),
	  [des0] "r" (q->des), [des1] "r" (q->des1),
	  [af] "r" (q->a), [rf] "r" (q->r), [al] "r" (q->al)
	: "cc");

	q->old = old0;
	q->old1 = old1;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_casp_64);

/*
 * LDAPR -> LDAR of the same width (RCsc strengthening, design §3.2).
 * Single load, no retry loop, no write of any kind.
 */
static noinline notrace void lse_emu_ldapr_8(struct lse_emu_req *q)
{
	u32 old, status;

	asm volatile(
	"	clrex\n"
	"61:	ldarb	%w[old], [%[addr]]\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [status] "=&r" (status)
	: [addr] "r" (q->addr)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_ldapr_8);

static noinline notrace void lse_emu_ldapr_16(struct lse_emu_req *q)
{
	u32 old, status;

	asm volatile(
	"	clrex\n"
	"61:	ldarh	%w[old], [%[addr]]\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [status] "=&r" (status)
	: [addr] "r" (q->addr)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_ldapr_16);

static noinline notrace void lse_emu_ldapr_32(struct lse_emu_req *q)
{
	u32 old, status;

	asm volatile(
	"	clrex\n"
	"61:	ldar	%w[old], [%[addr]]\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [status] "=&r" (status)
	: [addr] "r" (q->addr)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_ldapr_32);

static noinline notrace void lse_emu_ldapr_64(struct lse_emu_req *q)
{
	u64 old;
	u32 status;

	asm volatile(
	"	clrex\n"
	"61:	ldar	%[old], [%[addr]]\n"
	"	mov	%w[status], #1\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	%w[status], #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.popsection\n"
	: [old] "=&r" (old), [status] "=&r" (status)
	: [addr] "r" (q->addr)
	: "cc");

	q->old = old;
	q->status = status;
}
NOKPROBE_SYMBOL(lse_emu_ldapr_64);

asm(".pushsection .text\n"
    "__lse_emu_text_end:\n"
    ".popsection\n");

/* Run one bounded attempt batch with the helper selected by the decode. */
static notrace void lse_emu_attempt(struct lse_emu_req *q,
				    const struct lse_emu_desc *d)
{
	switch (d->fam) {
	case LSE_FAM_RMW:
		switch (d->size) {
		case 0: lse_emu_rmw_8(q);  return;
		case 1: lse_emu_rmw_16(q); return;
		case 2: lse_emu_rmw_32(q); return;
		default: lse_emu_rmw_64(q); return;
		}
	case LSE_FAM_CAS:
		switch (d->size) {
		case 0: lse_emu_cas_8(q);  return;
		case 1: lse_emu_cas_16(q); return;
		case 2: lse_emu_cas_32(q); return;
		default: lse_emu_cas_64(q); return;
		}
	case LSE_FAM_CASP:
		if (d->size == 0)
			lse_emu_cas_64(q);	/* pair as one 64-bit op */
		else
			lse_emu_casp_64(q);
		return;
	default:
		switch (d->size) {
		case 0: lse_emu_ldapr_8(q);  return;
		case 1: lse_emu_ldapr_16(q); return;
		case 2: lse_emu_ldapr_32(q); return;
		default: lse_emu_ldapr_64(q); return;
		}
	}
}

/* ------------------------------------------------------------------ */
/* Active context + narrow bridges (called from fault.c)              */
/* ------------------------------------------------------------------ */

static inline struct lse_emu_ctx *lse_emu_this_ctx(void)
{
	return this_cpu_ptr(&lse_emu_ctx);
}

static inline bool lse_emu_pc_in_helpers(unsigned long pc)
{
	return (unsigned long)__lse_emu_text_start <= pc &&
	       pc < (unsigned long)__lse_emu_text_end;
}

/*
 * Narrow fault bridge (design §4.2): called from do_mem_abort() for
 * kernel-mode data aborts.  Only when the emulation context is active and
 * the inner PC sits on one of the helper's exact extable sites do we
 * capture the syndrome and redirect to the attempt fixup; every other
 * exception keeps the original path.
 */
int lse_emu_mem_abort_hook(unsigned long addr, unsigned int esr,
			   struct pt_regs *regs)
{
	struct lse_emu_ctx *ctx = lse_emu_this_ctx();

	if (!ctx->active || !lse_emu_pc_in_helpers(regs->pc) ||
	    !search_exception_tables(regs->pc))
		return 0;

	ctx->addr = addr;
	ctx->esr = esr;
	ctx->ev = LSE_EMU_EV_FAULT;
	fixup_exception(regs);
	return 1;
}
NOKPROBE_SYMBOL(lse_emu_mem_abort_hook);

#ifdef CONFIG_HAVE_HW_BREAKPOINT
/* True if this task has EL0-privilege hardware watchpoints installed. */
static bool lse_emu_task_has_el0_wp(void)
{
	int i;

	for (i = 0; i < ARM_MAX_WRP; i++) {
		struct perf_event *wp = current->thread.debug.hbp_watch[i];

		if (wp && counter_arch_bp(wp)->ctrl.privilege ==
			  AARCH64_BREAKPOINT_EL0)
			return true;
	}
	return false;
}
#endif

/*
 * Narrow debug bridge (design §6): called from do_debug_exception() for
 * kernel-mode debug exceptions.  A data watchpoint can match the inner
 * EL1 access performed on behalf of the emulated instruction.  The commit
 * must not be lost to the debug machinery:
 *  - store-side hit (WnR=1): the exclusive store has already completed
 *    (a failed STXR performs no access and matches nothing), so resume at
 *    pc+4 and let the helper finish the verified commit;
 *  - load-side hit (WnR=0): nothing has been committed; abort the attempt
 *    via the extable fixup and re-execute later with the watchpoints
 *    suppressed so no event is reported twice.
 * In both cases user watchpoints are suppressed/restored through the
 * existing wps_disabled machinery; non-watchpoint debug events and events
 * of tasks without EL0 watchpoints keep the original path.
 */
int lse_emu_debug_hook(unsigned long addr, unsigned int esr,
		       struct pt_regs *regs)
{
	struct lse_emu_ctx *ctx = lse_emu_this_ctx();

	if (!ctx->active || !lse_emu_pc_in_helpers(regs->pc))
		return 0;
	if (ESR_ELx_EC(esr) != ESR_ELx_EC_WATCHPT_CUR)
		return 0;
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	if (!lse_emu_task_has_el0_wp())
		return 0;

	lse_emu_wp_suppress();
	ctx->addr = addr;
	ctx->esr = esr;
	ctx->ev = LSE_EMU_EV_DEBUG;
	if (esr & AARCH64_ESR_ACCESS_MASK)	/* store-side: store done */
		regs->pc += 4;
	else
		fixup_exception(regs);		/* load-side: abort */
	return 1;
#else
	return 0;
#endif
}
NOKPROBE_SYMBOL(lse_emu_debug_hook);

/* ------------------------------------------------------------------ */
/* Signal delivery (si_addr = data address, design §4.2)              */
/* ------------------------------------------------------------------ */

static void lse_emu_force_sig(int sig, int code, unsigned long addr,
			      struct pt_regs *regs)
{
	struct siginfo info;

	memset(&info, 0, sizeof(info));
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = code;
	info.si_addr = (void __user *)addr;
	arm64_notify_die("LSE emulation", regs, &info, 0);
}

/* ------------------------------------------------------------------ */
/* Validation before any window is opened (design §4.1)               */
/* ------------------------------------------------------------------ */

static bool lse_emu_check_vma(struct mm_struct *mm, unsigned long addr,
			      unsigned long len, bool write, int *sig,
			      int *code)
{
	struct vm_area_struct *vma;

	vma = find_vma(mm, addr);
	/* find_vma() may return a vma that starts behind addr: check gap. */
	if (!vma || vma->vm_start > addr || addr + len > vma->vm_end) {
		*sig = SIGSEGV;
		*code = SEGV_MAPERR;
		return false;
	}

	/*
	 * RMW/CAS/CASP are logical read+write: require write permission
	 * (on arm64 a writable PTE is readable, so VM_WRITE alone may be
	 * sufficient - do not mechanically require VM_READ).  LDAPR is a
	 * pure read.  A compare failure or a ZR source does not waive the
	 * permission requirements.
	 */
	if (write) {
		if (!(vma->vm_flags & VM_WRITE)) {
			*sig = SIGSEGV;
			*code = SEGV_ACCERR;
			return false;
		}
	} else if (!(vma->vm_flags & (VM_READ | VM_WRITE))) {
		*sig = SIGSEGV;
		*code = SEGV_ACCERR;
		return false;
	}

	/* Correctness domain: Normal WB, Inner Shareable only (design §0). */
	if ((vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP | VM_IO)) ||
	    (pgprot_val(vma->vm_page_prot) & PTE_ATTRINDX_MASK) !=
							PTE_ATTRINDX(MT_NORMAL) ||
	    (pgprot_val(vma->vm_page_prot) & PTE_SHARED) != PTE_SHARED) {
		*sig = SIGBUS;
		*code = BUS_ADRERR;
		return false;
	}

	return true;
}

/* ------------------------------------------------------------------ */
/* Undef hook handler                                                 */
/* ------------------------------------------------------------------ */

static int lse_emu_handler(struct pt_regs *regs, u32 insn)
{
	struct lse_emu_desc d;
	struct lse_emu_req q;
	struct lse_emu_ctx *ctx;
	struct mm_struct *mm = current->mm;
	unsigned long addr;
	unsigned long flags;
	unsigned int ev, iesr;
	unsigned long iaddr;
	int sig = 0, code = 0;
	bool write;

	if (!user_mode(regs))
		return 1;

	if (!lse_emu_decode(insn, &d))
		return 1;		/* illegal encoding: standard SIGILL */

	perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS, 1, regs, regs->pc);

	memset(&q, 0, sizeof(q));
	q.op = d.op;
	q.a  = d.a;
	q.r  = d.r;
	q.al = d.a && d.r;

	/*
	 * Snapshot every input before anything is committed (design §2.2).
	 * Rn = 31 reads SP, data registers read through ZR semantics.
	 */
	addr = (unsigned long)lse_emu_read_base(regs, d.rn);
	/* TCR.TBI0 hardware rule: strip the top byte (untagged_addr). */
	addr = (unsigned long)untagged_addr(addr);

	/* Natural alignment; CASP checks the whole pair. */
	if (addr & (d.bytes - 1)) {
		lse_emu_force_sig(SIGBUS, BUS_ADRALN, addr, regs);
		return 0;
	}
	/* SP alignment check when the base is SP and SCTLR_EL1.SA0 is set. */
	if (d.rn == 31 && (read_sysreg(sctlr_el1) & SCTLR_EL1_SA0) &&
	    (addr & 15)) {
		lse_emu_force_sig(SIGBUS, BUS_ADRALN, addr, regs);
		return 0;
	}
	/* USER_DS range incl. overflow, then the CSDB-hardened pointer. */
	if (!access_ok(VERIFY_WRITE, (void __user *)addr, d.bytes)) {
		lse_emu_force_sig(SIGSEGV, SEGV_MAPERR, addr, regs);
		return 0;
	}
	q.addr = (unsigned long)uaccess_mask_ptr((void __user *)addr);

	switch (d.fam) {
	case LSE_FAM_RMW:
		q.src = lse_emu_read_data(regs, d.rs) &
			lse_emu_width_mask(d.bytes);
		break;
	case LSE_FAM_CAS:
		q.exp = lse_emu_read_data(regs, d.rs) &
			lse_emu_width_mask(d.bytes);
		q.des = lse_emu_read_data(regs, d.rt) &
			lse_emu_width_mask(d.bytes);
		break;
	case LSE_FAM_CASP:
		if (d.size == 0) {
			/* 2x32: compare/update as one 64-bit word (LE). */
			u64 e0 = (u32)lse_emu_read_data(regs, d.rs);
			u64 e1 = (u32)lse_emu_read_data(regs, d.rs + 1);
			u64 d0 = (u32)lse_emu_read_data(regs, d.rt);
			u64 d1 = (u32)lse_emu_read_data(regs, d.rt + 1);

			q.exp = (e1 << 32) | e0;
			q.des = (d1 << 32) | d0;
		} else {
			q.exp  = lse_emu_read_data(regs, d.rs);
			q.exp1 = lse_emu_read_data(regs, d.rs + 1);
			q.des  = lse_emu_read_data(regs, d.rt);
			q.des1 = lse_emu_read_data(regs, d.rt + 1);
		}
		break;
	default:
		break;	/* LDAPR: no data operands */
	}

	write = d.fam != LSE_FAM_LDAPR;

	for (;;) {
		int result;

		/* VMA view taken outside the exclusive window (design §4.1). */
		down_read(&mm->mmap_sem);
		if (!lse_emu_check_vma(mm, addr, d.bytes, write, &sig, &code)) {
			up_read(&mm->mmap_sem);
			lse_emu_force_sig(sig, code, addr, regs);
			return 0;
		}

		/* Open the attempt window. */
		preempt_disable();
		local_irq_save(flags);
		pagefault_disable();
		uaccess_enable();

		ctx = lse_emu_this_ctx();
		ctx->active = 1;
		ctx->ev = LSE_EMU_EV_NONE;
		ctx->esr = 0;
		ctx->addr = 0;

		lse_emu_attempt(&q, &d);

		/* Copy the bridge state out before leaving the window. */
		ev = ctx->ev;
		iesr = ctx->esr;
		iaddr = ctx->addr;
		ctx->active = 0;
		ctx->ev = LSE_EMU_EV_NONE;

		result = q.status;

		uaccess_disable();
		pagefault_enable();
		local_irq_restore(flags);
		preempt_enable();
		up_read(&mm->mmap_sem);

		if (result == LSE_EMU_COMMITTED) {
			u64 mask = lse_emu_width_mask(d.bytes);

			/* Write only the architectural outputs. */
			switch (d.fam) {
			case LSE_FAM_RMW:
				lse_emu_write_data(regs, d.rt, q.old & mask);
				break;
			case LSE_FAM_CAS:
				/* CAS returns the old value in Rs. */
				lse_emu_write_data(regs, d.rs, q.old & mask);
				break;
			case LSE_FAM_CASP:
				if (d.size == 0) {
					lse_emu_write_data(regs, d.rs,
							   (u32)q.old);
					lse_emu_write_data(regs, d.rs + 1,
							   (u32)(q.old >> 32));
				} else {
					lse_emu_write_data(regs, d.rs, q.old);
					lse_emu_write_data(regs, d.rs + 1,
							   q.old1);
				}
				break;
			default:
				lse_emu_write_data(regs, d.rt, q.old & mask);
				break;
			}

			if (ev == LSE_EMU_EV_DEBUG) {
				/*
				 * Store-side watchpoint hit: the exclusive
				 * store already committed, the helper just
				 * verified it.  Advance PC manually (do not
				 * clear the single-step state) and forward
				 * the debug event with the data address.
				 */
				regs->pc += 4;
				lse_emu_wp_restore();
				lse_emu_force_sig(SIGTRAP, TRAP_HWBKPT,
						  iaddr, regs);
			} else {
				arm64_skip_faulting_instruction(regs, 4);
				/*
				 * If a load-side watchpoint suppressed the
				 * EL0 watchpoints earlier (event forwarded,
				 * instruction re-executed), the commit is
				 * now done: restore them immediately.
				 */
				lse_emu_wp_restore();
			}
			return 0;
		}

		if (result == LSE_EMU_FAULT && ev == LSE_EMU_EV_DEBUG) {
			/*
			 * Load-side watchpoint hit: nothing committed, PC
			 * untouched, watchpoints stay suppressed until the
			 * (re-)execution of this instruction commits.
			 */
			lse_emu_force_sig(SIGTRAP, TRAP_HWBKPT, iaddr, regs);
			return 0;
		}

		if (result == LSE_EMU_FAULT) {
			/*
			 * Forward as the original EL0 user abort: real
			 * FSC/FAR from the inner fault, EC=DABT_LOW, IL=1,
			 * ISV=0 (design §4.2).  WnR reflects the logical
			 * access so COW is resolved for RMW/CAS/CASP.
			 */
			u32 esr = (ESR_ELx_EC_DABT_LOW << ESR_ELx_EC_SHIFT) |
				  ESR_ELx_IL | (iesr & ESR_ELx_FSC);

			if (write)
				esr |= ESR_ELx_WNR;
			do_mem_abort(iaddr, esr, regs);

			if (signal_pending(current))
				return 0;	/* PC unchanged; retry by user */
			continue;
		}

		/* LSE_EMU_RETRY: batch exhausted, nothing committed. */
		if (signal_pending(current))
			return 0;	/* PC unchanged; ret_to_user delivers */
		cond_resched();
	}
}
NOKPROBE_SYMBOL(lse_emu_handler);

/* ------------------------------------------------------------------ */
/* Registration: 12 disjoint hooks (9 RMW ops + CAS + CASP + LDAPR)    */
/* ------------------------------------------------------------------ */

#define LSE_EMU_PSTATE_MASK	(PSR_MODE_MASK | PSR_MODE32_BIT)
#define LSE_EMU_PSTATE_VAL	PSR_MODE_EL0t

static struct undef_hook lse_emu_hooks[12] = {
	/* RMW ops 0..8 */
	{ .instr_mask = 0x3f20fc00, .instr_val = 0x38200000 | (0 << 12) },
	{ .instr_mask = 0x3f20fc00, .instr_val = 0x38200000 | (1 << 12) },
	{ .instr_mask = 0x3f20fc00, .instr_val = 0x38200000 | (2 << 12) },
	{ .instr_mask = 0x3f20fc00, .instr_val = 0x38200000 | (3 << 12) },
	{ .instr_mask = 0x3f20fc00, .instr_val = 0x38200000 | (4 << 12) },
	{ .instr_mask = 0x3f20fc00, .instr_val = 0x38200000 | (5 << 12) },
	{ .instr_mask = 0x3f20fc00, .instr_val = 0x38200000 | (6 << 12) },
	{ .instr_mask = 0x3f20fc00, .instr_val = 0x38200000 | (7 << 12) },
	{ .instr_mask = 0x3f20fc00, .instr_val = 0x38200000 | (8 << 12) },
	/* CAS */
	{ .instr_mask = 0x3fa07c00, .instr_val = 0x08a07c00 },
	/* CASP */
	{ .instr_mask = 0xbfa07c00, .instr_val = 0x08207c00 },
	/* LDAPR */
	{ .instr_mask = 0x3ffffc00, .instr_val = 0x38bfc000 },
};

/*
 * call_undef_hook() keeps only the last matching fn; the masks above are
 * pairwise disjoint so exactly one entry matches any given instruction and
 * the shared handler below re-decodes anyway.
 */
static void __init lse_emu_hooks_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(lse_emu_hooks); i++) {
		lse_emu_hooks[i].pstate_mask = LSE_EMU_PSTATE_MASK;
		lse_emu_hooks[i].pstate_val = LSE_EMU_PSTATE_VAL;
		lse_emu_hooks[i].fn = lse_emu_handler;
		register_undef_hook(&lse_emu_hooks[i]);
	}
}

/* Verify the helper bodies really sit between the assembler markers. */
static bool __init lse_emu_layout_ok(void)
{
	static void (*const helpers[])(struct lse_emu_req *) = {
		lse_emu_rmw_8, lse_emu_rmw_16, lse_emu_rmw_32, lse_emu_rmw_64,
		lse_emu_cas_8, lse_emu_cas_16, lse_emu_cas_32, lse_emu_cas_64,
		lse_emu_casp_64,
		lse_emu_ldapr_8, lse_emu_ldapr_16, lse_emu_ldapr_32,
		lse_emu_ldapr_64,
	};
	unsigned long start = (unsigned long)__lse_emu_text_start;
	unsigned long end = (unsigned long)__lse_emu_text_end;
	int i;

	for (i = 0; i < ARRAY_SIZE(helpers); i++) {
		unsigned long pc = (unsigned long)helpers[i];

		if (pc < start || pc >= end)
			return false;
	}
	return true;
}

/* Diagnostic boot param: arm64.user_lse_emulation=on|off (default on). */
static int __init lse_emu_param(char *str)
{
	if (!str)
		return -EINVAL;
	if (!strcmp(str, "off"))
		lse_emu_enabled = false;
	else if (strcmp(str, "on"))
		return 1;
	return 0;
}
early_param("arm64.user_lse_emulation", lse_emu_param);

static int __init lse_emulate_init(void)
{
	if (!lse_emu_enabled) {
		pr_info("LSE emulation disabled (arm64.user_lse_emulation=off)\n");
		return 0;
	}

	if (!lse_emu_layout_ok()) {
		pr_warn("LSE emulation disabled: helper layout check failed\n");
		return 0;
	}

	lse_emu_hooks_init();
	pr_info("LSE/LDAPR user emulation enabled (v8.0 cores)\n");
	return 0;
}
core_initcall(lse_emulate_init);
