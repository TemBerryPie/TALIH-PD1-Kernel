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
 *    original EL0 data abort: EC=DABT_LOW, IL=1, ISV=0 with the inner FSC
 *    plus EA/FnV preserved (si_addr invalid when FnV=1, matching do_sea()
 *    in this tree) and the logical WnR of the emulated access;
 *  - EL0 hardware watchpoints hit by the inner accesses cancel the attempt
 *    and are reported once per hit as SIGTRAP/TRAP_HWBKPT with the user PC
 *    untouched: per ARM DDI 0487A D2.10.8 the matched instruction has not
 *    executed and the memory location is Unchanged, so the instruction is
 *    simply re-executed, and every re-execution that hits the watchpoint
 *    again reports again -- exactly the behaviour of a native LL/SC
 *    sequence under a watchpoint.  Watchpoints are never suppressed
 *    (cancel = trap): no disable window, no restore bookkeeping, no way to
 *    lose a commit; zero memory risk, correctness first;
 *  - illegal encodings are not intercepted (hook returns unhandled and the
 *    standard SIGILL/ILL_ILLOPC path runs with the PC left alone);
 *  - HWCAP_ATOMICS / HWCAP_LRCPC are NOT advertised and the ID registers
 *    are not modified: only statically-encoded sites trap here.
 */

#include <linux/compiler.h>
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
#include <linux/stringify.h>
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
 * struct lse_emu_req field offsets for the LL/SC helper bodies below: they
 * are plain assembler routines (no C operands are available in bare
 * file-scope asm) and address the request through x0 with these offsets.
 * The values are pinned against the C layout by BUILD_BUG_ONs in
 * lse_emulate_init() so the struct and the asm can never drift apart.
 */
#define LSE_REQ_OFF_ADDR	0	/* u64  masked user pointer      */
#define LSE_REQ_OFF_SRC		8	/* u64  RMW source               */
#define LSE_REQ_OFF_EXP		16	/* u64  CAS/CASP expected        */
#define LSE_REQ_OFF_EXP1	24	/* u64  CASP64 expected high     */
#define LSE_REQ_OFF_DES		32	/* u64  CAS/CASP desired         */
#define LSE_REQ_OFF_DES1	40	/* u64  CASP64 desired high      */
#define LSE_REQ_OFF_OLD		48	/* u64  out: old value           */
#define LSE_REQ_OFF_OLD1	56	/* u64  out: CASP64 old high     */
#define LSE_REQ_OFF_STATUS	64	/* u32  out: LSE_EMU_* status    */
#define LSE_REQ_OFF_OP		68	/* u32  RMW op                   */
#define LSE_REQ_OFF_A		72	/* u32  acquire flag             */
#define LSE_REQ_OFF_R		76	/* u32  release flag             */
#define LSE_REQ_OFF_AL		80	/* u32  A+R post-commit DMB flag */

/*
 * Active emulation context.  `active` is set just before the bounded LL/SC
 * attempt and cleared again before preempt is re-enabled, so it never spans
 * a slow path; the narrow bridges in do_mem_abort()/do_debug_exception()
 * consult it (design §4.2/§6).
 */
struct lse_emu_ctx {
	u8	active;
	u8	ev;		/* LSE_EMU_EV_* for the current attempt */
	u32	esr;		/* full inner syndrome (FSC/EA/FnV or debug ESR) */
	unsigned long addr;	/* data address (FAR) of the inner event */
};
static DEFINE_PER_CPU(struct lse_emu_ctx, lse_emu_ctx);

/*
 * The LL/SC helper bodies below are the only code that may fault while the
 * context is active.  They are emitted into their own dedicated section
 * .text.lse_emu, which vmlinux.lds.S places contiguously with KEEP() between
 * the exported boundary symbols __lse_emu_start/__lse_emu_end.  The fault
 * and debug bridges verify the inner PC against those real section boundary
 * symbols (no fragile assembler markers), and the bracket is validated at
 * init time (lse_emu_layout_ok): emulation is disabled if the section does
 * not contain exactly the 13 helper entries and their extable sites.
 */
extern char __lse_emu_start[], __lse_emu_end[];

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
/* LL/SC helpers (design §3.3).  One bare-assembler body per          */
/* family/size; the acquire/release forms are selected inside the     */
/* body so that the whole bounded batch stays one closed region with  */
/* no C call, no spill and no barrier between the exclusive load and  */
/* store.                                                             */
/* ------------------------------------------------------------------ */

/*
 * The 13 helper bodies below are plain assembler routines that follow the
 * AAPCS calling convention -- q arrives in x0, results are written back
 * into the request fields, only caller-saved registers are touched and
 * they return with ret -- so the C dispatch (lse_emu_attempt) calls them
 * like ordinary functions and lse_emu_layout_ok() can take their entry
 * addresses.  Being bare file-scope asm, each body addresses the request
 * with the LSE_REQ_OFF_* offsets and a fixed register map (documented per
 * body); no compiler-allocated operands exist at file scope.
 *
 * Every body is emitted into the dedicated .text.lse_emu section
 * (.pushsection ... .popsection) and carries its own __ex_table entries
 * (61..64 -> the per-block 65: fixup site), so a faulting inner access is
 * always redirected to the same block's fixup, which performs no user
 * memory access.
 */
void lse_emu_rmw_8_body(struct lse_emu_req *q);
void lse_emu_rmw_16_body(struct lse_emu_req *q);
void lse_emu_rmw_32_body(struct lse_emu_req *q);
void lse_emu_rmw_64_body(struct lse_emu_req *q);
void lse_emu_cas_8_body(struct lse_emu_req *q);
void lse_emu_cas_16_body(struct lse_emu_req *q);
void lse_emu_cas_32_body(struct lse_emu_req *q);
void lse_emu_cas_64_body(struct lse_emu_req *q);
void lse_emu_casp_64_body(struct lse_emu_req *q);
void lse_emu_ldapr_8_body(struct lse_emu_req *q);
void lse_emu_ldapr_16_body(struct lse_emu_req *q);
void lse_emu_ldapr_32_body(struct lse_emu_req *q);
void lse_emu_ldapr_64_body(struct lse_emu_req *q);

/*
 * RMW, 8/16/32-bit: one register map for the three 32-bit forms.
 *   x1 addr, w2 op, w3 af, w4 rf, w5 al, w6 src, w7 old, w8 val,
 *   w9 st, w10 status, w11 t1, w12 t2, w13 cnt
 * Ops 4..7 (signed/unsigned max/min) need sign extension only for the
 * byte and halfword forms; 32/64-bit compare directly.
 */
asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_rmw_8_body\n"
	"lse_emu_rmw_8_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	ldr	w2, [x0, #" __stringify(LSE_REQ_OFF_OP) "]\n"
	"	ldr	w3, [x0, #" __stringify(LSE_REQ_OFF_A) "]\n"
	"	ldr	w4, [x0, #" __stringify(LSE_REQ_OFF_R) "]\n"
	"	ldr	w5, [x0, #" __stringify(LSE_REQ_OFF_AL) "]\n"
	"	ldr	w6, [x0, #" __stringify(LSE_REQ_OFF_SRC) "]\n"
	"	clrex\n"
	"	mov	w13, #16\n"
	"1:	cbz	w3, 2f\n"
	"61:	ldaxrb	w7, [x1]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxrb	w7, [x1]\n"
	"4:	cmp	w2, #0\n"
	"	b.eq	40f\n"
	"	cmp	w2, #1\n"
	"	b.eq	41f\n"
	"	cmp	w2, #2\n"
	"	b.eq	42f\n"
	"	cmp	w2, #3\n"
	"	b.eq	43f\n"
	"	cmp	w2, #4\n"
	"	b.eq	44f\n"
	"	cmp	w2, #5\n"
	"	b.eq	45f\n"
	"	cmp	w2, #6\n"
	"	b.eq	46f\n"
	"	cmp	w2, #7\n"
	"	b.eq	47f\n"
	"	mov	w8, w6\n"
	"	b	6f\n"
	"40:	add	w8, w7, w6\n"
	"	b	6f\n"
	"41:	bic	w8, w7, w6\n"
	"	b	6f\n"
	"42:	eor	w8, w7, w6\n"
	"	b	6f\n"
	"43:	orr	w8, w7, w6\n"
	"	b	6f\n"
	"44:	sxtb	w11, w7\n"
	"	sxtb	w12, w6\n"
	"	cmp	w11, w12\n"
	"	csel	w8, w7, w6, ge\n"
	"	b	6f\n"
	"45:	sxtb	w11, w7\n"
	"	sxtb	w12, w6\n"
	"	cmp	w11, w12\n"
	"	csel	w8, w7, w6, le\n"
	"	b	6f\n"
	"46:	cmp	w7, w6\n"
	"	csel	w8, w7, w6, hs\n"
	"	b	6f\n"
	"47:	cmp	w7, w6\n"
	"	csel	w8, w7, w6, ls\n"
	"6:	cbz	w4, 8f\n"
	"63:	stlxrb	w9, w8, [x1]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxrb	w9, w8, [x1]\n"
	"9:	cbnz	w9, 20f\n"
	"	cbz	w5, 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	w10, #1\n"
	"	b	99f\n"
	"20:	sub	w13, w13, #1\n"
	"	cbnz	w13, 1b\n"
	"	clrex\n"
	"	mov	w10, #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w10, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	"	str	w7, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w10, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_rmw_8_body);

asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_rmw_16_body\n"
	"lse_emu_rmw_16_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	ldr	w2, [x0, #" __stringify(LSE_REQ_OFF_OP) "]\n"
	"	ldr	w3, [x0, #" __stringify(LSE_REQ_OFF_A) "]\n"
	"	ldr	w4, [x0, #" __stringify(LSE_REQ_OFF_R) "]\n"
	"	ldr	w5, [x0, #" __stringify(LSE_REQ_OFF_AL) "]\n"
	"	ldr	w6, [x0, #" __stringify(LSE_REQ_OFF_SRC) "]\n"
	"	clrex\n"
	"	mov	w13, #16\n"
	"1:	cbz	w3, 2f\n"
	"61:	ldaxrh	w7, [x1]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxrh	w7, [x1]\n"
	"4:	cmp	w2, #0\n"
	"	b.eq	40f\n"
	"	cmp	w2, #1\n"
	"	b.eq	41f\n"
	"	cmp	w2, #2\n"
	"	b.eq	42f\n"
	"	cmp	w2, #3\n"
	"	b.eq	43f\n"
	"	cmp	w2, #4\n"
	"	b.eq	44f\n"
	"	cmp	w2, #5\n"
	"	b.eq	45f\n"
	"	cmp	w2, #6\n"
	"	b.eq	46f\n"
	"	cmp	w2, #7\n"
	"	b.eq	47f\n"
	"	mov	w8, w6\n"
	"	b	6f\n"
	"40:	add	w8, w7, w6\n"
	"	b	6f\n"
	"41:	bic	w8, w7, w6\n"
	"	b	6f\n"
	"42:	eor	w8, w7, w6\n"
	"	b	6f\n"
	"43:	orr	w8, w7, w6\n"
	"	b	6f\n"
	"44:	sxth	w11, w7\n"
	"	sxth	w12, w6\n"
	"	cmp	w11, w12\n"
	"	csel	w8, w7, w6, ge\n"
	"	b	6f\n"
	"45:	sxth	w11, w7\n"
	"	sxth	w12, w6\n"
	"	cmp	w11, w12\n"
	"	csel	w8, w7, w6, le\n"
	"	b	6f\n"
	"46:	cmp	w7, w6\n"
	"	csel	w8, w7, w6, hs\n"
	"	b	6f\n"
	"47:	cmp	w7, w6\n"
	"	csel	w8, w7, w6, ls\n"
	"6:	cbz	w4, 8f\n"
	"63:	stlxrh	w9, w8, [x1]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxrh	w9, w8, [x1]\n"
	"9:	cbnz	w9, 20f\n"
	"	cbz	w5, 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	w10, #1\n"
	"	b	99f\n"
	"20:	sub	w13, w13, #1\n"
	"	cbnz	w13, 1b\n"
	"	clrex\n"
	"	mov	w10, #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w10, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	"	str	w7, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w10, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_rmw_16_body);

asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_rmw_32_body\n"
	"lse_emu_rmw_32_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	ldr	w2, [x0, #" __stringify(LSE_REQ_OFF_OP) "]\n"
	"	ldr	w3, [x0, #" __stringify(LSE_REQ_OFF_A) "]\n"
	"	ldr	w4, [x0, #" __stringify(LSE_REQ_OFF_R) "]\n"
	"	ldr	w5, [x0, #" __stringify(LSE_REQ_OFF_AL) "]\n"
	"	ldr	w6, [x0, #" __stringify(LSE_REQ_OFF_SRC) "]\n"
	"	clrex\n"
	"	mov	w13, #16\n"
	"1:	cbz	w3, 2f\n"
	"61:	ldaxr	w7, [x1]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxr	w7, [x1]\n"
	"4:	cmp	w2, #0\n"
	"	b.eq	40f\n"
	"	cmp	w2, #1\n"
	"	b.eq	41f\n"
	"	cmp	w2, #2\n"
	"	b.eq	42f\n"
	"	cmp	w2, #3\n"
	"	b.eq	43f\n"
	"	cmp	w2, #4\n"
	"	b.eq	44f\n"
	"	cmp	w2, #5\n"
	"	b.eq	45f\n"
	"	cmp	w2, #6\n"
	"	b.eq	46f\n"
	"	cmp	w2, #7\n"
	"	b.eq	47f\n"
	"	mov	w8, w6\n"
	"	b	6f\n"
	"40:	add	w8, w7, w6\n"
	"	b	6f\n"
	"41:	bic	w8, w7, w6\n"
	"	b	6f\n"
	"42:	eor	w8, w7, w6\n"
	"	b	6f\n"
	"43:	orr	w8, w7, w6\n"
	"	b	6f\n"
	"44:	cmp	w7, w6\n"
	"	csel	w8, w7, w6, ge\n"
	"	b	6f\n"
	"45:	cmp	w7, w6\n"
	"	csel	w8, w7, w6, le\n"
	"	b	6f\n"
	"46:	cmp	w7, w6\n"
	"	csel	w8, w7, w6, hs\n"
	"	b	6f\n"
	"47:	cmp	w7, w6\n"
	"	csel	w8, w7, w6, ls\n"
	"6:	cbz	w4, 8f\n"
	"63:	stlxr	w9, w8, [x1]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxr	w9, w8, [x1]\n"
	"9:	cbnz	w9, 20f\n"
	"	cbz	w5, 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	w10, #1\n"
	"	b	99f\n"
	"20:	sub	w13, w13, #1\n"
	"	cbnz	w13, 1b\n"
	"	clrex\n"
	"	mov	w10, #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w10, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	"	str	w7, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w10, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_rmw_32_body);

/*
 * RMW, 64-bit: x1 addr, x2 src, w3 op, w4 af, w5 rf, w6 al, x7 old,
 * x8 val, w9 st, w10 status, w11 cnt.
 */
asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_rmw_64_body\n"
	"lse_emu_rmw_64_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	ldr	x2, [x0, #" __stringify(LSE_REQ_OFF_SRC) "]\n"
	"	ldr	w3, [x0, #" __stringify(LSE_REQ_OFF_OP) "]\n"
	"	ldr	w4, [x0, #" __stringify(LSE_REQ_OFF_A) "]\n"
	"	ldr	w5, [x0, #" __stringify(LSE_REQ_OFF_R) "]\n"
	"	ldr	w6, [x0, #" __stringify(LSE_REQ_OFF_AL) "]\n"
	"	clrex\n"
	"	mov	w11, #16\n"
	"1:	cbz	w4, 2f\n"
	"61:	ldaxr	x7, [x1]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxr	x7, [x1]\n"
	"4:	cmp	w3, #0\n"
	"	b.eq	40f\n"
	"	cmp	w3, #1\n"
	"	b.eq	41f\n"
	"	cmp	w3, #2\n"
	"	b.eq	42f\n"
	"	cmp	w3, #3\n"
	"	b.eq	43f\n"
	"	cmp	w3, #4\n"
	"	b.eq	44f\n"
	"	cmp	w3, #5\n"
	"	b.eq	45f\n"
	"	cmp	w3, #6\n"
	"	b.eq	46f\n"
	"	cmp	w3, #7\n"
	"	b.eq	47f\n"
	"	mov	x8, x2\n"
	"	b	6f\n"
	"40:	add	x8, x7, x2\n"
	"	b	6f\n"
	"41:	bic	x8, x7, x2\n"
	"	b	6f\n"
	"42:	eor	x8, x7, x2\n"
	"	b	6f\n"
	"43:	orr	x8, x7, x2\n"
	"	b	6f\n"
	"44:	cmp	x7, x2\n"
	"	csel	x8, x7, x2, ge\n"
	"	b	6f\n"
	"45:	cmp	x7, x2\n"
	"	csel	x8, x7, x2, le\n"
	"	b	6f\n"
	"46:	cmp	x7, x2\n"
	"	csel	x8, x7, x2, hs\n"
	"	b	6f\n"
	"47:	cmp	x7, x2\n"
	"	csel	x8, x7, x2, ls\n"
	"6:	cbz	w5, 8f\n"
	"63:	stlxr	w9, x8, [x1]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxr	w9, x8, [x1]\n"
	"9:	cbnz	w9, 20f\n"
	"	cbz	w6, 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	w10, #1\n"
	"	b	99f\n"
	"20:	sub	w11, w11, #1\n"
	"	cbnz	w11, 1b\n"
	"	clrex\n"
	"	mov	w10, #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w10, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	"	str	x7, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w10, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_rmw_64_body);

/*
 * CAS scalar, all widths; also used for CASP with sz=0 where the pair is
 * emulated as one 64-bit exclusive transaction on the 8-byte aligned pair
 * (design §3.3 CASP_32: CAS_scalar_64 on concat(E1,E0)/concat(D1,D0)).
 * A compare failure still writes the old value back through the exclusive
 * store: the write permission check and the store event must not be skipped
 * (design §2.2/§3.4).
 *
 * 8/16/32-bit: x1 addr, w2 af, w3 rf, w4 al, w5 exp, w6 des, w7 old,
 * w8 val, w9 st, w10 status, w11 cnt.
 */
asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_cas_8_body\n"
	"lse_emu_cas_8_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	ldr	w2, [x0, #" __stringify(LSE_REQ_OFF_A) "]\n"
	"	ldr	w3, [x0, #" __stringify(LSE_REQ_OFF_R) "]\n"
	"	ldr	w4, [x0, #" __stringify(LSE_REQ_OFF_AL) "]\n"
	"	ldr	w5, [x0, #" __stringify(LSE_REQ_OFF_EXP) "]\n"
	"	ldr	w6, [x0, #" __stringify(LSE_REQ_OFF_DES) "]\n"
	"	clrex\n"
	"	mov	w11, #16\n"
	"1:	cbz	w2, 2f\n"
	"61:	ldaxrb	w7, [x1]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxrb	w7, [x1]\n"
	"4:	cmp	w7, w5\n"
	"	csel	w8, w6, w7, eq\n"
	"6:	cbz	w3, 8f\n"
	"63:	stlxrb	w9, w8, [x1]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxrb	w9, w8, [x1]\n"
	"9:	cbnz	w9, 20f\n"
	"	cbz	w4, 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	w10, #1\n"
	"	b	99f\n"
	"20:	sub	w11, w11, #1\n"
	"	cbnz	w11, 1b\n"
	"	clrex\n"
	"	mov	w10, #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w10, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	"	str	w7, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w10, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_cas_8_body);

asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_cas_16_body\n"
	"lse_emu_cas_16_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	ldr	w2, [x0, #" __stringify(LSE_REQ_OFF_A) "]\n"
	"	ldr	w3, [x0, #" __stringify(LSE_REQ_OFF_R) "]\n"
	"	ldr	w4, [x0, #" __stringify(LSE_REQ_OFF_AL) "]\n"
	"	ldr	w5, [x0, #" __stringify(LSE_REQ_OFF_EXP) "]\n"
	"	ldr	w6, [x0, #" __stringify(LSE_REQ_OFF_DES) "]\n"
	"	clrex\n"
	"	mov	w11, #16\n"
	"1:	cbz	w2, 2f\n"
	"61:	ldaxrh	w7, [x1]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxrh	w7, [x1]\n"
	"4:	cmp	w7, w5\n"
	"	csel	w8, w6, w7, eq\n"
	"6:	cbz	w3, 8f\n"
	"63:	stlxrh	w9, w8, [x1]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxrh	w9, w8, [x1]\n"
	"9:	cbnz	w9, 20f\n"
	"	cbz	w4, 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	w10, #1\n"
	"	b	99f\n"
	"20:	sub	w11, w11, #1\n"
	"	cbnz	w11, 1b\n"
	"	clrex\n"
	"	mov	w10, #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w10, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	"	str	w7, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w10, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_cas_16_body);

asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_cas_32_body\n"
	"lse_emu_cas_32_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	ldr	w2, [x0, #" __stringify(LSE_REQ_OFF_A) "]\n"
	"	ldr	w3, [x0, #" __stringify(LSE_REQ_OFF_R) "]\n"
	"	ldr	w4, [x0, #" __stringify(LSE_REQ_OFF_AL) "]\n"
	"	ldr	w5, [x0, #" __stringify(LSE_REQ_OFF_EXP) "]\n"
	"	ldr	w6, [x0, #" __stringify(LSE_REQ_OFF_DES) "]\n"
	"	clrex\n"
	"	mov	w11, #16\n"
	"1:	cbz	w2, 2f\n"
	"61:	ldaxr	w7, [x1]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxr	w7, [x1]\n"
	"4:	cmp	w7, w5\n"
	"	csel	w8, w6, w7, eq\n"
	"6:	cbz	w3, 8f\n"
	"63:	stlxr	w9, w8, [x1]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxr	w9, w8, [x1]\n"
	"9:	cbnz	w9, 20f\n"
	"	cbz	w4, 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	w10, #1\n"
	"	b	99f\n"
	"20:	sub	w11, w11, #1\n"
	"	cbnz	w11, 1b\n"
	"	clrex\n"
	"	mov	w10, #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w10, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	"	str	w7, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w10, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_cas_32_body);

/*
 * CAS 64-bit / CASP 2x32 (pair emulated as one 64-bit transaction).
 * x1 addr, w2 af, w3 rf, w4 al, x5 exp, x6 des, x7 old, x8 val,
 * w9 st, w10 status, w11 cnt.
 */
asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_cas_64_body\n"
	"lse_emu_cas_64_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	ldr	w2, [x0, #" __stringify(LSE_REQ_OFF_A) "]\n"
	"	ldr	w3, [x0, #" __stringify(LSE_REQ_OFF_R) "]\n"
	"	ldr	w4, [x0, #" __stringify(LSE_REQ_OFF_AL) "]\n"
	"	ldr	x5, [x0, #" __stringify(LSE_REQ_OFF_EXP) "]\n"
	"	ldr	x6, [x0, #" __stringify(LSE_REQ_OFF_DES) "]\n"
	"	clrex\n"
	"	mov	w11, #16\n"
	"1:	cbz	w2, 2f\n"
	"61:	ldaxr	x7, [x1]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxr	x7, [x1]\n"
	"4:	cmp	x7, x5\n"
	"	csel	x8, x6, x7, eq\n"
	"6:	cbz	w3, 8f\n"
	"63:	stlxr	w9, x8, [x1]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxr	w9, x8, [x1]\n"
	"9:	cbnz	w9, 20f\n"
	"	cbz	w4, 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	w10, #1\n"
	"	b	99f\n"
	"20:	sub	w11, w11, #1\n"
	"	cbnz	w11, 1b\n"
	"	clrex\n"
	"	mov	w10, #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w10, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	"	str	x7, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w10, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_cas_64_body);

/*
 * CASP with sz=1: 2x64, 16-byte aligned, 128-bit footprint.  v8.0 LDXP is
 * not a single-copy atomic load, so a mismatch is answered by a same-value
 * STXP whose success validates the whole 128-bit reservation before the
 * old pair is reported (design §3.4: the validation may not be skipped).
 *
 * x1 addr, w2 af, w3 rf, w4 al, x5 exp0 (then mismatch flag t1),
 * x6 exp1 (then mismatch flag t2), x7 des0, x8 des1, x9 old0, x10 old1,
 * x11 val0, x12 val1, w13 st, w14 status, w15 cnt.  exp0/exp1 are dead
 * after their compares, so they double as the mismatch flags.
 */
asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_casp_64_body\n"
	"lse_emu_casp_64_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	ldr	w2, [x0, #" __stringify(LSE_REQ_OFF_A) "]\n"
	"	ldr	w3, [x0, #" __stringify(LSE_REQ_OFF_R) "]\n"
	"	ldr	w4, [x0, #" __stringify(LSE_REQ_OFF_AL) "]\n"
	"	ldr	x5, [x0, #" __stringify(LSE_REQ_OFF_EXP) "]\n"
	"	ldr	x6, [x0, #" __stringify(LSE_REQ_OFF_EXP1) "]\n"
	"	ldr	x7, [x0, #" __stringify(LSE_REQ_OFF_DES) "]\n"
	"	ldr	x8, [x0, #" __stringify(LSE_REQ_OFF_DES1) "]\n"
	"	clrex\n"
	"	mov	w15, #16\n"
	"1:	cbz	w2, 2f\n"
	"61:	ldaxp	x9, x10, [x1]\n"
	"	b	4f\n"
	"2:\n"
	"62:	ldxp	x9, x10, [x1]\n"
	"4:	cmp	x9, x5\n"
	"	cset	x5, ne\n"
	"	cmp	x10, x6\n"
	"	cset	x6, ne\n"
	"	orr	x5, x5, x6\n"
	"	cmp	x5, xzr\n"
	"	csel	x11, x7, x9, eq\n"
	"	csel	x12, x8, x10, eq\n"
	"6:	cbz	w3, 8f\n"
	"63:	stlxp	w13, x11, x12, [x1]\n"
	"	b	9f\n"
	"8:\n"
	"64:	stxp	w13, x11, x12, [x1]\n"
	"9:	cbnz	w13, 20f\n"
	"	cbz	w4, 21f\n"
	"	dmb	ish\n"
	"21:	clrex\n"
	"	mov	w14, #1\n"
	"	b	99f\n"
	"20:	sub	w15, w15, #1\n"
	"	cbnz	w15, 1b\n"
	"	clrex\n"
	"	mov	w14, #2\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w14, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.long	62b - ., 65b - .\n"
	"	.long	63b - ., 65b - .\n"
	"	.long	64b - ., 65b - .\n"
	"	.popsection\n"
	"	str	x9, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	x10, [x0, #" __stringify(LSE_REQ_OFF_OLD1) "]\n"
	"	str	w14, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_casp_64_body);

/*
 * LDAPR -> LDAR of the same width (RCpc acquire strengthening, design
 * §3.2).  Single load, no retry loop, no write of any kind.
 * 8/16/32-bit: x1 addr, w2 old, w3 status.
 */
asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_ldapr_8_body\n"
	"lse_emu_ldapr_8_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	clrex\n"
	"61:	ldarb	w2, [x1]\n"
	"	mov	w3, #1\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w3, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.popsection\n"
	"	str	w2, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w3, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_ldapr_8_body);

asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_ldapr_16_body\n"
	"lse_emu_ldapr_16_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	clrex\n"
	"61:	ldarh	w2, [x1]\n"
	"	mov	w3, #1\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w3, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.popsection\n"
	"	str	w2, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w3, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_ldapr_16_body);

asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_ldapr_32_body\n"
	"lse_emu_ldapr_32_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	clrex\n"
	"61:	ldar	w2, [x1]\n"
	"	mov	w3, #1\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w3, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.popsection\n"
	"	str	w2, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w3, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_ldapr_32_body);

/* LDAPR 64-bit: x1 addr, x2 old, w3 status. */
asm(".pushsection .text.lse_emu, \"ax\"\n"
	".align	2\n"
	".globl	lse_emu_ldapr_64_body\n"
	"lse_emu_ldapr_64_body:\n"
	"	ldr	x1, [x0, #" __stringify(LSE_REQ_OFF_ADDR) "]\n"
	"	clrex\n"
	"61:	ldar	x2, [x1]\n"
	"	mov	w3, #1\n"
	"	b	99f\n"
	"65:	clrex\n"
	"	mov	w3, #3\n"
	"	b	99f\n"
	"99:\n"
	"	.pushsection __ex_table, \"a\"\n"
	"	.align	3\n"
	"	.long	61b - ., 65b - .\n"
	"	.popsection\n"
	"	str	x2, [x0, #" __stringify(LSE_REQ_OFF_OLD) "]\n"
	"	str	w3, [x0, #" __stringify(LSE_REQ_OFF_STATUS) "]\n"
	"	ret\n"
	".popsection\n"
	);
NOKPROBE_SYMBOL(lse_emu_ldapr_64_body);

/* Run one bounded attempt batch with the helper selected by the decode. */
static notrace void lse_emu_attempt(struct lse_emu_req *q,
				    const struct lse_emu_desc *d)
{
	switch (d->fam) {
	case LSE_FAM_RMW:
		switch (d->size) {
		case 0: lse_emu_rmw_8_body(q);  return;
		case 1: lse_emu_rmw_16_body(q); return;
		case 2: lse_emu_rmw_32_body(q); return;
		default: lse_emu_rmw_64_body(q); return;
		}
	case LSE_FAM_CAS:
		switch (d->size) {
		case 0: lse_emu_cas_8_body(q);  return;
		case 1: lse_emu_cas_16_body(q); return;
		case 2: lse_emu_cas_32_body(q); return;
		default: lse_emu_cas_64_body(q); return;
		}
	case LSE_FAM_CASP:
		if (d->size == 0)
			lse_emu_cas_64_body(q);	/* pair as one 64-bit op */
		else
			lse_emu_casp_64_body(q);
		return;
	default:
		switch (d->size) {
		case 0: lse_emu_ldapr_8_body(q);  return;
		case 1: lse_emu_ldapr_16_body(q); return;
		case 2: lse_emu_ldapr_32_body(q); return;
		default: lse_emu_ldapr_64_body(q); return;
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
	return (unsigned long)__lse_emu_start <= pc &&
	       pc < (unsigned long)__lse_emu_end;
}

/*
 * Narrow fault bridge (design §4.2): called from do_mem_abort() for
 * kernel-mode data aborts.  Only when the emulation context is active and
 * the inner PC sits on one of the helper's exact extable sites do we
 * capture the full syndrome (FSC plus EA/FnV and every other ISS field of
 * the inner abort -- the handler masks it down to the architecturally
 * meaningful fields on reassembly) and redirect to the attempt fixup;
 * every other exception keeps the original path.
 */
int lse_emu_mem_abort_hook(unsigned long addr, unsigned int esr,
			   struct pt_regs *regs)
{
	struct lse_emu_ctx *ctx = lse_emu_this_ctx();

	if (!READ_ONCE(ctx->active) || !lse_emu_pc_in_helpers(regs->pc) ||
	    !search_exception_tables(regs->pc))
		return 0;

	WRITE_ONCE(ctx->addr, addr);
	WRITE_ONCE(ctx->esr, esr);
	WRITE_ONCE(ctx->ev, LSE_EMU_EV_FAULT);
	/*
	 * Consume the event only when the fixup really redirects this PC;
	 * otherwise the abort keeps the original path (P1-c: never swallow
	 * an event the bridge cannot handle).
	 */
	if (!fixup_exception(regs)) {
		WRITE_ONCE(ctx->addr, 0);
		WRITE_ONCE(ctx->esr, 0);
		WRITE_ONCE(ctx->ev, LSE_EMU_EV_NONE);
		return 0;
	}
	return 1;
}
NOKPROBE_SYMBOL(lse_emu_mem_abort_hook);

#ifdef CONFIG_HAVE_HW_BREAKPOINT
/*
 * True when the fired data address falls inside one of the current
 * task's EL0-privilege hardware watchpoints (same byte-range match as
 * watchpoint_handler's get_distance_from_watchpoint()).  This both
 * proves the task owns EL0 watchpoints and attributes the event to one
 * of them: a hit of an EL1-privilege (kernel) watchpoint -- e.g. a task
 * holding an EL0 and an EL1 watchpoint when the helper's inner access
 * runs -- does not match here and keeps the original debug path instead
 * of being swallowed by the bridge (P1-c).
 */
static bool lse_emu_el0_wp_covers(unsigned long addr)
{
	int i;

	addr = untagged_addr(addr);

	for (i = 0; i < ARM_MAX_WRP; i++) {
		struct perf_event *wp = current->thread.debug.hbp_watch[i];
		struct arch_hw_breakpoint *info;
		u64 low, high;

		if (!wp)
			continue;
		info = counter_arch_bp(wp);
		if (info->ctrl.privilege != AARCH64_BREAKPOINT_EL0 ||
		    !info->ctrl.enabled)
			continue;
		low  = info->address + __ffs(info->ctrl.len);
		high = info->address + __fls(info->ctrl.len);
		if (addr >= low && addr <= high)
			return true;
	}
	return false;
}
#endif

/*
 * Narrow debug bridge (design §6): called from do_debug_exception() for
 * kernel-mode debug exceptions.  A data watchpoint can match the inner
 * EL1 access performed on behalf of the emulated instruction (the same
 * "uaccess routine hits a user watchpoint" case watchpoint_report()
 * already knows about).
 *
 * Cancel = trap (design simplification, round-2 review): per ARM DDI
 * 0487A D2.10.8 the preferred return address of a watchpoint exception is
 * the address of the instruction that generated it and the memory
 * location is Unchanged -- for an exclusive store the store has NOT taken
 * place.  There is nothing to salvage and no committed side, so the
 * attempt is cancelled: the bridge verifies the exact extable site and
 * redirects the helper to the per-block fixup (65:), which issues CLREX
 * -- abandoning the exclusive monitor -- and sets status=FAULT with no
 * register or memory side effect, i.e. the helper state is rolled back
 * completely to before the un-executed instruction.  The handler then
 * reports the event through the standard user debug path
 * (SIGTRAP/TRAP_HWBKPT with the data address) leaving the user PC
 * untouched, so the emulated instruction is re-executed.
 *
 * Trade-off: a watchpoint placed on LSE-hot code produces an event
 * (SIGTRAP) on every re-execution that hits it -- the same stream a
 * native LDXR/STXR sequence produces under a watchpoint -- instead of the
 * previous suppress-and-re-execute-once scheme.  The suppression
 * machinery (wps_disabled bookkeeping plus the restore call on every one
 * of the eight emulation exits) is gone: there is no window in which user
 * watchpoints are disabled, no lifecycle to get wrong, and no way for a
 * cancelled commit to be mistaken for a completed one.  Zero memory risk;
 * correctness first.
 *
 * The bridge consumes the event only when every gate matches (P1-c:
 * never swallow a foreign event):
 *  - the emulation context is active and the inner PC lies inside the
 *    .text.lse_emu section (the inner access is an EL1 access performed
 *    on behalf of the user task only while that window is open);
 *  - the exception is a data watchpoint (EC == WATCHPT_CUR);
 *  - the fired address falls inside one of the current task's
 *    EL0-privilege watchpoints (lse_emu_el0_wp_covers) -- events of
 *    tasks without EL0 watchpoints and hits of EL1-privilege watchpoints
 *    keep the original debug path;
 *  - the inner PC is an exact __ex_table site of the helpers and
 *    fixup_exception() really redirects it.
 * On any gate failure the exception keeps the original path with the
 * context untouched.
 */
int lse_emu_debug_hook(unsigned long addr, unsigned int esr,
		       struct pt_regs *regs)
{
	struct lse_emu_ctx *ctx = lse_emu_this_ctx();

	if (!READ_ONCE(ctx->active) || !lse_emu_pc_in_helpers(regs->pc))
		return 0;
	if (ESR_ELx_EC(esr) != ESR_ELx_EC_WATCHPT_CUR)
		return 0;
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	if (!lse_emu_el0_wp_covers(addr))
		return 0;
	if (!search_exception_tables(regs->pc))
		return 0;

	/*
	 * Redirect the helper to the attempt fixup first: the fixup lands
	 * on the 65: site which performs no user memory access (CLREX and
	 * status only), so nothing can re-trigger before the event is
	 * recorded.  On failure the exception keeps the original debug
	 * path.
	 */
	if (!fixup_exception(regs))
		return 0;

	WRITE_ONCE(ctx->addr, addr);
	WRITE_ONCE(ctx->esr, esr);
	WRITE_ONCE(ctx->ev, LSE_EMU_EV_DEBUG);
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
	 * Read side (LDAPR, or the load half of RMW/CAS/CASP): allow
	 * VM_READ or VM_EXEC.  That is the same set this tree's
	 * do_page_fault() admits for an EL0 data read fault
	 * (vm_flags = VM_READ | VM_WRITE | VM_EXEC is its default for a
	 * read abort): an exec-only user mapping gets a user-readable PTE
	 * here, and a native LDAR/LDAXR on such a page would read it
	 * fine, so the emulated load must be allowed to do the same.
	 * Write side: require VM_WRITE, matching the WnR=1 fault the
	 * inner exclusive store would take.  A compare failure or a ZR
	 * source does not waive the permission requirements.
	 */
	if (write) {
		if (!(vma->vm_flags & VM_WRITE)) {
			*sig = SIGSEGV;
			*code = SEGV_ACCERR;
			return false;
		}
	} else if (!(vma->vm_flags & (VM_READ | VM_EXEC))) {
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
		/*
		 * P0-1: the helper bodies are opaque callee-saved-respecting
		 * calls now, and the context fields are volatile (WRITE_ONCE/
		 * READ_ONCE), so none of these stores may be reordered into
		 * or past the LL/SC region where a faulting inner access
		 * would otherwise observe a torn or stale context; the
		 * READ_ONCE/WRITE_ONCE pair keeps the cross-function
		 * contract explicit for the bridges.
		 */
		WRITE_ONCE(ctx->active, 1);
		WRITE_ONCE(ctx->ev, LSE_EMU_EV_NONE);
		WRITE_ONCE(ctx->esr, 0);
		WRITE_ONCE(ctx->addr, 0);

		lse_emu_attempt(&q, &d);

		/* Copy the bridge state out before leaving the window. */
		ev = READ_ONCE(ctx->ev);
		iesr = READ_ONCE(ctx->esr);
		iaddr = READ_ONCE(ctx->addr);
		WRITE_ONCE(ctx->active, 0);
		WRITE_ONCE(ctx->ev, LSE_EMU_EV_NONE);
		/* Clear the scratch fields so no inner-event data can leak. */
		WRITE_ONCE(ctx->esr, 0);
		WRITE_ONCE(ctx->addr, 0);

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

			/*
			 * A debug event always cancels the attempt via the
			 * extable fixup before anything is committed (see
			 * lse_emu_debug_hook), so a verified commit belongs
			 * to an execution no watchpoint fired on: advance PC
			 * normally.  There is no watchpoint state to restore
			 * -- the suppress/restore scheme is gone (F2).
			 */
			arm64_skip_faulting_instruction(regs, 4);
			return 0;
		}

		if (result == LSE_EMU_FAULT && ev == LSE_EMU_EV_DEBUG) {
			/*
			 * Load- or store-side watchpoint hit: per ARM DDI
			 * 0487A D2.10.8 the matched instruction has not
			 * executed and the memory location is unchanged.
			 * Report the event with the data address and the
			 * user PC untouched: the instruction is re-executed
			 * on return, and every re-execution that hits the
			 * watchpoint again reports again -- exactly what a
			 * native LL/SC sequence does under a watchpoint
			 * (F2: cancel = trap; no suppression, no
			 * exactly-once re-execution bookkeeping).
			 */
			lse_emu_force_sig(SIGTRAP, TRAP_HWBKPT, iaddr, regs);
			return 0;
		}

		if (result == LSE_EMU_FAULT) {
			/*
			 * Forward as the original EL0 user abort: EC=DABT_LOW,
			 * IL=1, ISV=0 (design §4.2).  WnR reflects the logical
			 * access so COW is resolved for RMW/CAS/CASP.
			 *
			 * F3: preserve EA and FnV from the inner ISS -- they
			 * qualify external-abort reporting and si_addr
			 * validity.  Every other ISS field (ISV, SAS, SRT,
			 * SF, AR, CM, SET, ...) describes the helper's own
			 * inner access, is scratch, and is masked off so no
			 * helper state can leak into the user-visible abort.
			 * FnV=1 means the FAR is invalid: pass 0 so the
			 * forwarding matches this tree's do_sea() semantics
			 * (si_addr = NULL when ESR_ELx_FnV is set).
			 */
			u32 esr = ((u32)ESR_ELx_EC_DABT_LOW << ESR_ELx_EC_SHIFT) |
				  (u32)ESR_ELx_IL;
			unsigned long faddr = iaddr;

			esr |= iesr & (ESR_ELx_FSC | ESR_ELx_EA | ESR_ELx_FnV);
			if (write)
				esr |= ESR_ELx_WNR;
			if (iesr & ESR_ELx_FnV)
				faddr = 0;
			do_mem_abort(faddr, esr, regs);

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

/*
 * Init-time layout validation: the LL/SC helper bodies must be the only
 * code inside the dedicated .text.lse_emu section.
 *
 * Checks (against the section boundary symbols exported by vmlinux.lds.S):
 *  - __lse_emu_start/__lse_emu_end are non-zero and start < end;
 *  - each of the 13 helper entry symbols lies inside the section and the
 *    entries are pairwise distinct (exactly 13 helper entries);
 *  - every __ex_table entry whose faulting site lies in the section also
 *    points to a fixup inside the section, and the site/fixup census is
 *    exactly 40 sites (4 per RMW/CAS/CASP body: 61/62/63/64, 1 per LDAPR
 *    body: 61) mapped to 13 distinct per-body fixup sites (65:).
 */
static bool __init lse_emu_layout_ok(void)
{
	static void (*const helpers[])(struct lse_emu_req *) = {
		lse_emu_rmw_8_body, lse_emu_rmw_16_body,
		lse_emu_rmw_32_body, lse_emu_rmw_64_body,
		lse_emu_cas_8_body, lse_emu_cas_16_body,
		lse_emu_cas_32_body, lse_emu_cas_64_body,
		lse_emu_casp_64_body,
		lse_emu_ldapr_8_body, lse_emu_ldapr_16_body,
		lse_emu_ldapr_32_body, lse_emu_ldapr_64_body,
	};
	extern struct exception_table_entry __start___ex_table[];
	extern struct exception_table_entry __stop___ex_table[];
	unsigned long start = (unsigned long)__lse_emu_start;
	unsigned long end = (unsigned long)__lse_emu_end;
	unsigned long fixes[ARRAY_SIZE(helpers)];
	struct exception_table_entry *e;
	int i, j, nfix = 0, nsite = 0;

	if (start == 0 || end == 0 || start >= end)
		return false;

	for (i = 0; i < ARRAY_SIZE(helpers); i++) {
		unsigned long pc = (unsigned long)helpers[i];

		if (pc < start || pc >= end)
			return false;
		for (j = 0; j < i; j++)
			if (pc == (unsigned long)helpers[j])
				return false;
	}

	for (e = __start___ex_table; e < __stop___ex_table; e++) {
		/* ARCH_HAS_RELATIVE_EXTABLE: fields are section-relative. */
		unsigned long site = (unsigned long)&e->insn + e->insn;
		unsigned long fix = (unsigned long)&e->fixup + e->fixup;

		if (site < start || site >= end)
			continue;
		nsite++;
		if (fix < start || fix >= end)
			return false;
		for (j = 0; j < nfix; j++)
			if (fixes[j] == fix)
				break;
		if (j == nfix) {
			if (nfix == ARRAY_SIZE(fixes))
				return false;	/* 14th distinct fixup */
			fixes[nfix++] = fix;
		}
	}

	return nsite == 40 && nfix == ARRAY_SIZE(helpers);
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
	/*
	 * The helper bodies address struct lse_emu_req fields by the
	 * hardcoded LSE_REQ_OFF_* offsets; pin them against the C layout
	 * at build time (the offsets are stringified into the asm).
	 */
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, addr) !=
		     LSE_REQ_OFF_ADDR);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, src) !=
		     LSE_REQ_OFF_SRC);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, exp) !=
		     LSE_REQ_OFF_EXP);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, exp1) !=
		     LSE_REQ_OFF_EXP1);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, des) !=
		     LSE_REQ_OFF_DES);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, des1) !=
		     LSE_REQ_OFF_DES1);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, old) !=
		     LSE_REQ_OFF_OLD);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, old1) !=
		     LSE_REQ_OFF_OLD1);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, status) !=
		     LSE_REQ_OFF_STATUS);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, op) !=
		     LSE_REQ_OFF_OP);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, a) !=
		     LSE_REQ_OFF_A);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, r) !=
		     LSE_REQ_OFF_R);
	BUILD_BUG_ON(__builtin_offsetof(struct lse_emu_req, al) !=
		     LSE_REQ_OFF_AL);

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
