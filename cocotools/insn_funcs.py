"""
cocotools/insn_funcs.py — Instruction parse/resolve/emit functions
Faithful Python translation of:
    lwasm/insn_inh.c    - inherent addressing
    lwasm/insn_gen.c    - general addressing (imm/dir/idx/ext)
    lwasm/insn_rel.c    - relative branch
    lwasm/insn_rtor.c   - register-to-register (TFR, EXG)
    lwasm/insn_rlist.c  - register list (PSHS/PULS)
    lwasm/insn_indexed.c - indexed addressing (partial)
(William Astle, LWTools, GPL v3)

Parse functions:  (as_, cl, operand:str) -> str (remaining operand)
Resolve functions:(as_, cl, force:int)   -> None
Emit functions:   (as_, cl)              -> None

C ops[] array layout for instructions:
    ops[0] = DIR  (direct page)
    ops[1] = IDX  (indexed)
    ops[2] = EXT  (extended)
    ops[3] = IMM  (immediate)
    For inh: ops[0] = opcode, rest = -1
    For relgen: ops[0]=base, ops[1]=natural_size, ops[2]=short, ops[3]=long
"""

from .lw_expr    import Expr, Ptr, TYPE_INT, OPER_PLUS, OPER_MINUS
from .lwasm_types import (
    PRAGMA_NEWSOURCE, PRAGMA_6809, PRAGMA_AUTOBRANCHLENGTH,
    PRAGMA_FORWARDREFMAX, PRAGMA_OPERANDSIZE, PRAGMA_QRTS, PRAGMA_M80EXT,
    PRAGMA_PCASPCR, PRAGMA_NOINDEX0TONONE,
    E_OPERAND_BAD, E_IMMEDIATE_INVALID, E_BYTE_OVERFLOW,
    E_EXPRESSION_NOT_RESOLVED, E_EXPRESSION_NOT_CONST, E_REGISTER_BAD,
    E_BITNUMBER_UNRESOLVED, E_BITNUMBER_INVALID, E_IMMEDIATE_UNRESOLVED,
    E_UNKNOWN_OPERATION, E_ILL5, E_NW_8,
    W_OPERAND_SIZE,
    lwasm_expr_linelen, lwasm_expr_lineaddr,
)
from .lwasm_core import curpragma, AsmState


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _skip_operand(cl, p):
    if curpragma(cl, PRAGMA_NEWSOURCE): return
    while p.peek() and not p.peek().isspace():
        p.advance()

def _oplen(opc):
    """OPLEN(op): 2 if two-byte opcode (>0xFF), else 1."""
    return 2 if opc > 0xFF else 1

def _ops(cl):
    """Return the ops list for the current instruction."""
    from .instab import INSTAB
    return INSTAB[cl.insn].ops

# ─────────────────────────────────────────────────────────────────────────────
# Inherent addressing  (insn_inh.c)
# ─────────────────────────────────────────────────────────────────────────────

def insn_parse_inh(as_, cl, operand):
    """insn_parse_inh: single opcode, no operand."""
    p = Ptr(operand)
    cl.len = _oplen(_ops(cl)[0])
    _skip_operand(cl, p)
    return p.remaining()

def insn_resolve_inh(as_, cl, force):
    pass

def insn_emit_inh(as_, cl):
    cl.emitop(_ops(cl)[0])


# 6800 compatibility inherent (may have two opcodes)
def insn_parse_inh6800(as_, cl, operand):
    p = Ptr(operand)
    ops = _ops(cl)
    cl.len = _oplen(ops[0])
    if ops[1] >= 0: cl.len += _oplen(ops[1])
    _skip_operand(cl, p)
    return p.remaining()

def insn_resolve_inh6800(as_, cl, force):
    pass

def insn_emit_inh6800(as_, cl):
    ops = _ops(cl)
    cl.emitop(ops[0])
    if ops[1] >= 0: cl.emitop(ops[1])
    cl.cycle_base = ops[3]


# ─────────────────────────────────────────────────────────────────────────────
# Immediate-only (ANDCC, ORCC, CWAI, etc.)  (insn_gen.c insn_parse_imm8)
# ─────────────────────────────────────────────────────────────────────────────

def insn_parse_imm8(as_, cl, operand):
    """insn_parse_imm8: '#' required."""
    p = Ptr(operand)
    if p.peek() == '#':
        p.advance()
        as_.exprwidth = 8
        e = as_.parse_expr(p)
        as_.exprwidth = 16
        if not e:
            as_.register_error(cl, E_OPERAND_BAD)
            return p.remaining()
        cl.len = _oplen(_ops(cl)[0]) + 1
        cl.save_expr(0, e)
    else:
        as_.register_error(cl, E_OPERAND_BAD)
    return p.remaining()

def insn_resolve_imm8(as_, cl, force):
    pass

def insn_emit_imm8(as_, cl):
    ops = _ops(cl)
    cl.emitop(ops[0])
    e = cl.fetch_expr(0)
    if e and e.istype(TYPE_INT):
        v = e.intval()
        if v < -128 or v > 255:
            cl.as_.register_error(cl, E_BYTE_OVERFLOW)
    cl.emitexpr(e, 1)


# ANDCC: invert mask flag bits
def insn_parse_andcc(as_, cl, operand):
    p = Ptr(operand)
    if p.peek() == '#':
        return insn_parse_imm8(as_, cl, operand)
    # flag-name syntax (e.g.  ANDCC C,V)
    rv = _parse_flags_string(as_, cl, p) ^ 0xFF
    e  = Expr.int(rv)
    cl.len = _oplen(_ops(cl)[0]) + 1
    cl.save_expr(0, e)
    return p.remaining()

def insn_parse_orcc(as_, cl, operand):
    p = Ptr(operand)
    if p.peek() == '#':
        return insn_parse_imm8(as_, cl, operand)
    rv = _parse_flags_string(as_, cl, p)
    e  = Expr.int(rv)
    cl.len = _oplen(_ops(cl)[0]) + 1
    cl.save_expr(0, e)
    return p.remaining()

def _parse_flags_string(as_, cl, p):
    FLAGS = 'CVZNIHFE'
    rv = 0
    while p.peek() and p.peek().upper() in FLAGS:
        rv |= 1 << FLAGS.index(p.peek().upper())
        p.advance()
        if p.peek() == ',': p.advance()
    if rv == 0:
        as_.register_error(cl, E_OPERAND_BAD)
    return rv


# ─────────────────────────────────────────────────────────────────────────────
# General addressing mode core  (insn_gen.c insn_parse_gen_aux)
# ─────────────────────────────────────────────────────────────────────────────
# lint2 values:
#   -1 = unknown (may be DIR or EXT)
#    0 = DIR
#    1 = IDX
#    2 = EXT
#    3 = IMM

def _insn_parse_gen_aux(as_, cl, p, elen=0):
    """
    insn_parse_gen_aux(as, cl, p, elen):
    Parse the operand for a general-mode instruction.
    Sets cl.lint2 to 0(DIR),1(IDX),2(EXT),3(IMM) or -1(unknown).
    """
    ops = _ops(cl)

    if not p.peek():
        as_.register_error(cl, E_OPERAND_BAD); return

    # ',' or '[' → definitely indexed
    if p.peek() in (',', '['):
        cl.lint  = -1
        cl.lint2 = 1
        insn_parse_indexed_aux(as_, cl, p)
        cl.minlen = _oplen(ops[1]) + 1 + elen
        cl.maxlen = _oplen(ops[1]) + 3 + elen
        _set_len_from_lint2(cl, ops, elen)
        return

    # Force size prefix
    optr2 = p.pos
    force_size = -1  # -1=auto, 0=direct, 2=extended
    if p.peek() == '<':
        p.advance()
        force_size = 0
        # '<' + '<' → indexed (PC-relative or similar)
        if p.peek() == '<':
            p.pos = optr2
            cl.lint  = -1
            cl.lint2 = 1
            insn_parse_indexed_aux(as_, cl, p)
            cl.minlen = _oplen(ops[1]) + 1 + elen
            cl.maxlen = _oplen(ops[1]) + 3 + elen
            return
    elif p.peek() == '>':
        p.advance()
        force_size = 2
    elif p.peek() == '*':
        nxt = p.s[p.pos+1] if p.pos+1 < len(p.s) else ''
        if nxt.isdigit() or nxt.isalpha() or nxt in '_@.?*+-':
            force_size = 0
            p.advance()
    else:
        force_size = -1

    cl.lint2 = force_size

    # Parse the expression
    s = as_.parse_expr(p)

    # If followed by comma, it's indexed
    if p.peek() == ',':
        p.pos = optr2
        cl.lint  = -1
        cl.lint2 = 1
        insn_parse_indexed_aux(as_, cl, p)
        cl.minlen = _oplen(ops[1]) + 1 + elen
        cl.maxlen = _oplen(ops[1]) + 3 + elen
        _set_len_from_lint2(cl, ops, elen)
        return

    if not s:
        as_.register_error(cl, E_OPERAND_BAD); return

    cl.save_expr(0, s)
    cl.minlen = _oplen(ops[3 if ops[3] >= 0 else 0]) + 1 + elen
    cl.maxlen = _oplen(ops[2]) + 2 + elen

    # Auto-determine DIR vs EXT for unresolved
    if cl.lint2 == -1:
        if s.istype(TYPE_INT):
            v = s.intval()
            if ((v >> 8) & 0xFF) == (cl.dpval & 0xFF):
                cl.lint2 = 0
            else:
                cl.lint2 = 2
        else:
            # Try range calculation
            cl.lint2 = -1  # leave for resolve

    # Set len based on known lint2
    _set_len_from_lint2(cl, ops, elen)


def _set_len_from_lint2(cl, ops, elen=0):
    lint2 = cl.lint2
    lint  = cl.lint
    if lint2 == 0:
        cl.len = _oplen(ops[0]) + 1 + elen
    elif lint2 == 2:
        cl.len = _oplen(ops[2]) + 2 + elen
    elif lint2 == 1 and lint != -1:
        if lint == 3:
            cl.len = _oplen(ops[1]) + 1 + elen
        else:
            cl.len = _oplen(ops[1]) + lint + 1 + elen
    # lint2==-1: len stays -1


def _insn_resolve_gen_aux(as_, cl, force, elen=0):
    """
    insn_resolve_gen_aux: resolve DIR vs EXT for ambiguous gen-mode operand.

    C's insn_resolve_gen_aux funnels every path (indexed, DP/EXT decision,
    and the early-return branches) through a shared `out:` label that
    computes l->len from the now-known lint2/lint. Previously this Python
    version only computed cl.len via _set_len_from_lint2 for the DIR/EXT
    branch, returning immediately after the indexed branch instead. That
    was invisible while the ad hoc indexed-mode parser eagerly decided
    offset size at parse time (so cl.len was already set by then and this
    function's indexed branch was always a no-op). Now that
    insn_parse_indexed_aux faithfully defers undecided offset sizes to
    this resolve step, the missing out:-equivalent call must be added so
    cl.len actually gets set once the indexed offset is resolved.
    """
    ops = _ops(cl)
    if cl.lint2 == 1:
        _insn_resolve_indexed_aux(as_, cl, force, elen)
        _set_len_from_lint2(cl, ops, elen)
        return
    if cl.lint2 != -1: return

    e = cl.fetch_expr(0)
    as_.reduce_expr(e)
    if e.istype(TYPE_INT):
        v = e.intval()
        if ((v >> 8) & 0xFF) == (cl.dpval & 0xFF):
            cl.lint2 = 0
        else:
            cl.lint2 = 2
    elif force:
        cl.lint2 = 2

    _set_len_from_lint2(cl, ops, elen)


def _insn_emit_gen_aux(as_, cl, extra=-1):
    """insn_emit_gen_aux: emit opcode + operand bytes for gen mode."""
    ops  = _ops(cl)
    e    = cl.fetch_expr(0)

    if cl.lint2 >= 0 and cl.lint2 < len(ops):
        cl.emitop(ops[cl.lint2])
    else:
        cl.emitop(ops[0])  # fallback

    if extra != -1:
        cl.emit(extra)

    if cl.lint2 == 1:
        # indexed
        if cl.lint == 3:
            # 5-bit offset resolve
            if e and e.istype(TYPE_INT):
                offs = e.intval()
                if (offs >= -16 and offs <= 15) or offs >= 0xFFF0:
                    cl.pb = (cl.pb & 0xE0) | (offs & 0x1F)
                    cl.lint = 0
                else:
                    as_.register_error(cl, E_BYTE_OVERFLOW)
            else:
                as_.register_error(cl, E_EXPRESSION_NOT_RESOLVED)
        cl.emit(cl.pb)
        if cl.lint > 0:
            i = e.intval() if (e and e.istype(TYPE_INT)) else 0
            if cl.lint == 1 and (i < -128 or i > 127):
                as_.register_error(cl, E_BYTE_OVERFLOW)
            cl.emitexpr(e, cl.lint)
        return

    if cl.lint2 == 2:
        cl.emitexpr(e, 2)
    else:
        cl.emitexpr(e, 1)


# ─────────────────────────────────────────────────────────────────────────────
# gen8 — general 8-bit immediate  (LDA, STA, ADDA, etc.)
# ─────────────────────────────────────────────────────────────────────────────

def insn_parse_gen8(as_, cl, operand):
    p = Ptr(operand)
    cl.genmode = 8
    ops = _ops(cl)

    if p.peek() == '#':
        p.advance()
        as_.exprwidth = 8
        e = as_.parse_expr(p)
        as_.exprwidth = 16
        if not e:
            as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
        cl.len   = _oplen(ops[3]) + 1
        cl.lint2 = 3
        cl.save_expr(0, e)
        return p.remaining()

    _insn_parse_gen_aux(as_, cl, p, 0)
    return p.remaining()

def insn_resolve_gen8(as_, cl, force):
    if cl.len != -1: return
    _insn_resolve_gen_aux(as_, cl, force, 0)

def insn_emit_gen8(as_, cl):
    ops = _ops(cl)
    if cl.lint2 == 3:
        e = cl.fetch_expr(0)
        if e and e.istype(TYPE_INT):
            i = e.intval()
            if i < -128 or i > 255:
                cl.as_.register_error(cl, E_BYTE_OVERFLOW)
        cl.emitop(ops[3])
        cl.emitexpr(e, 1)
        return
    _insn_emit_gen_aux(as_, cl, -1)


# ─────────────────────────────────────────────────────────────────────────────
# gen16 — general 16-bit immediate  (LDX, STX, ADDD, etc.)
# ─────────────────────────────────────────────────────────────────────────────

def insn_parse_gen16(as_, cl, operand):
    p = Ptr(operand)
    cl.genmode = 16
    ops = _ops(cl)

    if p.peek() == '#':
        p.advance()
        e = as_.parse_expr(p)
        if not e:
            as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
        cl.len   = _oplen(ops[3]) + 2
        cl.lint2 = 3
        cl.save_expr(0, e)
        return p.remaining()

    _insn_parse_gen_aux(as_, cl, p, 0)
    return p.remaining()

def insn_resolve_gen16(as_, cl, force):
    if cl.len != -1: return
    _insn_resolve_gen_aux(as_, cl, force, 0)

def insn_emit_gen16(as_, cl):
    ops = _ops(cl)
    if cl.lint2 == 3:
        e = cl.fetch_expr(0)
        cl.emitop(ops[3])
        cl.emitexpr(e, 2)
        return
    _insn_emit_gen_aux(as_, cl, -1)


# ─────────────────────────────────────────────────────────────────────────────
# gen0 — no immediate mode  (STA, STX, CLR, etc.)
# ─────────────────────────────────────────────────────────────────────────────

def insn_parse_gen0(as_, cl, operand):
    p = Ptr(operand)
    if p.peek() == '#':
        as_.register_error(cl, E_IMMEDIATE_INVALID); return p.remaining()
    _insn_parse_gen_aux(as_, cl, p, 0)
    return p.remaining()

def insn_resolve_gen0(as_, cl, force):
    if cl.len != -1: return
    _insn_resolve_gen_aux(as_, cl, force, 0)

def insn_emit_gen0(as_, cl):
    _insn_emit_gen_aux(as_, cl, -1)


# ─────────────────────────────────────────────────────────────────────────────
# gen32 — 32-bit immediate (6309 LDQ etc.)
# ─────────────────────────────────────────────────────────────────────────────

def insn_parse_gen32(as_, cl, operand):
    p = Ptr(operand)
    cl.genmode = 32
    ops = _ops(cl)
    if p.peek() == '#':
        p.advance()
        e = as_.parse_expr(p)
        if not e:
            as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
        cl.len   = _oplen(ops[3]) + 4
        cl.lint2 = 3
        cl.save_expr(0, e)
        return p.remaining()
    _insn_parse_gen_aux(as_, cl, p, 0)
    return p.remaining()

def insn_resolve_gen32(as_, cl, force):
    if cl.len != -1: return
    _insn_resolve_gen_aux(as_, cl, force, 0)

def insn_emit_gen32(as_, cl):
    ops = _ops(cl)
    if cl.lint2 == 3:
        e = cl.fetch_expr(0)
        cl.emitop(ops[3])
        cl.emitexpr(e, 4)
        return
    _insn_emit_gen_aux(as_, cl, -1)


# ─────────────────────────────────────────────────────────────────────────────
# Indexed addressing mode  (insn_indexed.c — core modes)
# ─────────────────────────────────────────────────────────────────────────────
#
# Supported post-byte forms (covering CoCo 1/2 programs):
#   ,R          5-bit zero offset       pb = 0x84/A4/C4/E4
#   n,R         8-bit offset            pb = 0x88/A8/C8/E8  + 1 byte
#   n,R         16-bit offset           pb = 0x89/A9/C9/E9  + 2 bytes
#   ,R+         post-increment 1        pb = 0x80/A0/C0/E0
#   ,R++        post-increment 2        pb = 0x81/A1/C1/E1
#   ,-R         pre-decrement 1         pb = 0x82/A2/C2/E2
#   ,--R        pre-decrement 2         pb = 0x83/A3/C3/E3
#   A,R B,R D,R accumulator offset      pb = 0x86/A6/C6/E6 / 87/A7/C7/E7 / 8B/AB/CB/EB
#   n,PC / n,PCR PC-relative            pb = 0x8C(8-bit) / 0x8D(16-bit)
#   [,R]  [n,R]  indirect forms         pb |= 0x10  (for 16-bit offsets only for post-inc/dec)

_REGS9 = "X  Y  U  S     PCRPC "   # 6809: reglist index 4 (W) unavailable
_REGS  = "X  Y  U  S  W  PCRPC "   # 6309: reglist index 4 = W


def _skip_to_next_token(cl, p):
    """
    lwasm_skip_to_next_token(cl, p)  (lwasm.c):
    Only active under PRAGMA_NEWSOURCE -- skips whitespace in place.
    """
    if curpragma(cl, PRAGMA_NEWSOURCE):
        while p.peek() and p.peek().isspace():
            p.advance()


# ---------------------------------------------------------------------------
# FUNCTION: insn_parse_indexed_aux
# SOURCE:   lwtools-4.24/lwasm/insn_indexed.c lines 39-464
# TRANSLATED: 2026-07-17
#
# Pre-translation checklist results:
#   Integer width: none -- all values are postbyte-range ints (0-0xFF),
#       safe by construction (see TRANSLATION_GUIDE "Known Safe Patterns").
#   Division/modulo: none.
#   char **p: yes -- p is a Ptr, shared with the caller (both call sites
#       already hold the same Ptr instance the caller's cursor advances).
#   goto: none in this function.
#   char signedness: safe -- lwasm only ever handles ASCII source text.
#   Argument order: N/A -- no argument list doubles as a mutation site.
#   Promotion: none needed -- Python ints are already unbounded/exact.
#   Complement: none.
#   lookupreg: yes -- AsmState.lookupreg3(reglist, p) for the "expr,REG"
#       form (this is the *only* place in this function that accepts PC
#       and PCR as well as X/Y/U/S/W; the other two register switches in
#       this function are hand-rolled because C hand-rolls them too --
#       they intentionally accept a smaller register set).
#
# Interaction risks identified:
#   - The lookahead pattern `tstr = *p + 1; skip_to_next_token(l, &tstr);
#     if (*tstr == ',') ...` creates a SEPARATE local cursor for peeking
#     ahead without committing the advance unless the comma actually
#     matches. This is the opposite of the usual "share the Ptr" rule --
#     here C is deliberately *not* aliasing pointers, so the Python
#     translation must not share the Ptr instance for tstr either.
#     Mitigation: construct a fresh `Ptr(p.s, p.pos + 1)` for each
#     lookahead, and only copy its position back into `p` if the comma
#     is actually found (mirroring `*p = tstr + 1`).
#   - `l -> lint` is read before being written in several branches (the
#     "expr,REG" path relies on l->lint carrying over from the possible
#     '<'/'<<'/'>' prefix parse earlier in *this same call*, or, if no
#     prefix was seen, on whatever the caller preset it to). Both real
#     call sites (insn_gen.c's `goto indexed:` block and insn_indexed.c's
#     PARSEFUNC(insn_parse_indexed)) set `l->lint = -1` immediately
#     before calling this function -- so the Python call sites must do
#     the same, or the "undetermined register-offset marker" path below
#     will read a stale/wrong value.
#   - The final marker `l->pb = (indir*0x80) | rn | (f0*0x40)` (used when
#     the offset size could not be decided here) is a *different* bit
#     layout than the fully-resolved postbyte forms produced elsewhere in
#     this function (register field unshifted in bits 0-2, indirect at
#     bit 7, not bit 4). insn_resolve_indexed_aux is the only consumer of
#     this marker and must decode it with the matching bit layout.
#
# Mitigations applied:
#   - Fresh Ptr per lookahead (see above), copied into `p` only on match.
#   - Both callers in this module now explicitly set cl.lint = -1 before
#     invoking insn_parse_indexed_aux, matching both real C call sites.
#   - insn_resolve_indexed_aux (module-private _insn_resolve_indexed_aux)
#     was re-translated in this same session to decode the marker layout
#     this function actually produces -- see its own header comment.
# ---------------------------------------------------------------------------

def insn_parse_indexed_aux(as_, cl, p):
    """
    Faithful translation of insn_parse_indexed_aux (insn_indexed.c 39-464).

    Parses one indexed-addressing operand starting at Ptr p. Side effects
    (matching the C out-parameter line_t *l):
        cl.pb    -- either a fully-resolved postbyte, or (when the offset
                    size can't be decided yet) a marker byte consumed by
                    _insn_resolve_indexed_aux.
        cl.lint  -- 0/1/2/3 = decided (no-offset/8-bit/16-bit/5-bit), or
                    left at -1 (or whatever the caller preset) when still
                    undetermined.
        p        -- advanced past the consumed operand text.
    Errors are registered on cl via as_.register_error and the function
    returns (void, like the C original); every error path in the C is an
    immediate return with no further side effects, reproduced here as an
    early Python `return`.
    """
    if curpragma(cl, PRAGMA_6809):
        reglist = _REGS9
    else:
        reglist = _REGS

    indir = 0

    # is it indirect?
    if p.peek() == '[':
        indir = 1
        p.advance()

    _skip_to_next_token(cl, p)

    if p.peek() == ',':
        incdec = 0
        # pre-dec, post-inc, or no-offset mode
        p.advance()
        _skip_to_next_token(cl, p)
        if p.peek() == '-':
            incdec = -1
            p.advance()
            if p.peek() == '-':
                incdec = -2
                p.advance()
            _skip_to_next_token(cl, p)

        # allowed registers here: X, Y, U, S, or W (6309) -- NOT PC/PCR
        c = p.peek()
        if c in ('x', 'X'):
            rn = 0
        elif c in ('y', 'Y'):
            rn = 1
        elif c in ('u', 'U'):
            rn = 2
        elif c in ('s', 'S'):
            rn = 3
        elif c in ('w', 'W'):
            if curpragma(cl, PRAGMA_6809):
                as_.register_error(cl, E_OPERAND_BAD)
                return
            rn = 4
        else:
            as_.register_error(cl, E_OPERAND_BAD)
            return
        p.advance()
        _skip_to_next_token(cl, p)

        if p.peek() == '+':
            if incdec != 0:
                as_.register_error(cl, E_OPERAND_BAD)
                return
            incdec = 1
            p.advance()
            if p.peek() == '+':
                incdec = 2
                p.advance()
            _skip_to_next_token(cl, p)

        if indir:
            if p.peek() != ']':
                as_.register_error(cl, E_OPERAND_BAD)
                return
            p.advance()

        if indir or rn == 4:
            if incdec == 1 or incdec == -1:
                as_.register_error(cl, E_OPERAND_BAD)
                return

        if rn == 4:
            if indir:
                if incdec == 0:
                    i = 0x90
                elif incdec == -2:
                    i = 0xF0
                else:
                    i = 0xD0
            else:
                if incdec == 0:
                    i = 0x8F
                elif incdec == -2:
                    i = 0xEF
                else:
                    i = 0xCF
        else:
            if incdec == 0:
                i = 0x84
            elif incdec == 1:
                i = 0x80
            elif incdec == 2:
                i = 0x81
            elif incdec == -1:
                i = 0x82
            elif incdec == -2:
                i = 0x83
            i = (rn << 5) | i | (indir << 4)

        cl.pb   = i
        cl.lint = 0
        return

    # accumulator-offset forms: A,R  B,R  D,R  (and 6309 E,R  F,R  W,R)
    i = p.peek().upper() if p.peek() else ''
    if (i in ('A', 'B', 'D')) or (not curpragma(cl, PRAGMA_6809) and i in ('E', 'F', 'W')):
        # Lookahead only -- a SEPARATE cursor, not shared with p, matching
        # C's `tstr = *p + 1` local pointer that is only copied back into
        # *p if the comma actually matches (see checklist note above).
        tstr = Ptr(p.s, p.pos + 1)
        _skip_to_next_token(cl, tstr)
        if tstr.peek() == ',':
            p.pos = tstr.pos + 1
            _skip_to_next_token(cl, p)
            c = p.peek()
            if c in ('x', 'X'):
                rn = 0
            elif c in ('y', 'Y'):
                rn = 1
            elif c in ('u', 'U'):
                rn = 2
            elif c in ('s', 'S'):
                rn = 3
            else:
                as_.register_error(cl, E_OPERAND_BAD)
                return
            p.advance()
            _skip_to_next_token(cl, p)
            if indir:
                if p.peek() != ']':
                    as_.register_error(cl, E_OPERAND_BAD)
                    return
                p.advance()

            if i == 'A':
                i = 0x86
            elif i == 'B':
                i = 0x85
            elif i == 'D':
                i = 0x8B
            elif i == 'E':
                i = 0x87
            elif i == 'F':
                i = 0x8A
            elif i == 'W':
                i = 0x8E

            cl.pb   = i | (indir << 4) | (rn << 5)
            cl.lint = 0
            return
        # else: not actually an accumulator-offset (e.g. a label starting
        # with A/B/D/E/F/W) -- fall through to expression parsing below,
        # exactly as C does (p was never advanced, only the local tstr).

    # we have the "expression" types now
    if p.peek() == '<':
        cl.lint = 1
        p.advance()
        if p.peek() == '<':
            cl.lint = 3
            p.advance()
            if indir:
                as_.register_error(cl, E_ILL5)
                return
    elif p.peek() == '>':
        cl.lint = 2
        p.advance()

    _skip_to_next_token(cl, p)

    f0 = 0
    if p.peek() == '0':
        tstr = Ptr(p.s, p.pos + 1)
        _skip_to_next_token(cl, tstr)
        if tstr.peek() == ',':
            f0 = 1

    # now we have to evaluate the expression
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD)
        return
    cl.save_expr(0, e)

    if p.peek() != ',':
        # if no comma, we have extended indirect
        if cl.lint == 1 or p.peek() != ']':
            as_.register_error(cl, E_OPERAND_BAD)
            return
        p.advance()
        cl.lint = 2
        cl.pb   = 0x9F
        return

    p.advance()
    _skip_to_next_token(cl, p)

    # now get the register
    rn = AsmState.lookupreg3(reglist, p)
    if rn < 0:
        as_.register_error(cl, E_REGISTER_BAD)
        return

    if indir:
        if p.peek() != ']':
            as_.register_error(cl, E_OPERAND_BAD)
            return
        else:
            p.advance()

    if rn <= 3:
        # X,Y,U,S
        if cl.lint == 1:
            cl.pb = 0x88 | (rn << 5) | (0x10 if indir else 0)
            return
        elif cl.lint == 2:
            cl.pb = 0x89 | (rn << 5) | (0x10 if indir else 0)
            return
        elif cl.lint == 3:
            cl.pb = (rn << 5)
            # NOTE: no return here -- matches C exactly. Execution falls
            # through to the bottom of the function, where the final
            # `if (l->lint != 3)` guard prevents cl.pb being overwritten;
            # the 5-bit offset itself gets merged into cl.pb later, at
            # emit time (see _insn_emit_gen_aux / insn_emit_indexed).

    # nnnn,W is only 16 bit (or 0 bit)
    if rn == 4:
        if cl.lint == 1:
            as_.register_error(cl, E_NW_8)
            return
        elif cl.lint == 3:
            as_.register_error(cl, E_ILL5)
            return
        if cl.lint == 2:
            cl.pb   = 0xb0 if indir else 0xaf
            cl.lint = 2
            return
        cl.pb = (0x80 * indir) | rn
        return

    # PCR? then we have PC relative addressing (like B??, LB??)
    if rn == 5 or (rn == 6 and curpragma(cl, PRAGMA_PCASPCR)):
        # e - (addr + linelen) => e - addr - linelen
        e2 = Expr.special(lwasm_expr_linelen, cl)
        e1 = Expr.oper(OPER_MINUS, e, e2)
        e2 = Expr.oper(OPER_MINUS, e1, cl.addr)
        cl.save_expr(0, e2)
        if cl.lint == 1:
            cl.pb = 0x9C if indir else 0x8C
            return
        elif cl.lint == 2:
            cl.pb = 0x9D if indir else 0x8D
            return
        elif cl.lint == 3:
            as_.register_error(cl, E_ILL5)
            return

    if rn == 6:
        if cl.lint == 1:
            cl.pb = 0x9C if indir else 0x8C
            return
        elif cl.lint == 2:
            cl.pb = 0x9D if indir else 0x8D
            return
        elif cl.lint == 3:
            as_.register_error(cl, E_ILL5)
            return

    if cl.lint != 3:
        cl.pb = (indir * 0x80) | rn | (f0 * 0x40)


# ---------------------------------------------------------------------------
# FUNCTION: insn_resolve_indexed_aux  (module-private: _insn_resolve_indexed_aux)
# SOURCE:   lwtools-4.24/lwasm/insn_indexed.c lines 479-707 (approx.)
# TRANSLATED / RE-TRANSLATED: 2026-07-17
#
# Not the primary subject of this translation package (that is package
# 03), but re-translated here as required glue: this is the *only*
# consumer of the "undetermined offset" marker byte that the newly
# faithful insn_parse_indexed_aux (above) writes into cl.pb, and the
# marker's bit layout changed as a direct result of that translation
# (register field now unshifted in bits 0-2, indirect at bit 7, explicit
# "f0" zero-offset flag at bit 6 -- see insn_parse_indexed_aux's header
# comment). The previous hand-rolled resolve helper decoded a different,
# incompatible layout (register pre-shifted into bits 5-6, indirect at
# bit 4) that matched the previous hand-rolled parse helper. Plugging in
# a faithful parser without also fixing this decoder would silently
# corrupt every forward-referenced indexed operand. A full line-by-line
# audit of this function (matching package 02's process: checklist,
# independent translation, comparison, tests) is still recommended as
# follow-up under package 03 -- this translation is a faithful, complete
# transliteration of the C but has not been through that separate audit
# process.
# ---------------------------------------------------------------------------

def _insn_resolve_indexed_aux(as_, cl, force, elen=0):
    """Faithful translation of insn_resolve_indexed_aux (insn_indexed.c)."""
    if cl.len != -1:
        return

    e = cl.fetch_expr(0)

    if not (e and e.istype(TYPE_INT)):
        # temporarily set the instruction length to see if we get a
        # constant for our expression; if so, we can select an
        # instruction size
        e2 = e.copy() if e else None
        ops = _ops(cl)
        cl.len = _oplen(ops[0]) + elen + 2
        if e2 is not None:
            as_.reduce_expr(e2)
        cl.len = -1

        regfield = cl.pb & 0x07
        indir    = cl.pb & 0x80
        f0       = cl.pb & 0x40

        if e2 is not None and e2.istype(TYPE_INT):
            v = e2.intval()
            if v == 0 and not curpragma(cl, PRAGMA_NOINDEX0TONONE) and regfield <= 4:
                if regfield < 4:
                    pb = 0x84 | ((cl.pb & 0x03) << 5) | (0x10 if indir else 0)
                else:
                    pb = 0x90 if indir else 0x8F
                cl.pb   = pb
                cl.lint = 0
                return
            elif v < -128 or v > 127:
                cl.lint = 2
                if regfield in (0, 1, 2, 3):
                    pb = 0x89 | ((cl.pb & 0x03) << 5) | (0x10 if indir else 0)
                elif regfield == 4:
                    pb = 0xB0 if indir else 0xAF
                else:
                    pb = 0x9D if indir else 0x8D
                cl.pb = pb
                return
            elif indir or regfield > 3 or v < -16 or v > 15:
                cl.lint = 1
                if regfield in (0, 1, 2, 3):
                    pb = 0x88 | ((cl.pb & 0x03) << 5) | (0x10 if indir else 0)
                elif regfield == 4:
                    if v == 0 and not (curpragma(cl, PRAGMA_NOINDEX0TONONE) or f0):
                        pb = 0x90 if indir else 0x8F
                        cl.lint = 0
                    else:
                        pb = 0xB0 if indir else 0xAF
                        cl.lint = 2
                else:
                    pb = 0x9C if indir else 0x8C
                cl.pb = pb
                return
            else:
                cl.lint = 0
                if v == 0 and not (curpragma(cl, PRAGMA_NOINDEX0TONONE) or f0):
                    pb = ((cl.pb & 0x03) << 5) | 0x84
                else:
                    pb = ((cl.pb & 0x03) << 5) | (v & 0x1F)
                cl.pb = pb
                return
        else:
            if regfield in (5, 6):
                # heuristic fudge-factor pass; see C comment
                saved = as_.pretendmax
                as_.pretendmax = 1
                if e2 is not None:
                    as_.reduce_expr(e2)
                as_.pretendmax = saved
                if e2 is not None and e2.istype(TYPE_INT):
                    v = e2.intval()
                    if -100 <= v <= 100:
                        cl.lint = 1
                        cl.pb   = 0x9C if indir else 0x8C
                        return
        # falls through to the main branch below, exactly as C does

    if e and e.istype(TYPE_INT):
        v = e.intval()
        regfield = cl.pb & 0x07
        indir    = cl.pb & 0x80
        f0       = cl.pb & 0x40

        if v == 0 and not curpragma(cl, PRAGMA_NOINDEX0TONONE) and regfield <= 4 and f0 == 0:
            if regfield < 4:
                pb = 0x84 | ((cl.pb & 0x03) << 5) | (0x10 if indir else 0)
            else:
                pb = 0x90 if indir else 0x8F
            cl.pb   = pb
            cl.lint = 0
            return
        elif v < -128 or v > 127:
            cl.lint = 2
            if regfield in (0, 1, 2, 3):
                pb = 0x89 | ((cl.pb & 0x03) << 5) | (0x10 if indir else 0)
            elif regfield == 4:
                pb = 0xB0 if indir else 0xAF
            else:
                pb = 0x9D if indir else 0x8D
            cl.pb = pb
            return
        elif indir or regfield > 3 or v < -16 or v > 15:
            cl.lint = 1
            if regfield in (0, 1, 2, 3):
                pb = 0x88 | ((cl.pb & 0x03) << 5) | (0x10 if indir else 0)
            elif regfield == 4:
                if v == 0 and not (curpragma(cl, PRAGMA_NOINDEX0TONONE) or f0):
                    pb = 0x90 if indir else 0x8F
                    cl.lint = 0
                else:
                    pb = 0xB0 if indir else 0xAF
                    cl.lint = 2
            else:
                pb = 0x9C if indir else 0x8C
            cl.pb = pb
            return
        else:
            cl.lint = 0
            if v == 0 and not (curpragma(cl, PRAGMA_NOINDEX0TONONE) or f0):
                pb = ((cl.pb & 0x03) << 5) | 0x84
            else:
                pb = ((cl.pb & 0x03) << 5) | (v & 0x1F)
            cl.pb = pb
            return
    else:
        if not force:
            return
        cl.lint  = 2
        regfield = cl.pb & 0x07
        indir    = cl.pb & 0x80
        if regfield in (0, 1, 2, 3):
            pb = 0x89 | ((cl.pb & 0x03) << 5) | (0x10 if indir else 0)
        elif regfield == 4:
            pb = 0xB0 if indir else 0xAF
        else:
            pb = 0x9D if indir else 0x8D
        cl.pb = pb
        return


def insn_parse_indexed(as_, cl, operand):
    """
    insn_parse_indexed (LEA instructions) -- PARSEFUNC wrapper, insn_indexed.c:
        l -> lint = -1;
        insn_parse_indexed_aux(as, l, p);
        if (l -> lint != -1) {
            if (l -> lint == 3) l->len = OPLEN(ops[0]) + 1;
            else                l->len = OPLEN(ops[0]) + l->lint + 1;
        }
    Note: real C does NOT set minlen/maxlen here (unlike the general
    gen_aux indexed path) -- matched faithfully; those fields are unused
    elsewhere in this codebase (grep confirms no reader in passes.py /
    pass1.py), so this is a safe, faithful correction from the previous
    ad hoc version, which had set them unconditionally.
    """
    p = Ptr(operand)
    cl.lint  = -1
    cl.lint2 = 1
    insn_parse_indexed_aux(as_, cl, p)
    if cl.lint != -1:
        ops = _ops(cl)
        if cl.lint == 3:
            cl.len = _oplen(ops[0]) + 1
        else:
            cl.len = _oplen(ops[0]) + cl.lint + 1
    return p.remaining()

def insn_resolve_indexed(as_, cl, force):
    """
    RESOLVEFUNC(insn_resolve_indexed), insn_indexed.c:
        if (l -> lint == -1) insn_resolve_indexed_aux(as, l, force, 0);
        if (l -> lint != -1 && l -> pb != -1) {
            if (l -> lint == 3) l->len = OPLEN(ops[0]) + 1;
            else                l->len = OPLEN(ops[0]) + l->lint + 1;
        }
    """
    if cl.lint == -1:
        _insn_resolve_indexed_aux(as_, cl, force, 0)
    if cl.lint != -1 and cl.pb != -1:
        ops = _ops(cl)
        if cl.lint == 3:
            cl.len = _oplen(ops[0]) + 1
        else:
            cl.len = _oplen(ops[0]) + cl.lint + 1

def insn_emit_indexed(as_, cl):
    ops = _ops(cl)
    cl.emitop(ops[0])
    e = cl.fetch_expr(0)
    if cl.lint == 3:
        if e and e.istype(TYPE_INT):
            offs = e.intval()
            if (offs >= -16 and offs <= 15) or offs >= 0xFFF0:
                cl.pb = (cl.pb & 0xE0) | (offs & 0x1F)
                cl.lint = 0
            else:
                cl.as_.register_error(cl, E_BYTE_OVERFLOW)
    cl.emit(cl.pb)
    if cl.lint == 1 and e:
        cl.emitexpr(e, 1)
    elif cl.lint == 2 and e:
        cl.emitexpr(e, 2)



# ─────────────────────────────────────────────────────────────────────────────
# Relative branches  (insn_rel.c)
# ─────────────────────────────────────────────────────────────────────────────

def insn_parse_rel8(as_, cl, operand):
    """8-bit relative branch: fixed size."""
    p = Ptr(operand)
    ops = _ops(cl)
    if p.peek() == '#': p.advance()
    t = as_.parse_expr(p)
    if not t:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    # offset = target - (addr + len)
    e2 = Expr.special(lwasm_expr_linelen, cl)
    e1 = Expr.oper(OPER_MINUS, t, e2)
    e2 = Expr.oper(OPER_MINUS, e1, cl.addr)
    cl.save_expr(0, e2)
    cl.len = _oplen(ops[0]) + 1
    return p.remaining()

def insn_resolve_rel8(as_, cl, force):
    pass

def insn_emit_rel8(as_, cl):
    e = cl.fetch_expr(0)
    ops = _ops(cl)
    if not e or not e.istype(TYPE_INT):
        cl.as_.register_error(cl, E_EXPRESSION_NOT_CONST); return
    offs = e.intval()
    if offs < -128 or offs > 127:
        cl.as_.register_error(cl, E_BYTE_OVERFLOW); return
    cl.emitop(ops[0])
    cl.emit(offs & 0xFF)


def insn_parse_rel16(as_, cl, operand):
    """16-bit relative branch: fixed size."""
    p = Ptr(operand)
    ops = _ops(cl)
    if p.peek() == '#': p.advance()
    t = as_.parse_expr(p)
    if not t:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    e2 = Expr.special(lwasm_expr_linelen, cl)
    e1 = Expr.oper(OPER_MINUS, t, e2)
    e2 = Expr.oper(OPER_MINUS, e1, cl.addr)
    cl.save_expr(0, e2)
    cl.len = _oplen(ops[0]) + 2
    return p.remaining()

def insn_resolve_rel16(as_, cl, force):
    pass

def insn_emit_rel16(as_, cl):
    e    = cl.fetch_expr(0)
    ops  = _ops(cl)
    cl.emitop(ops[0])
    cl.emitexpr(e, 2)


def insn_parse_relgen(as_, cl, operand):
    """
    insn_parse_relgen: auto-size relative branch.
    ops[0] = base (or short) opcode
    ops[1] = natural size preference (8 or 16)
    ops[2] = short (8-bit) opcode
    ops[3] = long (16-bit) opcode
    """
    p    = Ptr(operand)
    ops  = _ops(cl)

    cl.lint    = -1     # -1=auto, 8=short, 16=long
    cl.maxlen  = _oplen(ops[3]) + 2
    cl.minlen  = _oplen(ops[2]) + 1

    if not curpragma(cl, PRAGMA_AUTOBRANCHLENGTH):
        cl.lint = ops[1]   # natural size
    else:
        if p.peek() == '>' and p.pos+1 < len(p.s) and not p.s[p.pos+1].isspace():
            p.advance(); cl.lint = 16
        elif p.peek() == '<' and p.pos+1 < len(p.s) and not p.s[p.pos+1].isspace():
            p.advance(); cl.lint = 8

    if p.peek() == '#': p.advance()

    t = as_.parse_expr(p)
    if not t:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()

    if cl.lint == 8:
        cl.len = _oplen(ops[2]) + 1
    elif cl.lint == 16:
        cl.len = _oplen(ops[3]) + 2

    # offset = target - (addr + linelen)
    e2 = Expr.special(lwasm_expr_linelen, cl)
    e1 = Expr.oper(OPER_MINUS, t, e2)
    e2 = Expr.oper(OPER_MINUS, e1, cl.addr)
    cl.save_expr(0, e2)

    # Try to resolve size early if lint is still -1
    if cl.len == -1:
        e1  = Expr.copy(e2)
        cl.len = _oplen(ops[2]) + 1   # assume short temporarily
        as_.reduce_expr(e1)
        cl.len = -1
        if e1.istype(TYPE_INT):
            offs = e1.intval()
            if -128 <= offs <= 127:
                cl.lint = 8
                cl.len  = _oplen(ops[2]) + 1
            else:
                cl.lint = 16
                cl.len  = _oplen(ops[3]) + 2

    return p.remaining()


def insn_resolve_relgen(as_, cl, force):
    ops = _ops(cl)
    if cl.lint == -1:
        e = cl.fetch_expr(0)
        if not e.istype(TYPE_INT):
            e2 = Expr.copy(e)
            cl.len = _oplen(ops[2]) + 1  # short temporarily
            as_.reduce_expr(e2)
            cl.len = -1
            if e2.istype(TYPE_INT):
                offs = e2.intval()
                if -128 <= offs <= 127:
                    cl.len  = _oplen(ops[2]) + 1
                    cl.lint = 8
                else:
                    cl.len  = _oplen(ops[3]) + 2
                    cl.lint = 16
        if e.istype(TYPE_INT):
            offs = e.intval()
            if -128 <= offs <= 127:
                cl.len  = _oplen(ops[2]) + 1
                cl.lint = 8
            else:
                cl.len  = _oplen(ops[3]) + 2
                cl.lint = 16

    if force and cl.len == -1:
        cl.len  = _oplen(ops[3]) + 2
        cl.lint = 16


def insn_emit_relgen(as_, cl):
    e    = cl.fetch_expr(0)
    ops  = _ops(cl)

    if cl.lint == 8:
        if not e or not e.istype(TYPE_INT):
            cl.as_.register_error(cl, E_EXPRESSION_NOT_CONST); return
        offs = e.intval()
        if offs < -128 or offs > 127:
            cl.as_.register_error(cl, E_BYTE_OVERFLOW); return
        cl.emitop(ops[2])
        cl.emit(offs & 0xFF)
    else:
        cl.emitop(ops[3])
        cl.emitexpr(e, 2)


# ─────────────────────────────────────────────────────────────────────────────
# Register-to-register  (insn_rtor.c) — TFR, EXG
# ─────────────────────────────────────────────────────────────────────────────

# Register codes for 6809 and 6309 (r0, r1 -> 4-bit nibbles)
# D X Y U S PC  A B CC DP  (6809)
# D X Y U S PC W V A B CC DP 0 0 E F  (6309 — extra registers)
_RTOR_REGS  = 'D X Y U S PCW V A B CCDP0 0 E F '   # 6309
_RTOR_REGS9 = 'D X Y U S PC    A B CCDP        '    # 6809

def insn_parse_rtor(as_, cl, operand):
    p = Ptr(operand)
    ops  = _ops(cl)
    regs = _RTOR_REGS9 if curpragma(cl, PRAGMA_6809) else _RTOR_REGS

    r0 = AsmState.lookupreg2(regs, p)
    if curpragma(cl, PRAGMA_NEWSOURCE):
        while p.peek() and p.peek().isspace(): p.advance()
    if r0 < 0 or p.peek() != ',':
        as_.register_error(cl, E_OPERAND_BAD); r0 = r1 = 0
    else:
        p.advance()
        if curpragma(cl, PRAGMA_NEWSOURCE):
            while p.peek() and p.peek().isspace(): p.advance()
        r1 = AsmState.lookupreg2(regs, p)
        if r1 < 0:
            as_.register_error(cl, E_OPERAND_BAD); r0 = r1 = 0

    cl.pb  = (r0 << 4) | r1
    cl.len = _oplen(ops[0]) + 1
    return p.remaining()

def insn_resolve_rtor(as_, cl, force):
    pass

def insn_emit_rtor(as_, cl):
    cl.emitop(_ops(cl)[0])
    cl.emit(cl.pb)


# ─────────────────────────────────────────────────────────────────────────────
# Register list  (insn_rlist.c) — PSHS, PULS, PSHU, PULU
# ─────────────────────────────────────────────────────────────────────────────
# Register bits for stack list:
# bit 0=CC  1=A  2=B  3=DP  4=X  5=Y  6=U/S  7=PC

_RLIST_REGS = 'CCA B DPX Y U PCD S '

def insn_parse_rlist(as_, cl, operand):
    p    = Ptr(operand)
    ops  = _ops(cl)
    cl.lint = 0

    if p.peek() == '#':
        remaining = insn_parse_imm8(as_, cl, operand)
        cl.lint = 1
        return remaining

    rb = 0
    while p.peek() and not p.peek().isspace() \
          and p.peek() not in (';', '*'):
        rn = AsmState.lookupreg2(_RLIST_REGS, p)
        if rn < 0:
            as_.register_error2(cl, E_REGISTER_BAD, "'%s'", p.remaining())
            return p.remaining()

        if curpragma(cl, PRAGMA_NEWSOURCE):
            while p.peek() and p.peek().isspace(): p.advance()

        if p.peek() and p.peek() not in (',',) and \
           not p.peek().isspace() and p.peek() not in (';', '*'):
            as_.register_error(cl, E_OPERAND_BAD)

        if p.peek() == ',':
            p.advance()
            if curpragma(cl, PRAGMA_NEWSOURCE):
                while p.peek() and p.peek().isspace(): p.advance()

        # U and S exclusivity check
        if (ops[0] & 2):   # PSHU/PULU
            if rn == 6:    # U not allowed
                as_.register_error2(cl, E_REGISTER_BAD, "'%s'", 'u')
                return p.remaining()
        else:              # PSHS/PULS
            if rn == 9:    # S not allowed
                as_.register_error2(cl, E_REGISTER_BAD, "'%s'", 's')
                return p.remaining()

        # Map register bits
        # _RLIST_REGS table: CC=0 A=1 B=2 DP=3 X=4 Y=5 U=6 PC=7 D=8 S=9
        if rn == 7:        # PC
            rb |= 0x80
        elif rn == 8:      # D = A|B (lwasm treats D as synonym for A,B in rlist)
            rb |= 0x06
        elif rn == 9:      # S
            rb |= 0x40
        else:
            rb |= (1 << rn)

    if rb == 0:
        as_.register_error(cl, E_OPERAND_BAD)

    cl.len = _oplen(ops[0]) + 1
    cl.pb  = rb
    return p.remaining()

def insn_resolve_rlist(as_, cl, force):
    pass

# ---------------------------------------------------------------------------
# FUNCTION: _cycle_calc_rlist
# SOURCE:   lwtools-4.24/lwasm/cycle.c lines 656-670 (lwasm_cycle_calc_rlist)
#
# Additional-cycle calculation for the rlist postbyte (PSHS/PULS/PSHU/PULU).
# Needed as a helper because insn_emit_rlist (source.c) calls it directly;
# not yet reachable from any other translated function.
#
# Pre-translation checklist:
#   Integer width: none -- cl.pb already constrained to a byte value by the
#     parse-time assignment (insn_parse_rlist); no masking needed here.
#   Division/modulo: none
#   char **p: N/A
#   goto: none
#   char signedness: N/A
#   Argument order: N/A -- no function-call arguments with side effects
#   Promotion: safe -- plain int accumulation, no truncation on assignment
#   Complement: none
#   lookupreg: N/A
# ---------------------------------------------------------------------------
def _cycle_calc_rlist(cl):
    """lwasm_cycle_calc_rlist(cl): extra ticks for pushed/pulled registers.

    1 cycle for each of the four 8-bit registers (bits 0-3: CC,A,B,DP),
    2 cycles for each of the four 16-bit registers (bits 4-7: X,Y,U/S,PC).
    """
    cycles = 0
    for i in range(8):
        if cl.pb & (1 << i):
            cycles += 1 if i <= 3 else 2
    return cycles

# ---------------------------------------------------------------------------
# FUNCTION: insn_emit_rlist
# SOURCE:   lwtools-4.24/lwasm/insn_rlist.c lines 96-108
# TRANSLATED: 2026-07-17
#
# Pre-translation checklist results:
#   Integer width: none -- no fixed-width assignments
#   Division/modulo: none
#   char **p: N/A
#   goto: none
#   char signedness: safe
#   Argument order: safe -- no argument-position side effects
#   Promotion: safe
#   Complement: none
#   lookupreg: N/A
#
# Interaction risks: cl.pb must already reflect the final rlist postbyte
#   (set during resolve/parse) by the time cycle_adj is computed here --
#   confirmed by insn_resolve_rlist being a no-op and cl.pb being set at
#   parse time in insn_parse_rlist.
# Mitigations applied: none needed
# ---------------------------------------------------------------------------
def insn_emit_rlist(as_, cl):
    if cl.lint == 1:
        insn_emit_imm8(as_, cl); return

    cl.emitop(_ops(cl)[0])
    cl.emit(cl.pb)

    cl.cycle_adj = _cycle_calc_rlist(cl)


# ─────────────────────────────────────────────────────────────────────────────
# Logic-mem (6309 AIM/EIM/OIM/TIM) — stub
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Logic-mem (6309 AIM/EIM/OIM/TIM)  (insn_logicmem.c)
# ─────────────────────────────────────────────────────────────────────────────
# Syntax: AIM #imm,<gen-mode-operand>  (also OIM/EIM/TIM)
# The immediate value is saved in expression slot 100 (matching the C
# source's use of that slot number as an "extra" operand outside the
# normal 0/1/2 slots used by the general addressing-mode machinery), then
# the remaining operand is parsed exactly like any other general-mode
# instruction, with elen=1 to account for the extra immediate byte that
# will be emitted alongside the addressing-mode bytes.

def insn_parse_logicmem(as_, cl, operand):
    p = Ptr(operand)
    if p.peek() == '#':
        p.advance()
    s = as_.parse_expr(p)
    if not s:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    cl.save_expr(100, s)
    if p.peek() not in (',', ';'):
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    p.advance()
    _insn_parse_gen_aux(as_, cl, p, 1)
    return p.remaining()

def insn_resolve_logicmem(as_, cl, force):
    if cl.len != -1: return
    _insn_resolve_gen_aux(as_, cl, force, 1)

def insn_emit_logicmem(as_, cl):
    e = cl.fetch_expr(100)
    if not (e and e.istype(TYPE_INT)):
        as_.register_error(cl, E_IMMEDIATE_UNRESOLVED)
        return
    v = e.intval()
    _insn_emit_gen_aux(as_, cl, v & 0xFF)


# ─────────────────────────────────────────────────────────────────────────────
# 6309 conv instructions (NEGQ, TSTQ etc.) — stub
# ─────────────────────────────────────────────────────────────────────────────

def insn_parse_conv(as_, cl, operand):
    ops = _ops(cl)
    cl.len = sum(_oplen(ops[i]) for i in range(3) if ops[i] >= 0)
    if ops[0] == -1: cl.len = 10
    return operand

def insn_resolve_conv(as_, cl, force): pass
def insn_emit_conv(as_, cl):
    ops = _ops(cl)
    for i in range(3):
        if ops[i] >= 0: cl.emitop(ops[i])
    cl.cycle_base = ops[3]


# ─────────────────────────────────────────────────────────────────────────────
# TFM (6309) — stub
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# TFM (6309 block transfer)  (insn_tfm.c)
# ─────────────────────────────────────────────────────────────────────────────
# Syntax: TFM r0+,r1+  /  TFM r0-,r1-  /  TFM r0+,r1  /  TFM r0,r1+
# Only D, X, Y, U, S are valid TFM registers (indices 0-4 in _TFM_REGLIST).
# The four legal direction combinations select one of four distinct
# opcodes (ops[0..3]); any other combination is E_UNKNOWN_OPERATION.

_TFM_REGLIST = "DXYUS   AB  00EF"   # index = register field value (0-4 legal)

def _tfm_reg(p):
    """Match one TFM register letter, return its _TFM_REGLIST index or None."""
    c = p.peek()
    if not c:
        return None
    idx = _TFM_REGLIST.find(c.upper())
    if idx < 0:
        return None
    p.advance()
    return idx

def insn_parse_tfm(as_, cl, operand):
    p = Ptr(operand)
    ops = _ops(cl)
    tfm = 0

    r0 = _tfm_reg(p)
    if r0 is None:
        as_.register_error(cl, E_REGISTER_BAD); return p.remaining()

    if p.peek() == '+':
        p.advance(); tfm = 1
    elif p.peek() == '-':
        p.advance(); tfm = 2

    if p.peek() != ',':
        as_.register_error(cl, E_UNKNOWN_OPERATION); return p.remaining()
    p.advance()

    r1 = _tfm_reg(p)
    if r1 is None:
        as_.register_error(cl, E_REGISTER_BAD); return p.remaining()

    if p.peek() == '+':
        p.advance(); tfm |= 4
    elif p.peek() == '-':
        p.advance(); tfm |= 8

    if p.peek() and not p.peek().isspace():
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()

    # Only D, X, Y, U, S (indices 0-4) are valid TFM registers.
    if r0 > 4 or r1 > 4:
        bad = r1 if r0 < r1 else r0   # matches C: "if (r0 < r1) r0 = r1;" then uses reglist[r0]
        as_.register_error2(cl, E_REGISTER_BAD, "'%c'", _TFM_REGLIST[bad])
        # C does not return here -- it falls through into the switch below.

    # tfm==5: r0+,r1+ / tfm==10: r0-,r1- / tfm==1: r0+,r1 / tfm==4: r0,r1+
    if tfm == 5:
        cl.lint = ops[0]
    elif tfm == 10:
        cl.lint = ops[1]
    elif tfm == 1:
        cl.lint = ops[2]
    elif tfm == 4:
        cl.lint = ops[3]
    else:
        as_.register_error(cl, E_UNKNOWN_OPERATION); return p.remaining()

    cl.pb  = (r0 << 4) | r1
    cl.len = _oplen(cl.lint) + 1
    return p.remaining()

def insn_resolve_tfm(as_, cl, force):
    pass

def insn_emit_tfm(as_, cl):
    cl.emitop(cl.lint)
    cl.emit(cl.pb)


# ─────────────────────────────────────────────────────────────────────────────
# Inter-register postbyte form (6309 TFR-style: ADDR/SUBR/CMPR/ANDR/ORR/
# EORR/ADCR/SBCR and similar r0,r1 instructions)  (insn_tfm.c insn_parse_tfmrtor)
# ─────────────────────────────────────────────────────────────────────────────
# Any of the 16 TFR/EXG-style registers is legal here (unlike TFM itself,
# which restricts to D/X/Y/U/S) -- matches lwasm_lookupreg2 over the full
# register table: D,X,Y,U,S,PC,W,V,A,B,CC,DP,0,0,E,F.

_TFMRTOR_REGS = "D X Y U S       A B     0 0 E F "

def insn_parse_tfmrtor(as_, cl, operand):
    p = Ptr(operand)
    ops = _ops(cl)

    r0 = AsmState.lookupreg2(_TFMRTOR_REGS, p)
    if r0 < 0 or p.peek() != ',':
        as_.register_error(cl, E_OPERAND_BAD)
        r0 = r1 = 0
    else:
        p.advance()
        r1 = AsmState.lookupreg2(_TFMRTOR_REGS, p)
        if r1 < 0:
            as_.register_error(cl, E_OPERAND_BAD)
            r0 = r1 = 0

    cl.len = _oplen(ops[0]) + 1
    cl.pb  = (r0 << 4) | r1
    return p.remaining()

def insn_resolve_tfmrtor(as_, cl, force):
    pass

def insn_emit_tfmrtor(as_, cl):
    ops = _ops(cl)
    cl.emitop(ops[0])
    cl.emit(cl.pb)


# ─────────────────────────────────────────────────────────────────────────────
# Bitbit (6309 BAND/BEOR/BIOR/BOR/LDBT/STBT) — stub
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Bitbit (6309 BAND/BEOR/BIOR/BOR/LDBT/STBT)  (insn_bitbit.c)
# ─────────────────────────────────────────────────────────────────────────────
# Syntax: BAND CC,srcbit,dstbit,<addr   (also A,/B,/CC, and the other 5
# mnemonics in this family). Postbyte = (reg<<6)|(srcbit<<3)|dstbit; the
# addressing byte is always a direct-page (1-byte) address, exactly like
# the C source -- these instructions "cannot tolerate external references"
# per the C comment, i.e. the address must resolve to a single byte offset
# from the current direct page.

def insn_parse_bitbit(as_, cl, operand):
    p = Ptr(operand)
    if not p.peek():
        as_.register_error(cl, E_REGISTER_BAD); return p.remaining()
    r_char = p.peek().upper()
    p.advance()
    if r_char == 'A':
        r = 1
    elif r_char == 'B':
        r = 2
    elif r_char == 'C' and p.peek() and p.peek().upper() == 'C':
        r = 0
        p.advance()
    else:
        as_.register_error(cl, E_REGISTER_BAD); return p.remaining()

    if p.peek() != ',':
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    p.advance()
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    cl.save_expr(0, e)

    if p.peek() != ',':
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    p.advance()
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    cl.save_expr(1, e)

    if p.peek() != ',':
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    p.advance()
    if p.peek() == '<':
        p.advance()   # ignore base-page address modifier, matches C
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    cl.save_expr(2, e)

    ops = _ops(cl)
    cl.lint = r
    cl.len  = _oplen(ops[0]) + 2
    return p.remaining()

def insn_resolve_bitbit(as_, cl, force):
    pass

def insn_emit_bitbit(as_, cl):
    ops = _ops(cl)

    e = cl.fetch_expr(0)
    if not (e and e.istype(TYPE_INT)):
        as_.register_error(cl, E_BITNUMBER_UNRESOLVED)
        return
    v1 = e.intval()
    if v1 < 0 or v1 > 7:
        as_.register_error(cl, E_BITNUMBER_INVALID)
        v1 = 0

    e = cl.fetch_expr(1)
    if not (e and e.istype(TYPE_INT)):
        as_.register_error(cl, E_BITNUMBER_UNRESOLVED)
        return
    v2 = e.intval()
    if v2 < 0 or v2 > 7:
        as_.register_error(cl, E_BITNUMBER_INVALID)
        v2 = 0

    cl.pb = (cl.lint << 6) | (v1 << 3) | v2

    e = cl.fetch_expr(2)
    if e and e.istype(TYPE_INT):
        vv = e.intval() & 0xFFFF
        diff = vv - (cl.dpval << 8)
        if diff > 0xFF or diff < 0:
            as_.register_error(cl, E_BYTE_OVERFLOW)
            return

    cl.emitop(ops[0])
    cl.emit(cl.pb)
    cl.emitexpr(e, 1)
