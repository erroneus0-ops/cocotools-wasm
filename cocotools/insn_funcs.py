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
    E_OPERAND_BAD, E_IMMEDIATE_INVALID, E_BYTE_OVERFLOW,
    E_EXPRESSION_NOT_RESOLVED, E_EXPRESSION_NOT_CONST, E_REGISTER_BAD,
    E_BITNUMBER_UNRESOLVED, E_BITNUMBER_INVALID, E_IMMEDIATE_UNRESOLVED,
    E_UNKNOWN_OPERATION,
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
        _parse_indexed_mode(as_, cl, p)
        cl.lint2 = 1
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
            _parse_indexed_mode(as_, cl, p)
            cl.lint2 = 1
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
        _parse_indexed_mode(as_, cl, p)
        cl.lint2 = 1
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
    """
    ops = _ops(cl)
    if cl.lint2 == 1:
        _insn_resolve_indexed_aux(as_, cl, force, elen); return
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

_IDX_REG_BITS = {'X': 0x00, 'Y': 0x20, 'U': 0x40, 'S': 0x60}
_IDX_ACC_BITS = {'A': 0x86, 'B': 0x85, 'D': 0x8B}
# Actually: A,R = 0x86, B,R = 0x85, D,R = 0x8B  for X base;
# For Y, U, S base: add the register bits

def _parse_indexed_mode(as_, cl, p):
    """
    Parse indexed addressing mode, set cl.pb and cl.lint (offset size).
    cl.lint values: 0=no offset byte, 1=8-bit, 2=16-bit, 3=5-bit constant
    """
    indirect = False

    if p.peek() == '[':
        indirect = True
        p.advance()

    # Check for accumulator offset: A,R / B,R / D,R
    saved_pos = p.pos
    acc_char  = p.peek().upper() if p.peek() else ''
    if acc_char in ('A', 'B', 'D'):
        p.advance()
        if p.peek() == ',':
            p.advance()
            reg_bits = _get_idx_reg_bits(cl, as_, p)
            if reg_bits is not None:
                acc_map = {'A': 0x86, 'B': 0x85, 'D': 0x8B}
                pb = reg_bits | acc_map[acc_char]
                if indirect: pb |= 0x10
                cl.pb   = pb
                cl.lint = 0
                if indirect:
                    if p.peek() == ']': p.advance()
                return
        p.pos = saved_pos  # backtrack

    # Check for pre-decrement: ,-R or ,--R
    if p.peek() == ',':
        p.advance()
        if p.peek() == '-':
            p.advance()
            if p.peek() == '-':
                p.advance()
                reg_bits = _get_idx_reg_bits(cl, as_, p)
                if reg_bits is None: return
                pb = reg_bits | 0x83   # ,--R pre-decrement 2
                if indirect: pb |= 0x10
                cl.pb   = pb
                cl.lint = 0
                if indirect and p.peek() == ']': p.advance()
                return
            else:
                reg_bits = _get_idx_reg_bits(cl, as_, p)
                if reg_bits is None: return
                # lwasm unconditionally blocks single pre-decrement indirect [,-R]
                # It exists on some 6809 silicon but lwasm errors regardless of mode.
                # Direct form ,-R is valid. Indirect [,-R] is not.
                if indirect:
                    as_.register_error(cl, E_OPERAND_BAD)
                    return
                pb = reg_bits | 0x82   # ,-R  pre-decrement 1
                cl.pb   = pb
                cl.lint = 0
                return
        # zero offset, no expression: ,R or ,R+ or ,R++
        reg_bits = _get_idx_reg_bits(cl, as_, p)
        if reg_bits is None:
            as_.register_error(cl, E_OPERAND_BAD); return
        if p.peek() == '+':
            p.advance()
            if p.peek() == '+':
                p.advance()
                pb = reg_bits | 0x81   # ,R++ post-increment 2
            else:
                pb = reg_bits | 0x80   # ,R+  post-increment 1
        else:
            pb = reg_bits | 0x84       # ,R   zero-offset
        if indirect: pb |= 0x10
        cl.pb   = pb
        cl.lint = 0
        if indirect and p.peek() == ']': p.advance()
        return

    # expr,R form
    expr = as_.parse_expr(p)
    if not expr:
        as_.register_error(cl, E_OPERAND_BAD); return
    cl.save_expr(0, expr)

    # [expr] with no register = extended indirect (post-byte 0x9F)
    if indirect and p.peek() == ']':
        p.advance()
        cl.pb   = 0x9F
        cl.lint = 2   # 16-bit address
        return

    if p.peek() != ',':
        as_.register_error(cl, E_OPERAND_BAD); return
    p.advance()

    # Check for PC-relative: n,PC or n,PCR
    if p.peek() and p.s[p.pos:p.pos+2].upper() == 'PC':
        p.advance(2)
        if p.peek() and p.peek().upper() == 'R': p.advance()
        # PC-relative offset = target - (addr + linelen), same as relgen
        pb = 0x8D  # 16-bit PC-relative
        if indirect: pb |= 0x10
        cl.pb   = pb
        cl.lint = 2   # 16-bit offset

        # Build offset expression: expr - LINELEN(cl) - addr(cl)
        le = Expr.special(lwasm_expr_linelen, cl)
        e1 = Expr.oper(OPER_MINUS, expr, le)
        e2 = Expr.oper(OPER_MINUS, e1, cl.addr)
        cl.save_expr(0, e2)

        if indirect and p.peek() == ']': p.advance()
        return

    reg_bits = _get_idx_reg_bits(cl, as_, p)
    if reg_bits is None:
        as_.register_error(cl, E_OPERAND_BAD); return

    # Determine offset size
    if expr.istype(TYPE_INT):
        v = expr.intval()
        if not indirect and -16 <= v <= 15:
            pb   = reg_bits | (v & 0x1F) & 0xFF   # 5-bit, bit7=0
            cl.pb   = pb
            cl.lint = 3   # 5-bit constant
        elif -128 <= v <= 127:
            pb   = reg_bits | 0x88  # 8-bit offset, bit7=1
            if indirect: pb |= 0x10
            cl.pb   = pb
            cl.lint = 1
        else:
            pb   = reg_bits | 0x89  # 16-bit offset, bit7=1
            if indirect: pb |= 0x10
            cl.pb   = pb
            cl.lint = 2
    else:
        # Forward ref: use 16-bit (conservative)
        pb   = reg_bits | 0x89
        if indirect: pb |= 0x10
        cl.pb   = pb
        cl.lint = 2

    if indirect and p.peek() == ']': p.advance()


def _get_idx_reg_bits(cl, as_, p):
    """Parse register name X/Y/U/S/PC and return base bits, or None."""
    # 2-char: PC
    if p.pos+1 < len(p.s) and p.s[p.pos:p.pos+2].upper() == 'PC':
        p.advance(2)
        if p.peek() and p.peek().upper() == 'R': p.advance()
        return None   # handled separately by caller
    reg = p.peek().upper() if p.peek() else ''
    bits = _IDX_REG_BITS.get(reg)
    if bits is None:
        as_.register_error(cl, E_REGISTER_BAD)
        return None
    p.advance()
    return bits


def _insn_resolve_indexed_aux(as_, cl, force, elen=0):
    """Resolve indexed mode: try to pick optimal offset size."""
    e = cl.fetch_expr(0)
    if not e: return
    # C: if (l->lint != -1) return;  -- only resolve if still undecided
    if cl.lint != -1: return

    as_.reduce_expr(e)
    if e.istype(TYPE_INT):
        v = e.intval()
        reg_base = cl.pb & 0x60
        indirect = cl.pb & 0x10
        if not indirect and -16 <= v <= 15:
            cl.pb   = reg_base | (v & 0x1F)
            cl.lint = 3
        elif -128 <= v <= 127:
            cl.pb   = reg_base | 0x88 | indirect
            cl.lint = 1
        else:
            cl.pb   = reg_base | 0x89 | indirect
            cl.lint = 2
        ops = _ops(cl)
        cl.len = _oplen(ops[1]) + 1 + cl.lint + elen if cl.lint != 3 else _oplen(ops[1]) + 1 + elen


def insn_parse_indexed(as_, cl, operand):
    """insn_parse_indexed: LEA instructions — pure indexed mode."""
    p = Ptr(operand)
    cl.lint  = -1
    cl.lint2 = 1
    _parse_indexed_mode(as_, cl, p)
    ops = _ops(cl)
    cl.minlen = _oplen(ops[0]) + 1
    cl.maxlen = _oplen(ops[0]) + 3
    if cl.lint == 0 or cl.lint == 3:
        cl.len = _oplen(ops[0]) + 1
    elif cl.lint == 1:
        cl.len = _oplen(ops[0]) + 2
    elif cl.lint == 2:
        cl.len = _oplen(ops[0]) + 3
    return p.remaining()

def insn_resolve_indexed(as_, cl, force):
    _insn_resolve_indexed_aux(as_, cl, force)

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
        insn_parse_imm8(as_, cl, operand)
        cl.lint = 1
        return p.remaining()

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

def insn_emit_rlist(as_, cl):
    if cl.lint == 1:
        insn_emit_imm8(as_, cl); return
    cl.emitop(_ops(cl)[0])
    cl.emit(cl.pb)


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
