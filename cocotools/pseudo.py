"""
cocotools/pseudo.py — Directive (pseudo-op) parse/resolve/emit functions
Faithful Python translation of lwasm/pseudo.c
(William Astle, LWTools, GPL v3)
Source: http://lwtools.projects.l-w.ca/

Each PARSEFUNC(pseudo_parse_xxx) becomes:
    def pseudo_parse_xxx(as_, cl, operand) -> str (remaining)

Each RESOLVEFUNC(pseudo_resolve_xxx) becomes:
    def pseudo_resolve_xxx(as_, cl, force) -> None

Each EMITFUNC(pseudo_emit_xxx) becomes:
    def pseudo_emit_xxx(as_, cl) -> None

The C char **p pattern is handled by Ptr objects:
    **p   → p.peek()
    (*p)++ → p.advance()
    remaining → p.remaining()
"""

import time

from .lw_expr    import Expr, Ptr, TYPE_INT, OPER_PLUS, OPER_MINUS, OPER_DIVIDE
from .lwasm_types import (
    OUTPUT_DECB, OUTPUT_BASIC, OUTPUT_LWMOD, OUTPUT_IHEX, OUTPUT_SREC,
    OUTPUT_DRAGON, OUTPUT_ABS, OUTPUT_OBJ, OUTPUT_OS9,
    PRAGMA_NEWSOURCE, PRAGMA_M80EXT, PRAGMA_NOLIST, PRAGMA_CESCAPES,
    PRAGMA_SYMBOLNOCASE, PRAGMA_CONDUNDEFZERO,
    E_SYMBOL_MISSING, E_OPERAND_BAD, E_EXPRESSION_BAD,
    E_EXEC_ADDRESS, E_SETDP_INVALID, E_SETDP_NOT_CONST,
    E_EXPRESSION_NOT_CONST, E_NEGATIVE_RESERVATION, E_NEGATIVE_BLOCKSIZE,
    E_EXPRESSION_NOT_RESOLVED, E_FILE_OPEN, E_FILENAME_MISSING,
    E_INCLUDEBIN_ILL_START, E_INCLUDEBIN_ILL_LENGTH,
    E_MISSING_PHASE, E_NESTED_PHASE, E_USER_SPECIFIED, E_PRAGMA_UNRECOGNIZED,
    E_REGISTER_BAD, E_OPCODE_BAD, E_ORG_NOT_FOUND,
    E_STRING_BAD, E_CONDITION_P1,
    W_USER_SPECIFIED, W_NOT_SUPPORTED,
    NOWARN_IFP1,
    symbol_flag_none, symbol_flag_set,
    lwasm_expr_linelen, lwasm_expr_linedlen,
    section_flag_bss, section_flag_constant,
)
from .lwasm_core import curpragma


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _skip_operand(cl, p):
    """skip_operand_real(cl, p): skip to end of token unless NEWSOURCE."""
    if curpragma(cl, PRAGMA_NEWSOURCE):
        return
    while p.peek() and not p.peek().isspace():
        p.advance()


def _skip_whitespace(p):
    while p.peek() and p.peek().isspace():
        p.advance()


def _cstringlen(as_, cl, p, delim):
    """
    cstringlen(as, ln, p, delim):
    Scan string up to delim, handle C escapes if PRAGMA_CESCAPES.
    Stores the raw bytes in cl.lstr; returns length.
    """
    buf = []
    if not (as_.pragmas & PRAGMA_CESCAPES):
        while p.peek() and p.peek() != delim:
            buf.append(p.peek())
            p.advance()
    else:
        while p.peek() and p.peek() != delim:
            ch = p.peek(); p.advance()
            if ch == '\\' and p.peek():
                nxt = p.peek(); p.advance()
                wch = ord(nxt)
                if nxt in '0123':
                    wch = int(nxt)
                    if p.peek() and '0' <= p.peek() < '8':
                        wch = wch*8 + int(p.peek()); p.advance()
                    if p.peek() and '0' <= p.peek() < '8':
                        wch = wch*8 + int(p.peek()); p.advance()
                elif nxt == 'x':
                    wch = 0
                    for _ in range(2):
                        if p.peek():
                            d = ord(p.peek().upper()) - ord('0')
                            if d > 9: d -= 7
                            if 0 <= d <= 15:
                                wch = wch*16 + d; p.advance()
                elif nxt == 'a': wch = 7
                elif nxt == 'b': wch = 8
                elif nxt == 't': wch = 9
                elif nxt == 'n': wch = 10
                elif nxt == 'v': wch = 11
                elif nxt == 'f': wch = 12
                elif nxt == 'r': wch = 13
                buf.append(chr(wch & 0xFF))
                continue
            buf.append(ch)
    cl.lstr = ''.join(buf)
    return len(buf)


# ─────────────────────────────────────────────────────────────────────────────
# ORG — set assembly address
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_org(as_, cl, operand):
    """pseudo_parse_org: set the assembly address."""
    p = Ptr(operand)
    cl.len = 0
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD)
        return p.remaining()
    as_.reduce_expr(e)
    cl.daddr = e
    if cl.inmod == 0:
        cl.addr = e
    cl.len = 0
    return p.remaining()

def pseudo_resolve_org(as_, cl, force):
    pass

def pseudo_emit_org(as_, cl):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# EQU / SET — assign symbol value
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_equ(as_, cl, operand):
    """pseudo_parse_equ: assign a value to the line's symbol."""
    p = Ptr(operand)
    cl.len = 0
    if not cl.sym:
        as_.register_error(cl, E_SYMBOL_MISSING)
        return p.remaining()
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD)
        return p.remaining()
    as_.register_symbol(cl, cl.sym, e, symbol_flag_none)
    cl.symset = 1
    cl.dptr = as_.lookup_symbol(cl, cl.sym)
    return p.remaining()

def pseudo_resolve_equ(as_, cl, force):
    pass

def pseudo_emit_equ(as_, cl):
    pass


def pseudo_parse_set(as_, cl, operand):
    """pseudo_parse_set: SET (reassignable EQU)."""
    p = Ptr(operand)
    cl.len = 0
    if not cl.sym:
        as_.register_error(cl, E_SYMBOL_MISSING)
        return p.remaining()
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD)
        return p.remaining()
    as_.register_symbol(cl, cl.sym, e, symbol_flag_set)
    cl.symset = 1
    cl.dptr = as_.lookup_symbol(cl, cl.sym)
    return p.remaining()

def pseudo_resolve_set(as_, cl, force):
    pass

def pseudo_emit_set(as_, cl):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# END — end of assembly
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_end(as_, cl, operand):
    """pseudo_parse_end: mark end of assembly, optionally with exec address."""
    p = Ptr(operand)
    cl.len = 0

    if curpragma(cl, PRAGMA_M80EXT) and as_.input.isinclude():
        return p.remaining()   # ignore END inside includes

    as_.endseen = 1

    needs_exec = as_.output_format in (
        OUTPUT_DECB, OUTPUT_BASIC, OUTPUT_LWMOD,
        OUTPUT_IHEX, OUTPUT_SREC, OUTPUT_DRAGON, OUTPUT_ABS
    )
    if not needs_exec:
        _skip_operand(cl, p)
        return p.remaining()

    if not p.peek():
        addr = Expr.int(0)
    else:
        addr = as_.parse_expr(p)
    if not addr:
        as_.register_error(cl, E_EXPRESSION_BAD)
        addr = Expr.int(0)
    cl.save_expr(0, addr)
    return p.remaining()

def pseudo_resolve_end(as_, cl, force):
    pass

def pseudo_emit_end(as_, cl):
    if curpragma(cl, PRAGMA_M80EXT) and as_.input.isinclude():
        return
    addr = cl.fetch_expr(0)
    if addr:
        if not addr.istype(TYPE_INT):
            if as_.output_format == OUTPUT_LWMOD:
                as_.execaddr_expr = Expr.copy(addr)
            else:
                as_.register_error(cl, E_EXEC_ADDRESS)
        else:
            as_.execaddr_expr = None
            as_.execaddr = addr.intval()
    as_.endseen = 1


# ─────────────────────────────────────────────────────────────────────────────
# FCB — form constant byte(s)
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_fcb(as_, cl, operand):
    """pseudo_parse_fcb: comma-separated list of byte expressions."""
    p = Ptr(operand)
    i = 0
    while True:
        e = as_.parse_expr(p)
        if not e:
            as_.register_error2(cl, E_EXPRESSION_BAD, '(#%d)', i)
            break
        cl.save_expr(i, e)
        i += 1
        if p.peek() != ',':
            break
        p.advance()
    cl.len = i
    return p.remaining()

def pseudo_resolve_fcb(as_, cl, force):
    pass

def pseudo_emit_fcb(as_, cl):
    for i in range(cl.len):
        e = cl.fetch_expr(i)
        cl.emitexpr(e, 1)


# ─────────────────────────────────────────────────────────────────────────────
# FDB — form double byte (16-bit word)
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_fdb(as_, cl, operand):
    """pseudo_parse_fdb: comma-separated list of 16-bit word expressions."""
    p = Ptr(operand)
    i = 0
    while True:
        e = as_.parse_expr(p)
        if not e:
            as_.register_error2(cl, E_EXPRESSION_BAD, '(#%d)', i)
            break
        cl.save_expr(i, e)
        i += 1
        if p.peek() != ',':
            break
        p.advance()
    cl.len = i * 2
    return p.remaining()

def pseudo_resolve_fdb(as_, cl, force):
    pass

def pseudo_emit_fdb(as_, cl):
    for i in range(cl.len // 2):
        e = cl.fetch_expr(i)
        cl.emitexpr(e, 2)


# ─────────────────────────────────────────────────────────────────────────────
# FCC — form character constant (string)
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_fcc(as_, cl, operand):
    """pseudo_parse_fcc: delimited string, first char is delimiter."""
    p = Ptr(operand)
    if not p.peek():
        as_.register_error(cl, E_OPERAND_BAD)
        return p.remaining()
    delim = p.peek(); p.advance()
    i = _cstringlen(as_, cl, p, delim)
    if p.peek() != delim:
        as_.register_error(cl, E_OPERAND_BAD)
        return p.remaining()
    p.advance()
    cl.len = i

    # PRAGMA_M80EXT: allow FCC "Hello",13,0 trailing bytes
    if curpragma(cl, PRAGMA_M80EXT):
        if p.peek() == ',':
            p.advance()
            pseudo_parse_fcb(as_, cl, p.remaining())
            cl.fcc_extras = cl.len
            cl.len = i + cl.fcc_extras
    return p.remaining()

def pseudo_resolve_fcc(as_, cl, force):
    pass

def pseudo_emit_fcc(as_, cl):
    s = cl.lstr or ''
    for ch in s[:cl.len - cl.fcc_extras]:
        cl.emit(ord(ch) & 0xFF)
    for i in range(cl.fcc_extras):
        e = cl.fetch_expr(i)
        cl.emitexpr(e, 1)


# ─────────────────────────────────────────────────────────────────────────────
# FCS — form char string with high bit on last byte
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_fcs(as_, cl, operand):
    p = Ptr(operand)
    if not p.peek():
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    delim = p.peek(); p.advance()
    i = _cstringlen(as_, cl, p, delim)
    if p.peek() != delim:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    p.advance()
    cl.len = i
    return p.remaining()

def pseudo_resolve_fcs(as_, cl, force):
    pass

def pseudo_emit_fcs(as_, cl):
    s = cl.lstr or ''
    for ch in s[:-1]:
        cl.emit(ord(ch) & 0xFF)
    if s:
        cl.emit(ord(s[-1]) | 0x80)


# ─────────────────────────────────────────────────────────────────────────────
# FCN — form char constant with NUL terminator
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_fcn(as_, cl, operand):
    p = Ptr(operand)
    if not p.peek():
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    delim = p.peek(); p.advance()
    i = _cstringlen(as_, cl, p, delim)
    if p.peek() != delim:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    p.advance()
    cl.len = i + 1
    return p.remaining()

def pseudo_resolve_fcn(as_, cl, force):
    pass

def pseudo_emit_fcn(as_, cl):
    s = cl.lstr or ''
    for ch in s:
        cl.emit(ord(ch) & 0xFF)
    cl.emit(0)


# ─────────────────────────────────────────────────────────────────────────────
# FQB — form quad byte (32-bit)
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_fqb(as_, cl, operand):
    p = Ptr(operand)
    i = 0
    while True:
        e = as_.parse_expr(p)
        if not e:
            as_.register_error2(cl, E_EXPRESSION_BAD, '(#%d)', i); break
        cl.save_expr(i, e)
        i += 1
        if p.peek() != ',': break
        p.advance()
    cl.len = i * 4
    return p.remaining()

def pseudo_resolve_fqb(as_, cl, force):
    pass

def pseudo_emit_fqb(as_, cl):
    for i in range(cl.len // 4):
        e = cl.fetch_expr(i)
        cl.emitexpr(e, 4)


# ─────────────────────────────────────────────────────────────────────────────
# RMB — reserve memory bytes
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_rmb(as_, cl, operand):
    """pseudo_parse_rmb: reserve N bytes (no output, just advance address)."""
    p = Ptr(operand)
    expr = as_.parse_expr(p)
    if not expr:
        as_.register_error(cl, E_EXPRESSION_BAD)
    cl.lint = 0
    if not as_.instruct:
        if cl.inmod:
            cl.dlen = -1
            cl.len  = 0
    cl.save_expr(0, expr)
    return p.remaining()

def pseudo_resolve_rmb(as_, cl, force):
    if cl.lint:
        return
    if cl.inmod:
        if cl.dlen >= 0: return
    else:
        if cl.len >= 0: return

    expr = cl.fetch_expr(0)
    if expr and expr.istype(TYPE_INT):
        v = expr.intval()
        if v < 0:
            as_.register_error2(cl, E_NEGATIVE_RESERVATION, '(%d)', v)
            cl.len = cl.dlen = 0
            return
        if cl.inmod: cl.dlen = v
        else:        cl.len  = v

def pseudo_emit_rmb(as_, cl):
    if cl.lint: return
    if cl.len < 0 or cl.dlen < 0:
        as_.register_error2(cl, E_EXPRESSION_NOT_RESOLVED, '%d %d', cl.len, cl.dlen)


# ─────────────────────────────────────────────────────────────────────────────
# RMD / RMW — reserve double words (2 bytes each)
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_rmd(as_, cl, operand):
    p = Ptr(operand)
    cl.lint = 0
    expr = as_.parse_expr(p)
    if not expr:
        as_.register_error(cl, E_EXPRESSION_BAD)
    if not as_.instruct:
        if cl.inmod:
            cl.dlen = -1; cl.len = 0
    cl.save_expr(0, expr)
    return p.remaining()

def pseudo_resolve_rmd(as_, cl, force):
    if cl.lint: return
    if cl.inmod:
        if cl.dlen >= 0: return
    else:
        if cl.len >= 0: return
    expr = cl.fetch_expr(0)
    if expr and expr.istype(TYPE_INT):
        v = expr.intval()
        if v < 0:
            as_.register_error2(cl, E_NEGATIVE_RESERVATION, '(%d)', v)
            cl.len = cl.dlen = 0; return
        if cl.inmod: cl.dlen = v * 2
        else:        cl.len  = v * 2

def pseudo_emit_rmd(as_, cl):
    if cl.lint: return
    if cl.len < 0 or cl.dlen < 0:
        as_.register_error(cl, E_EXPRESSION_NOT_CONST)


# ─────────────────────────────────────────────────────────────────────────────
# ZMB / BSZ / FZB — zero memory bytes
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_zmb(as_, cl, operand):
    p = Ptr(operand)
    expr = as_.parse_expr(p)
    if not expr:
        as_.register_error(cl, E_EXPRESSION_BAD)
    cl.save_expr(0, expr)
    return p.remaining()

def pseudo_resolve_zmb(as_, cl, force):
    if cl.len >= 0: return
    expr = cl.fetch_expr(0)
    if expr and expr.istype(TYPE_INT):
        v = expr.intval()
        if v < 0:
            as_.register_error2(cl, E_NEGATIVE_BLOCKSIZE, '(%d)', v)
            cl.len = 0; return
        cl.len = v

def pseudo_emit_zmb(as_, cl):
    if cl.len < 0:
        as_.register_error(cl, E_EXPRESSION_NOT_CONST); return
    for _ in range(cl.len):
        cl.emit(0)


# ─────────────────────────────────────────────────────────────────────────────
# SETDP — set direct page register value
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_setdp(as_, cl, operand):
    p = Ptr(operand)
    cl.len = 0
    if as_.output_format == OUTPUT_OBJ:
        as_.register_error(cl, E_SETDP_INVALID); return p.remaining()
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    as_.reduce_expr(e)
    if not e.istype(TYPE_INT):
        as_.register_error(cl, E_SETDP_NOT_CONST); return p.remaining()
    cl.dpval = e.intval() & 0xFF
    cl.dshow = cl.dpval
    cl.dsize = 1
    return p.remaining()

def pseudo_resolve_setdp(as_, cl, force):
    pass

def pseudo_emit_setdp(as_, cl):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# PHASE / DEPHASE
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_phase(as_, cl, operand):
    p = Ptr(operand)
    cl.len = 0
    if cl.phase:
        as_.register_error(cl, E_NESTED_PHASE); return p.remaining()
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    as_.reduce_expr(e)
    cl.phase = e
    return p.remaining()

def pseudo_resolve_phase(as_, cl, force):
    pass

def pseudo_emit_phase(as_, cl):
    pass


def pseudo_parse_dephase(as_, cl, operand):
    cl.len = 0
    if cl.phase:
        cl.phase = None
    else:
        as_.register_error(cl, E_MISSING_PHASE)
    return operand  # nothing consumed

def pseudo_resolve_dephase(as_, cl, force):
    pass

def pseudo_emit_dephase(as_, cl):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# INCLUDE — include a source file
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_include(as_, cl, operand):
    p = Ptr(operand)
    if not p.peek():
        as_.register_error(cl, E_FILENAME_MISSING); return p.remaining()

    delim = 0
    if p.peek() in ('"', "'"):
        delim = p.peek(); p.advance()
        buf = []
        while p.peek() and p.peek() != delim:
            buf.append(p.peek()); p.advance()
        fn = ''.join(buf)
        if p.peek() == delim: p.advance()
    else:
        buf = []
        while p.peek() and not p.peek().isspace():
            buf.append(p.peek()); p.advance()
        fn = ''.join(buf)

    # Push a SETLINENO directive so line numbers resume correctly
    as_.input.open_string('INTERNAL',
                          f'\x01\x01SETLINENO {cl.lineno + 1}\n')

    as_.fileerr = 0
    try:
        as_.input.open(f'include:{fn}')
    except IOError:
        if not (as_.preprocess or (as_.flags & 0x0008)):
            as_.register_error(cl, E_FILE_OPEN)
        as_.fileerr = 1

    if as_.fileerr == 0:
        cl.hideline = 1
    cl.len = 0
    return p.remaining()

def pseudo_resolve_include(as_, cl, force):
    pass

def pseudo_emit_include(as_, cl):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# ALIGN — align to boundary
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_align(as_, cl, operand):
    p = Ptr(operand)
    if not p.peek():
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    cl.save_expr(0, e)
    if p.peek() == ',':
        p.advance()
        e2 = as_.parse_expr(p)
    else:
        e2 = Expr.int(0)
    if not e2:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    cl.save_expr(1, e2)
    return p.remaining()

def pseudo_resolve_align(as_, cl, force):
    e = cl.fetch_expr(0)
    if not e or not e.istype(TYPE_INT): return
    align = e.intval()
    if align < 1:
        as_.register_error(cl, E_EXPRESSION_BAD); return
    te = Expr.copy(cl.addr)
    as_.exportcheck = 1
    as_.reduce_expr(te)
    as_.exportcheck = 0
    if te.istype(TYPE_INT):
        a = te.intval()
        if a % align == 0:
            cl.len = 0
        else:
            cl.len = align - (a % align)

def pseudo_emit_align(as_, cl):
    if cl.csect and cl.csect.flags & (section_flag_bss | section_flag_constant):
        return
    e = cl.fetch_expr(1)
    for _ in range(cl.len):
        cl.emitexpr(e, 1)


# ─────────────────────────────────────────────────────────────────────────────
# FILL — fill N bytes with value
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_fill(as_, cl, operand):
    p = Ptr(operand)
    if not p.peek():
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    e1 = as_.parse_expr(p)
    if p.peek() != ',':
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    p.advance()
    e = as_.parse_expr(p)
    if not e:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    cl.save_expr(0, e)
    cl.save_expr(1, e1)
    if not e1:
        as_.register_error(cl, E_OPERAND_BAD)
    return p.remaining()

def pseudo_resolve_fill(as_, cl, force):
    e = cl.fetch_expr(0)
    te = Expr.copy(e)
    as_.exportcheck = 1; as_.reduce_expr(te); as_.exportcheck = 0
    if te.istype(TYPE_INT):
        v = te.intval()
        if v < 0:
            as_.register_error(cl, E_EXPRESSION_BAD); return
        cl.len = v

def pseudo_emit_fill(as_, cl):
    if cl.csect and cl.csect.flags & (section_flag_bss | section_flag_constant):
        return
    e = cl.fetch_expr(1)
    for _ in range(cl.len):
        cl.emitexpr(e, 1)


# ─────────────────────────────────────────────────────────────────────────────
# Conditional assembly
# ─────────────────────────────────────────────────────────────────────────────

def _cond_setup(as_, cl, p):
    """Common setup for IFxx directives.  Returns False if already skipping."""
    cl.len = 0; cl.hideline = 1; cl.hidecond = 1
    if as_.skipcond and not as_.skipmacro:
        as_.skipcount += 1
        _skip_operand(cl, p)
        return False
    return True

def pseudo_parse_ifeq(as_, cl, operand):
    p = Ptr(operand)
    if not _cond_setup(as_, cl, p): return p.remaining()
    e = as_.parse_cond(p)
    if e: as_.reduce_expr(e)
    if e and e.intval() != 0:
        as_.skipcond = 1; as_.skipcount = 1
    return p.remaining()

def pseudo_parse_ifne(as_, cl, operand):
    p = Ptr(operand)
    if not _cond_setup(as_, cl, p): return p.remaining()
    e = as_.parse_cond(p)
    if e: as_.reduce_expr(e)
    if e and e.intval() == 0:
        as_.skipcond = 1; as_.skipcount = 1
    return p.remaining()

def pseudo_parse_ifgt(as_, cl, operand):
    p = Ptr(operand)
    if not _cond_setup(as_, cl, p): return p.remaining()
    e = as_.parse_cond(p)
    if e: as_.reduce_expr(e)
    if e and e.intval() <= 0:
        as_.skipcond = 1; as_.skipcount = 1
    return p.remaining()

def pseudo_parse_ifge(as_, cl, operand):
    p = Ptr(operand)
    if not _cond_setup(as_, cl, p): return p.remaining()
    e = as_.parse_cond(p)
    if e: as_.reduce_expr(e)
    if e and e.intval() < 0:
        as_.skipcond = 1; as_.skipcount = 1
    return p.remaining()

def pseudo_parse_iflt(as_, cl, operand):
    p = Ptr(operand)
    if not _cond_setup(as_, cl, p): return p.remaining()
    e = as_.parse_cond(p)
    if e: as_.reduce_expr(e)
    if e and e.intval() >= 0:
        as_.skipcond = 1; as_.skipcount = 1
    return p.remaining()

def pseudo_parse_ifle(as_, cl, operand):
    p = Ptr(operand)
    if not _cond_setup(as_, cl, p): return p.remaining()
    e = as_.parse_cond(p)
    if e: as_.reduce_expr(e)
    if e and e.intval() > 0:
        as_.skipcond = 1; as_.skipcount = 1
    return p.remaining()

def pseudo_parse_ifdef(as_, cl, operand):
    p = Ptr(operand)
    cl.len = 0; cl.hideline = 1; cl.hidecond = 1
    if as_.skipcond and not as_.skipmacro:
        as_.skipcount += 1; _skip_operand(cl, p); return p.remaining()
    buf = []
    while p.peek() and not p.peek().isspace() and p.peek() not in ('|', '&'):
        buf.append(p.peek()); p.advance()
    if not buf:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    sym = ''.join(buf)
    s = as_.lookup_symbol(cl, sym)
    if not s:
        if p.peek() == '|':
            p.advance()
            return pseudo_parse_ifdef(as_, cl, p.remaining())
        as_.skipcond = 1; as_.skipcount = 1
    _skip_operand(cl, p)
    return p.remaining()

def pseudo_parse_ifndef(as_, cl, operand):
    p = Ptr(operand)
    cl.len = 0; cl.hideline = 1; cl.hidecond = 1
    if as_.skipcond and not as_.skipmacro:
        as_.skipcount += 1; _skip_operand(cl, p); return p.remaining()
    buf = []
    while p.peek() and not p.peek().isspace() and p.peek() not in ('&', '|'):
        buf.append(p.peek()); p.advance()
    if not buf:
        as_.register_error(cl, E_OPERAND_BAD); return p.remaining()
    sym = ''.join(buf)
    s = as_.lookup_symbol(cl, sym)
    if s:
        as_.skipcond = 1; as_.skipcount = 1
    return p.remaining()

def pseudo_parse_endc(as_, cl, operand):
    p = Ptr(operand)
    cl.hideline = 1; cl.hidecond = 1; cl.len = 0
    _skip_operand(cl, p)
    if as_.skipcond and not as_.skipmacro:
        as_.skipcount -= 1
        if as_.skipcount <= 0:
            as_.skipcond = 0
    return p.remaining()

def pseudo_parse_else(as_, cl, operand):
    p = Ptr(operand)
    cl.len = 0; cl.hidecond = 1; cl.hideline = 1
    _skip_operand(cl, p)
    if as_.skipmacro: return p.remaining()
    if as_.skipcond:
        if as_.skipcount == 1:
            as_.skipcount = 0; as_.skipcond = 0
        return p.remaining()
    as_.skipcond = 1; as_.skipcount = 1
    return p.remaining()

# Null resolve/emit for all conditionals
def _cond_noop(as_, cl, force=None): pass

pseudo_resolve_ifeq = pseudo_resolve_ifne = pseudo_resolve_ifgt = \
pseudo_resolve_ifge = pseudo_resolve_iflt = pseudo_resolve_ifle = \
pseudo_resolve_ifdef = pseudo_resolve_ifndef = pseudo_resolve_endc = \
pseudo_resolve_else = _cond_noop

pseudo_emit_ifeq = pseudo_emit_ifne = pseudo_emit_ifgt = \
pseudo_emit_ifge = pseudo_emit_iflt = pseudo_emit_ifle = \
pseudo_emit_ifdef = pseudo_emit_ifndef = pseudo_emit_endc = \
pseudo_emit_else = _cond_noop

# Aliases
pseudo_parse_if = pseudo_parse_ifne
pseudo_resolve_if = pseudo_resolve_ifne
pseudo_emit_if   = pseudo_emit_ifne
pseudo_parse_endif = pseudo_parse_endc
pseudo_resolve_endif = pseudo_resolve_endc
pseudo_emit_endif = pseudo_emit_endc


# ─────────────────────────────────────────────────────────────────────────────
# IFP1 / IFP2 (mostly harmless stubs)
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_ifp1(as_, cl, operand):
    p = Ptr(operand)
    cl.len = 0; cl.hideline = 1; cl.hidecond = 1
    if as_.skipcond and not as_.skipmacro:
        as_.skipcount += 1; _skip_operand(cl, p); return p.remaining()
    if not (as_.nowarn_flags & NOWARN_IFP1):
        as_.register_error2(cl, W_NOT_SUPPORTED, '%s', 'IFP1')
    return p.remaining()

pseudo_parse_ifp2 = pseudo_parse_ifp1

def pseudo_resolve_ifp1(as_, cl, force): pass
def pseudo_emit_ifp1(as_, cl): pass
pseudo_resolve_ifp2 = pseudo_resolve_ifp1
pseudo_emit_ifp2    = pseudo_emit_ifp1


# ─────────────────────────────────────────────────────────────────────────────
# ERROR / WARNING / MSG
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_error(as_, cl, operand):
    p = Ptr(operand)
    as_.register_error2(cl, E_USER_SPECIFIED, '%s', p.remaining())
    _skip_operand(cl, p)
    return p.remaining()

def pseudo_parse_warning(as_, cl, operand):
    p = Ptr(operand)
    as_.register_error2(cl, W_USER_SPECIFIED, '%s', p.remaining())
    cl.len = 0
    _skip_operand(cl, p)
    return p.remaining()

def pseudo_resolve_error(as_, cl, force): pass
def pseudo_emit_error(as_, cl): pass
pseudo_resolve_warning = pseudo_resolve_error
pseudo_emit_warning    = pseudo_emit_error


# ─────────────────────────────────────────────────────────────────────────────
# NOOP — directives that are silently ignored (NAM, PAG, etc.)
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_noop(as_, cl, operand):
    cl.len = 0
    return ''

def pseudo_resolve_noop(as_, cl, force): pass
def pseudo_emit_noop(as_, cl): pass


# ─────────────────────────────────────────────────────────────────────────────
# DTS / DTB — date/time stamps
# ─────────────────────────────────────────────────────────────────────────────

def pseudo_parse_dts(as_, cl, operand):
    p = Ptr(operand); _skip_operand(cl, p)
    t = time.ctime().rstrip('\n')
    cl.lstr = t
    cl.len  = len(t)
    return p.remaining()

def pseudo_resolve_dts(as_, cl, force): pass

def pseudo_emit_dts(as_, cl):
    for ch in (cl.lstr or '')[:cl.len]:
        cl.emit(ord(ch))


def pseudo_parse_dtb(as_, cl, operand):
    p = Ptr(operand); _skip_operand(cl, p)
    cl.len = 6
    return p.remaining()

def pseudo_resolve_dtb(as_, cl, force): pass

def pseudo_emit_dtb(as_, cl):
    t = time.localtime()
    cl.emit(t.tm_year % 256)
    cl.emit(t.tm_mon)
    cl.emit(t.tm_mday)
    cl.emit(t.tm_hour)
    cl.emit(t.tm_min)
    cl.emit(t.tm_sec)


# ─────────────────────────────────────────────────────────────────────────────
# Stubs for features deferred to later translation passes
# ─────────────────────────────────────────────────────────────────────────────

def _stub_parse(as_, cl, operand):
    """Stub for directives not yet translated."""
    cl.len = 0; return ''

def _stub_rn(as_, cl, force=None): pass

# MACRO / ENDM
def pseudo_parse_macro(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_macro(as_, cl, force):  pass
def pseudo_emit_macro(as_, cl):            pass

def pseudo_parse_endm(as_, cl, operand):   return _stub_parse(as_, cl, operand)
def pseudo_resolve_endm(as_, cl, force):   pass
def pseudo_emit_endm(as_, cl):             pass

# SECTION / ENDSECT
def pseudo_parse_section(as_, cl, operand):    return _stub_parse(as_, cl, operand)
def pseudo_resolve_section(as_, cl, force):    pass
def pseudo_emit_section(as_, cl):              pass
def pseudo_parse_endsection(as_, cl, operand): return _stub_parse(as_, cl, operand)
def pseudo_resolve_endsection(as_, cl, force): pass
def pseudo_emit_endsection(as_, cl):           pass

# STRUCT / ENDS
def pseudo_parse_struct(as_, cl, operand):    return _stub_parse(as_, cl, operand)
def pseudo_resolve_struct(as_, cl, force):    pass
def pseudo_emit_struct(as_, cl):              pass
def pseudo_parse_endstruct(as_, cl, operand): return _stub_parse(as_, cl, operand)
def pseudo_resolve_endstruct(as_, cl, force): pass
def pseudo_emit_endstruct(as_, cl):           pass

# EXTERN / EXPORT / EXTDEP
def pseudo_parse_extern(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_extern(as_, cl, force):  pass
def pseudo_emit_extern(as_, cl):            pass
def pseudo_parse_export(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_export(as_, cl, force):  pass
def pseudo_emit_export(as_, cl):            pass
def pseudo_parse_extdep(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_extdep(as_, cl, force):  pass
def pseudo_emit_extdep(as_, cl):            pass

# PRAGMA and friends
def pseudo_parse_pragma(as_, cl, operand):         return _stub_parse(as_, cl, operand)
def pseudo_resolve_pragma(as_, cl, force):         pass
def pseudo_emit_pragma(as_, cl):                   pass
def pseudo_parse_starpragma(as_, cl, operand):     return _stub_parse(as_, cl, operand)
def pseudo_resolve_starpragma(as_, cl, force):     pass
def pseudo_emit_starpragma(as_, cl):               pass
def pseudo_parse_starpragmapush(as_, cl, operand): return _stub_parse(as_, cl, operand)
def pseudo_resolve_starpragmapush(as_, cl, force): pass
def pseudo_emit_starpragmapush(as_, cl):           pass
def pseudo_parse_starpragmapop(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_starpragmapop(as_, cl, force):  pass
def pseudo_emit_starpragmapop(as_, cl):            pass

# REORG
def pseudo_parse_reorg(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_reorg(as_, cl, force):  pass
def pseudo_emit_reorg(as_, cl):            pass

# OS9 specific
def pseudo_parse_os9(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_os9(as_, cl, force):  pass
def pseudo_emit_os9(as_, cl):            pass
def pseudo_parse_mod(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_mod(as_, cl, force):  pass
def pseudo_emit_mod(as_, cl):            pass
def pseudo_parse_emod(as_, cl, operand): return _stub_parse(as_, cl, operand)
def pseudo_resolve_emod(as_, cl, force): pass
def pseudo_emit_emod(as_, cl):           pass

# INCLUDEBIN / INCLUDESTR
def pseudo_parse_includebin(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_includebin(as_, cl, force):  pass
def pseudo_emit_includebin(as_, cl):            pass
def pseudo_parse_includestr(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_includestr(as_, cl, force):  pass
def pseudo_emit_includestr(as_, cl):            pass

# SETSTR
def pseudo_parse_setstr(as_, cl, operand):  return _stub_parse(as_, cl, operand)
def pseudo_resolve_setstr(as_, cl, force):  pass
def pseudo_emit_setstr(as_, cl):            pass

# IFPRAGMA / IFSTR
def pseudo_parse_ifpragma(as_, cl, operand): return _stub_parse(as_, cl, operand)
def pseudo_resolve_ifpragma(as_, cl, force): pass
def pseudo_emit_ifpragma(as_, cl):           pass
def pseudo_parse_ifstr(as_, cl, operand):    return _stub_parse(as_, cl, operand)
def pseudo_resolve_ifstr(as_, cl, force):    pass
def pseudo_emit_ifstr(as_, cl):              pass

# FDBS — little-endian FDB (byte-swapped)
def pseudo_parse_fdbs(as_, cl, operand):
    return pseudo_parse_fdb(as_, cl, operand)  # same parse as FDB

def pseudo_resolve_fdbs(as_, cl, force): pass

def pseudo_emit_fdbs(as_, cl):
    for i in range(cl.len // 2):
        e = cl.fetch_expr(i)
        # emit high byte then low byte (swapped from FDB)
        te = Expr.oper(OPER_DIVIDE, e, Expr.int(256))
        as_.reduce_expr(te)
        cl.emitexpr(e, 1)    # low byte first
        cl.emitexpr(te, 1)   # high byte second (te = e / 256)
