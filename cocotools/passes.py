"""
cocotools/passes.py — Assembly passes 2 through 7 and output
Faithful Python translation of lwasm/pass2.c - pass7.c and output.c
(William Astle, LWTools, GPL v3)
Source: http://lwtools.projects.l-w.ca/

Pass overview:
  pass2 — reduce all expressions; enable undefined-symbol errors
  pass3 — repeatedly call resolve(force=0) until nothing more changes
  pass4 — force-resolve remaining unresolved instructions (resolve(force=1))
  pass5 — ensure all line addresses are fully resolved integers
  pass6 — final expression reduction; flag any remaining unresolved exprs
  pass7 — emit bytes by calling each instruction's emit function
  output — write DECB .BIN file from collected line output buffers
"""

import io

from .lwasm_types import (
    OUTPUT_OBJ, OUTPUT_LWMOD, OUTPUT_DECB, OUTPUT_RAW, OUTPUT_RAWREL,
    E_LINE_ADDRESS, E_LINED_ADDRESS, E_EXPRESSION_BAD, E_INSTRUCTION_FAILED,
    E_SYMBOL_UNDEFINED_EXPORT,
    PRAGMA_TESTMODE,
    lwasm_expr_secbase, lwasm_expr_syment, lwasm_expr_import,
)
from .lw_expr import Expr, TYPE_INT, TYPE_OPER, TYPE_SPECIAL
from .lwasm_core import curpragma


# ─────────────────────────────────────────────────────────────────────────────
# Expression OK helpers  (exprok_aux / exprok in pass5.c and pass6.c)
# ─────────────────────────────────────────────────────────────────────────────

def _exprok_aux_p5(e, as_):
    """pass5 exprok_aux: returns True if the term is NOT OK (still unresolved)."""
    if e.istype(TYPE_INT):
        return False
    if e.istype(TYPE_OPER):
        return False
    if e.istype(TYPE_SPECIAL) and as_.output_format in (OUTPUT_OBJ, OUTPUT_LWMOD):
        if e.specint() == lwasm_expr_secbase:
            return False
    return True   # not OK — still unresolved


def _exprok_p5(as_, e):
    """pass5 exprok: True if expression is fully resolved (no unresolved terms)."""
    if e is None:
        return True
    return not e.testterms(lambda n: _exprok_aux_p5(n, as_))


def _exprok_aux_p6(e, as_):
    """pass6 exprok_aux: slightly wider acceptance for OBJ/LWMOD."""
    if e.istype(TYPE_INT):
        return False
    if as_.output_format in (OUTPUT_OBJ, OUTPUT_LWMOD):
        if e.istype(TYPE_OPER):
            return False
        if e.istype(TYPE_SPECIAL):
            t = e.specint()
            if t in (lwasm_expr_secbase, lwasm_expr_syment, lwasm_expr_import):
                return False
    return True


def _exprok_p6(as_, e):
    """pass6 exprok."""
    if e is None:
        return True
    return not e.testterms(lambda n: _exprok_aux_p6(n, as_))


# ─────────────────────────────────────────────────────────────────────────────
# pass2 — reduce expressions; enable badsymerr
# ─────────────────────────────────────────────────────────────────────────────

def do_pass2(as_):
    """
    do_pass2(as):
    Verify export list (for OBJ target), then do one reduction pass on every
    expression.  Sets badsymerr=1 so that undefined symbol references produce
    errors from this pass onward.
    """
    # Verify export list (OBJ target only)
    if as_.output_format == OUTPUT_OBJ:
        from .lwasm_types import PRAGMA_IMPORTUNDEFEXPORT
        from .lwasm_types import ImportListEntry
        ex = as_.exportlist
        while ex:
            s = as_.lookup_symbol(None, ex.symbol)
            if not s:
                if curpragma(ex.line, PRAGMA_IMPORTUNDEFEXPORT):
                    # auto-import the symbol
                    im = as_.importlist
                    while im:
                        if im.symbol == ex.symbol:
                            break
                        im = im.next
                    if not im:
                        from .lwasm_types import ImportListEntry
                        ni       = ImportListEntry(ex.symbol)
                        ni.next  = as_.importlist
                        as_.importlist = ni
                else:
                    as_.register_error(ex.line, E_SYMBOL_UNDEFINED_EXPORT)
            ex.se = s
            ex = ex.next
        if as_.errorcount > 0:
            return

    as_.badsymerr = 1

    cl = as_.line_head
    while cl:
        as_.cl = cl
        as_.reduce_expr(cl.addr)
        as_.reduce_expr(cl.daddr)
        le = cl.exprs
        while le:
            as_.reduce_expr(le.expr)
            le = le.next
        cl = cl.next


# ─────────────────────────────────────────────────────────────────────────────
# pass3 — resolve instruction sizes (non-forced, loop until stable)
# ─────────────────────────────────────────────────────────────────────────────

def do_pass3(as_):
    """
    do_pass3(as):
    Repeatedly reduce expressions and call resolve(force=0) on instructions
    with unknown length, until no further progress is made.
    """
    from .instab import INSTAB

    while True:
        rc = 0
        cl = as_.line_head
        while cl:
            as_.cl = cl
            as_.reduce_expr(cl.addr)
            as_.reduce_expr(cl.daddr)

            le = cl.exprs
            while le:
                as_.reduce_expr(le.expr)
                le = le.next

            if cl.len == -1 or cl.dlen == -1:
                if cl.insn >= 0 and cl.insn < len(INSTAB):
                    ie = INSTAB[cl.insn]
                    if ie.resolve:
                        ie.resolve(as_, cl, 0)
                        # Synchronise len/dlen
                        if cl.inmod == 0 and cl.len >= 0 and cl.dlen >= 0:
                            if cl.len == 0:
                                cl.len  = cl.dlen
                            else:
                                cl.dlen = cl.len
                        if cl.len != -1 and cl.dlen != -1:
                            rc += 1

            cl = cl.next

        if as_.errorcount > 0:
            return
        if rc == 0:
            break


# ─────────────────────────────────────────────────────────────────────────────
# pass4 — force-resolve remaining unresolved instructions
# ─────────────────────────────────────────────────────────────────────────────

def _do_pass4_aux(as_, force):
    """
    do_pass4_aux(as, force):
    Find each unresolved instruction and try to resolve it, reducing the
    surrounding expression context.  If force=1 and nothing resolves, error.
    """
    from .instab import INSTAB

    # Count unresolved
    cnt = sum(1 for cl in _line_iter(as_) if cl.len == -1)
    if cnt == 0:
        return

    sl = as_.line_head
    while cnt > 0:
        trycount = cnt

        # Advance sl to next unresolved instruction
        while sl and sl.len != -1:
            as_.cl = sl
            as_.reduce_expr(sl.addr)
            as_.reduce_expr(sl.daddr)
            le = sl.exprs
            while le:
                as_.reduce_expr(le.expr)
                le = le.next
            sl = sl.next

        if sl is None:
            break

        # Reduce expressions on sl
        as_.cl = sl
        as_.reduce_expr(sl.addr)
        as_.reduce_expr(sl.daddr)
        le = sl.exprs
        while le:
            as_.reduce_expr(le.expr)
            le = le.next

        # Try to resolve sl
        if sl.len == -1 and sl.insn >= 0 and sl.insn < len(INSTAB):
            ie = INSTAB[sl.insn]
            if ie.resolve:
                ie.resolve(as_, sl, 1)
                if force and sl.len == -1 and sl.dlen == -1:
                    as_.register_error(sl, E_INSTRUCTION_FAILED)
                    return

        if sl.len != -1 and sl.dlen != -1:
            cnt -= 1
            if cnt == 0:
                return
            continue   # this one resolved; keep scanning forward

        # Flatten remaining lines after sl
        while True:
            rc = 0
            cl = sl
            while cl:
                as_.cl = cl
                as_.reduce_expr(cl.addr)
                as_.reduce_expr(cl.daddr)
                le = cl.exprs
                while le:
                    as_.reduce_expr(le.expr)
                    le = le.next

                if cl.len == -1:
                    if cl.insn >= 0 and cl.insn < len(INSTAB):
                        ie = INSTAB[cl.insn]
                        if ie.resolve:
                            ie.resolve(as_, cl, 0)
                            if cl.inmod == 0 and cl.len >= 0 and cl.dlen >= 0:
                                if cl.len == 0:
                                    cl.len  = cl.dlen
                                else:
                                    cl.dlen = cl.len
                            if cl.len != -1 and cl.dlen != -1:
                                rc  += 1
                                cnt -= 1
                                if cnt == 0:
                                    return
                cl = cl.next

            if as_.errorcount > 0:
                return
            if rc == 0:
                break

        if trycount == cnt:
            break   # no progress — give up


def do_pass4(as_):
    """do_pass4(as): force-resolve all remaining unresolved instructions."""
    _do_pass4_aux(as_, 1)


# ─────────────────────────────────────────────────────────────────────────────
# pass5 — ensure all line addresses are resolved integers
# ─────────────────────────────────────────────────────────────────────────────

def do_pass5(as_):
    """
    do_pass5(as):
    Count lines with non-integer addresses, then repeatedly reduce until
    all addresses are fully constant.  Report errors for any that remain.
    """
    # Initial count
    cnt = 0
    cl = as_.line_head
    while cl:
        as_.cl = cl
        as_.reduce_expr(cl.addr)
        if not _exprok_p5(as_, cl.addr):
            cnt += 1
        as_.reduce_expr(cl.daddr)
        if not _exprok_p5(as_, cl.daddr):
            cnt += 1
        cl = cl.next

    sl = as_.line_head
    while cnt > 0:
        ocnt = cnt

        # Advance to first unresolved address
        while sl and _exprok_p5(as_, sl.addr) and _exprok_p5(as_, sl.daddr):
            sl = sl.next

        if sl is None:
            break

        # Reduce from sl onward
        cl = sl
        while cl:
            as_.cl = sl
            as_.reduce_expr(sl.addr)
            if _exprok_p5(as_, cl.addr):
                cnt -= 1
                if cnt == 0:
                    return
            as_.reduce_expr(sl.daddr)
            if _exprok_p5(as_, cl.daddr):
                cnt -= 1
                if cnt == 0:
                    return
            cl = cl.next

        if cnt == ocnt:
            break   # no progress

    # Flag any remaining unresolved addresses
    if cnt:
        cl = sl
        while cl:
            if not _exprok_p5(as_, cl.addr):
                as_.register_error(cl, E_LINE_ADDRESS)
            if not _exprok_p5(as_, cl.daddr):
                as_.register_error(cl, E_LINED_ADDRESS)
            cl = cl.next


# ─────────────────────────────────────────────────────────────────────────────
# pass6 — final expression reduction; flag unresolved
# ─────────────────────────────────────────────────────────────────────────────

def do_pass6(as_):
    """
    do_pass6(as):
    One final reduction pass.  Everything should reduce now that addresses are
    constant.  Flag any expression that still cannot be fully resolved.
    """
    cl = as_.line_head
    while cl:
        as_.cl = cl
        le = cl.exprs
        while le:
            as_.reduce_expr(le.expr)
            if not _exprok_p6(as_, le.expr):
                try:
                    expr_str = str(le.expr)
                except Exception:
                    expr_str = '?'
                as_.register_error2(cl, E_EXPRESSION_BAD, '%s', expr_str)
            le = le.next
        cl = cl.next


# ─────────────────────────────────────────────────────────────────────────────
# pass7 — emit bytes
# ─────────────────────────────────────────────────────────────────────────────

def do_pass7(as_):
    """
    do_pass7(as):
    Walk every line and call its emit function.  Collect the bytes into
    cl.output / cl.outputl.
    """
    from .instab import INSTAB

    cl = as_.line_head
    while cl:
        as_.cl = cl
        if cl.insn >= 0 and cl.insn < len(INSTAB):
            ie = INSTAB[cl.insn]
            if ie.emit:
                ie.emit(as_, cl)
        cl = cl.next


# ─────────────────────────────────────────────────────────────────────────────
# output — write .BIN (DECB format)
# ─────────────────────────────────────────────────────────────────────────────

def do_output(as_, output_path):
    """
    do_output(as, output_path):
    Write the assembled output to output_path.  Only DECB and RAW formats
    are implemented here; other formats raise NotImplementedError.

    DECB .BIN format:
      For each contiguous block:
        0x00  [preamble marker]
        hi(len) lo(len)
        hi(addr) lo(addr)
        [len bytes of data]
      Postamble:
        0xFF 0x00 0x00 hi(exec) lo(exec)
    """
    if as_.errorcount > 0:
        import sys
        print("Not doing output due to assembly errors.", file=sys.stderr)
        return

    if as_.output_format == OUTPUT_DECB:
        data = _collect_decb(as_)
    elif as_.output_format == OUTPUT_RAW:
        data = _collect_raw(as_)
    else:
        raise NotImplementedError(
            f"Output format {as_.output_format} not yet implemented")

    with open(output_path, 'wb') as f:
        f.write(data)


def collect_decb_bytes(as_):
    """
    Public helper: return DECB-format bytes as a bytes object.
    Used by cocotools.py CLI and tests.
    """
    return bytes(_collect_decb(as_))


def _collect_decb(as_):
    """
    write_code_decb(as, of) — translated to return bytearray.
    """
    buf       = bytearray()
    blocklen  = -1
    nextcalc  = -1
    preambloc = -1   # byte offset in buf where the 2-byte length lives

    cl = as_.line_head
    while cl:
        if cl.outputl < 0:
            cl = cl.next
            continue

        if not cl.addr.istype(TYPE_INT):
            cl = cl.next
            continue

        caddr = cl.addr.intval()

        if caddr != nextcalc and cl.outputl > 0:
            # Need a new preamble record
            if blocklen > 0:
                # Patch the length of the previous block
                buf[preambloc]   = (blocklen >> 8) & 0xFF
                buf[preambloc+1] =  blocklen       & 0xFF

            blocklen  = 0
            nextcalc  = caddr
            preambloc = len(buf) + 1   # +1: skip the 0x00 preamble byte

            buf.append(0x00)                           # preamble marker
            buf.append(0x00); buf.append(0x00)         # length placeholder
            buf.append((nextcalc >> 8) & 0xFF)
            buf.append(nextcalc        & 0xFF)

        nextcalc += cl.outputl
        buf.extend(cl.output[:cl.outputl])
        blocklen += cl.outputl

        cl = cl.next

    # Patch the last block's length
    if blocklen > 0:
        buf[preambloc]   = (blocklen >> 8) & 0xFF
        buf[preambloc+1] =  blocklen       & 0xFF

    # Postamble
    exec_addr = as_.execaddr
    buf.append(0xFF)
    buf.append(0x00); buf.append(0x00)
    buf.append((exec_addr >> 8) & 0xFF)
    buf.append( exec_addr       & 0xFF)

    return buf


def _collect_raw(as_):
    """write_code_raw: flat byte stream, gaps filled with zeros."""
    if not as_.line_head:
        return bytearray()

    # Find the range of addresses
    start = None; end = 0
    cl = as_.line_head
    while cl:
        if cl.outputl > 0 and cl.addr.istype(TYPE_INT):
            a = cl.addr.intval()
            if start is None: start = a
            end = max(end, a + cl.outputl)
        cl = cl.next

    if start is None:
        return bytearray()

    buf = bytearray(end - start)
    cl  = as_.line_head
    while cl:
        if cl.outputl > 0 and cl.addr.istype(TYPE_INT):
            a = cl.addr.intval() - start
            buf[a:a+cl.outputl] = cl.output[:cl.outputl]
        cl = cl.next

    return buf


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: run all passes in order
# ─────────────────────────────────────────────────────────────────────────────

def assemble(as_, output_path=None):
    """
    Run passes 2–7 then optionally write output.
    Returns as_.errorcount (0 = success).
    """
    do_pass2(as_)
    if as_.errorcount: return as_.errorcount
    do_pass3(as_)
    if as_.errorcount: return as_.errorcount
    do_pass4(as_)
    if as_.errorcount: return as_.errorcount
    do_pass5(as_)
    if as_.errorcount: return as_.errorcount
    do_pass6(as_)
    if as_.errorcount: return as_.errorcount
    do_pass7(as_)
    if output_path:
        do_output(as_, output_path)
    return as_.errorcount


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _line_iter(as_):
    cl = as_.line_head
    while cl:
        yield cl
        cl = cl.next
