"""
cocotools/listing.py — Listing and symbol dump generation
Faithful Python translation of lwasm/list.c and lwasm/symdump.c
(William Astle, LWTools, GPL v3)
Source: http://lwtools.projects.l-w.ca/

do_list(as_, file=None)     — generate assembly listing
do_symdump(as_, file=None)  — dump symbol table in assembly format
list_symbols(as_, f)        — append symbol table to an open listing file
"""

import sys

from .lwasm_types import (
    FLAG_LIST, FLAG_SYMBOLS, FLAG_SYMBOLS_NOLOCALS, FLAG_SYMDUMP,
    symbol_flag_nolist, symbol_flag_set,
    OUTPUT_OBJ,
    PRAGMA_NOLIST, PRAGMA_NOLISTCODE, PRAGMA_NOEXPANDCOND,
    PRAGMA_C, PRAGMA_CD, PRAGMA_CC, PRAGMA_CT,
)
from .lw_expr import TYPE_INT
from .lwasm_core import curpragma


# ─────────────────────────────────────────────────────────────────────────────
# do_list  (list.c: do_list)
# ─────────────────────────────────────────────────────────────────────────────

def do_list(as_, output_path=None):
    """
    do_list(as, output_path=None):
    Generate assembly listing.  If output_path is None or '-', write to stdout.
    """
    if not (as_.flags & FLAG_LIST):
        return

    if output_path and output_path != '-':
        try:
            of = open(output_path, 'w', encoding='utf-8', errors='replace')
            close_after = True
        except OSError:
            print("Cannot open list file; list not generated", file=sys.stderr)
            return
    else:
        of = sys.stdout
        close_after = False

    try:
        _do_list_inner(as_, of)
    finally:
        if close_after:
            of.close()


def _do_list_inner(as_, of):
    from .instab import INSTAB
    from .lw_expr import Expr

    cl = as_.line_head
    while cl:
        nl = cl.next

        if curpragma(cl, PRAGMA_NOLISTCODE):
            cl = nl; continue

        if curpragma(cl, PRAGMA_NOLIST):
            if cl.outputl <= 0:
                cl = nl; continue

        # Collect output bytes
        if cl.noexpand_start:
            obytes = bytearray()
            nc = 0
            scan = cl
            while scan:
                if scan.noexpand_start:
                    nc += scan.noexpand_start
                if scan.noexpand_end:
                    nc -= scan.noexpand_end
                if scan.outputl > 0:
                    obytes.extend(scan.output[:scan.outputl])
                # warnings
                if scan.warn:
                    e = scan.warn
                    while e:
                        if of != sys.stdout:
                            print(f"Warning ({cl.linespec}:{cl.lineno}): {e.mess}")
                        print(f"Warning: {e.mess}", file=of)
                        e = e.next
                if nc == 0:
                    nl = scan.next
                    break
                scan = scan.next
        else:
            # warnings
            if cl.warn:
                e = cl.warn
                while e:
                    if of != sys.stdout:
                        print(f"Warning ({cl.linespec}:{cl.lineno}): {e.mess}")
                    print(f"Warning: {e.mess}", file=of)
                    e = e.next
            obytes = bytearray(cl.output[:cl.outputl]) if cl.outputl > 0 else bytearray()

        obytelen = len(obytes)

        if cl.hidecond and curpragma(cl, PRAGMA_NOEXPANDCOND):
            cl = nl; continue

        # Determine whether to show address
        no_output = (cl.len < 1 and cl.dlen < 1) and obytelen < 1 and \
                    (cl.symset == 1 or cl.sym is None)

        if no_output:
            if cl.soff >= 0:
                print(f"{cl.soff & 0xffff:04X}s                 ", end='', file=of)
            elif cl.dshow >= 0:
                if cl.dsize == 1:
                    print(f"     {cl.dshow & 0xff:02X}               ", end='', file=of)
                else:
                    print(f"     {cl.dshow & 0xffff:04X}             ", end='', file=of)
            elif cl.dptr:
                te = cl.dptr.value
                as_.reduce_expr(te)
                if te and te.istype(TYPE_INT):
                    print(f"     {te.intval() & 0xffff:04X}             ", end='', file=of)
                else:
                    print(f"     ????             ", end='', file=of)
            else:
                print(f"                      ", end='', file=of)
        else:
            # Show address
            ie = INSTAB[cl.insn] if (cl.insn >= 0 and cl.insn < len(INSTAB)) else None
            from .lwasm_types import lwasm_insn_setdata
            use_daddr = ie and (ie.flags & lwasm_insn_setdata)
            te_expr = cl.daddr if use_daddr else cl.addr

            te = Expr.copy(te_expr)
            as_.exportcheck = 1
            as_.csect = cl.csect
            as_.reduce_expr(te)
            as_.exportcheck = 0

            addr_val = te.intval() & 0xffff if te.istype(TYPE_INT) else 0
            sep = '.' if (cl.inmod or (cl.dlen != cl.len)) and use_daddr else ' '
            print(f"{addr_val:04X}{sep}", end='', file=of)

            # Up to 8 bytes
            for i in range(min(obytelen, 8)):
                print(f"{obytes[i]:02X}", end='', file=of)
            for _ in range(min(obytelen, 8), 8):
                print("  ", end='', file=of)
            print(" ", end='', file=of)

        # File/line spec
        MAX_LINESPEC = 17
        if as_.listnofile:
            print(f"{cl.lineno:05d} ", end='', file=of)
        else:
            linespec = cl.linespec or ''
            # trim "include:" prefix
            if len(linespec) > 8 and linespec[7] == ':':
                linespec = linespec[8:]
            if len(linespec) > MAX_LINESPEC:
                linespec = linespec[len(linespec) - MAX_LINESPEC:]
            while linespec.startswith(' '):
                linespec = linespec[1:]
            print(f"({linespec:{MAX_LINESPEC}s}):{cl.lineno:05d} ", end='', file=of)

        # Cycle counts (stubs — pragma_c/cd support is not yet wired)
        print("        ", end='', file=of)  # 8 chars for cycle placeholder

        # Source text with optional tab expansion
        text = cl.ltext or ''
        if as_.tabwidth == 0:
            print(text, file=of)
        else:
            out = []
            col = 0
            for ch in text:
                if ch == '\t':
                    out.append(' ')
                    col += 1
                    while col % as_.tabwidth:
                        out.append(' ')
                        col += 1
                else:
                    out.append(ch)
                    col += 1
            print(''.join(out), file=of)

        # Continuation bytes (beyond 8)
        if obytelen > 8:
            for i in range(8, obytelen):
                if i % 8 == 0:
                    if i != 8:
                        print(f"\n     ", end='', file=of)
                    else:
                        print(f"     ", end='', file=of)
                print(f"{obytes[i]:02X}", end='', file=of)
            if obytelen > 8:
                print('', file=of)

        cl = nl

    # Append symbol table if -s flag set
    if (as_.flags & FLAG_SYMBOLS) and of:
        list_symbols(as_, of)


# ─────────────────────────────────────────────────────────────────────────────
# list_symbols  (symbol.c: list_symbols / list_symbols_aux)
# ─────────────────────────────────────────────────────────────────────────────

def list_symbols(as_, of):
    """Append symbol table to an open listing file."""
    print("\nSymbol Table:", file=of)
    _list_symbols_aux(as_, of, as_.symtab.head)


def _list_symbols_aux(as_, of, se):
    if not se:
        return

    _list_symbols_aux(as_, of, se.left)

    s = se
    while s:
        if not (s.flags & symbol_flag_nolist):
            if not ((as_.flags & FLAG_SYMBOLS_NOLOCALS) and s.context >= 0):
                as_.reduce_expr(s.value)

                # Flags: [SxG] or [S G] etc.
                flag_s = 'S' if (s.flags & symbol_flag_set) else ' '
                flag_g = 'G' if s.context < 0 else 'L'
                if as_.output_format == OUTPUT_OBJ:
                    flag_t = 'c' if (s.value and s.value.istype(TYPE_INT)) else 's'
                    print(f"[{flag_s}{flag_t}{flag_g}] {s.symbol:<32} ", end='', file=of)
                else:
                    print(f"[{flag_s}{flag_g}] {s.symbol:<32} ", end='', file=of)

                te = Expr.copy(s.value) if s.value else None
                if te:
                    as_.reduce_expr(te)
                    if te.istype(TYPE_INT):
                        print(f"{te.intval() & 0xffff:04X}", file=of)
                    else:
                        print("<<incomplete>>", file=of)
                else:
                    print("<<incomplete>>", file=of)

        s = s.nextver

    _list_symbols_aux(as_, of, se.right)


# ─────────────────────────────────────────────────────────────────────────────
# do_symdump  (symdump.c: do_symdump / dump_symbols_aux)
# ─────────────────────────────────────────────────────────────────────────────

def do_symdump(as_, output_path=None):
    """
    do_symdump(as, output_path=None):
    Dump global symbol table in assembly format (SYM EQU $VALUE).
    If output_path is None or '-', write to stdout.
    """
    if not (as_.flags & FLAG_SYMDUMP):
        return

    if output_path and output_path != '-':
        try:
            of = open(output_path, 'w', encoding='utf-8', errors='replace')
            close_after = True
        except OSError:
            print("Cannot open symbol dump file", file=sys.stderr)
            return
    else:
        of = sys.stdout
        close_after = False

    try:
        _dump_symbols_aux(as_, of, as_.symtab.head)
    finally:
        if close_after:
            of.close()


def _dump_symbols_aux(as_, of, se):
    if not se:
        return

    from .lw_expr import Expr

    _dump_symbols_aux(as_, of, se.left)

    s = se
    while s:
        if not (s.flags & symbol_flag_nolist) and s.context < 0:
            as_.reduce_expr(s.value)
            directive = 'SET' if (s.flags & symbol_flag_set) else 'EQU'

            te = Expr.copy(s.value) if s.value else None
            if te:
                as_.reduce_expr(te)
                if te.istype(TYPE_INT):
                    print(f"{s.symbol} {directive} ${te.intval() & 0xffff:04X}", file=of)
                else:
                    print(f"{s.symbol} {directive} 0 ; <<incomplete>>", file=of)
            else:
                print(f"{s.symbol} {directive} 0 ; <<incomplete>>", file=of)

        s = s.nextver

    _dump_symbols_aux(as_, of, se.right)


# Lazy import to avoid circular dependency
try:
    from .lw_expr import Expr
except ImportError:
    pass
