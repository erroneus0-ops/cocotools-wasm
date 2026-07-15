"""
cocotools/source_diag.py -- Source-level diagnostic analysis pass

Reads 6809 assembly source text and detects patterns that are syntactically
valid and accepted by lwasm but produce undefined or unportable behavior on
real 6809/6309 hardware.

ARCHITECTURE:
This module operates on SOURCE TEXT only. It never touches the lwasm
translation layer (lwasm.py, insn_funcs.py, lwasm_core.py, passes.py).
The lwasm translation remains a faithful reproduction of lwasm behavior.
This is a separate pass that runs alongside it.

Usage:
    from cocotools.source_diag import analyze_source
    log = analyze_source(source_text, filename='myfile.asm')
    log.report()

Or from the command line via cocotools.py --diag myfile.asm
"""

import re
from .diagnostics import (
    DiagnosticLog,
    W_UNDEFINED_PREDEC1_SU,
    W_CC_CLOBBERED_BEFORE_BRANCH,
    CC_SETTING_COMPARE,
    CC_CLOBBERING_LOADS,
    CC_NEUTRAL,
    CONDITIONAL_BRANCHES,
)

# Suppression marker pattern -- (!WNNNN) in a comment suppresses that warning
import re as _re
_SUPPRESS_RE = _re.compile(r'[(][!]W([0-9]+)[)]')

def _is_suppressed(line_text, warning_code):
    """Return True if the line contains (!WNNNN) matching the warning code."""
    for m in _SUPPRESS_RE.finditer(line_text):
        if int(m.group(1)) == warning_code:
            return True
    return False

# ── Tokenizer ──────────────────────────────────────────────────────────────────

# Match an assembly source line:
#   optional label, optional mnemonic, optional operand, optional comment
_LINE_RE = re.compile(
    r'^'
    r'(?P<label>[A-Za-z_][A-Za-z0-9_@.]*)?'   # optional label
    r'\s*'
    r'(?P<mnemonic>[A-Za-z][A-Za-z0-9]*)?'     # optional mnemonic
    r'\s*'
    r'(?P<operand>[^;*\n]*?)?'                  # optional operand (stop at ; or *)
    r'\s*'
    r'(?:[;*].*)?$'                             # optional comment
)

# Indirect pre-decrement on S or U: [,-S] or [,-U]
# Also catches [,--S] [,--U] (double decrement indirect, also problematic)
_INDIRECT_PREDEC_SU = re.compile(
    r'\[\s*,\s*-{1,2}\s*([SsUu])\s*\]'
)

# Direct pre-decrement on S or U: ,-S or ,-U (valid but flag for awareness)
# William Astle confirmed: direct form IS valid. We note but don't warn.
_DIRECT_PREDEC_SU = re.compile(
    r'(?<!\[)\s*,\s*-{1,2}\s*([SsUu])(?!\s*\])'
)


def _parse_line(line):
    """Parse one assembly source line.
    Returns (label, mnemonic, operand) strings, all possibly empty.
    Strips inline comments.
    """
    # Strip full-line comments (* in column 1, or ; anywhere)
    stripped = line.rstrip()
    if stripped.lstrip().startswith('*') or stripped.lstrip().startswith(';'):
        return ('', '', '')
    m = _LINE_RE.match(stripped)
    if not m:
        return ('', '', '')
    label    = (m.group('label')    or '').strip()
    mnemonic = (m.group('mnemonic') or '').strip().upper()
    operand  = (m.group('operand')  or '').strip()
    return (label, mnemonic, operand)


# ── Diagnostic checks ──────────────────────────────────────────────────────────

def _check_indirect_predec_su(line_num, mnemonic, operand, log, filename):
    """W2000: [,-S] or [,-U] -- indirect pre-decrement on S/U.
    Direct form ,-S is valid. Indirect form [,-S] is undefined by Motorola,
    absent on 6309.
    """
    m = _INDIRECT_PREDEC_SU.search(operand)
    if m:
        reg = m.group(1).upper()
        log.warn(line_num, filename, W_UNDEFINED_PREDEC1_SU, reg=reg)


def _check_cc_clobber_backward(branch_idx, instructions, raw_lines, log, filename):
    """W2001: Backward scan from a conditional branch.

    From the branch, scan backward through preceding instructions:
    - CC-neutral instruction (STA, PSHS, NOP, etc.) -- continue scanning
    - CC_SETTING_COMPARE instruction -- clean, stop (programmer intended this)
    - CC_CLOBBERING_LOAD instruction -- W2001, unless suppressed
    - Unconditional transfer (BRA, JMP, label boundary) -- stop, unknown state

    Suppression: if the clobbering instruction's line contains (!W2001),
    the warning is suppressed.
    """
    branch_ln, branch_mn, branch_op = instructions[branch_idx]

    for back in range(1, branch_idx + 1):
        idx = branch_idx - back
        line_num, mn, op = instructions[idx]
        mn_upper = mn.upper()

        if mn_upper in CC_SETTING_COMPARE:
            # Programmer set CC intentionally -- clean
            return

        if mn_upper in CC_CLOBBERING_LOADS:
            # Found a load before the branch.
            # Only warn if there was a prior explicit compare/test before
            # this load -- otherwise the load itself is the intended CC setter
            # (e.g. LDA ,X+ / BEQ -- canonical null-terminated string loop).
            compare_mn = None
            for back2 in range(1, idx + 1):
                prev_mn = instructions[idx - back2][1].upper()
                if prev_mn in CC_SETTING_COMPARE:
                    compare_mn = prev_mn
                    break
                if prev_mn not in CC_NEUTRAL and prev_mn not in CC_CLOBBERING_LOADS:
                    break
            if compare_mn is None:
                # No prior compare found -- load is the intended CC setter
                return
            # Prior compare exists and load clobbered it -- W2001
            raw_line = raw_lines[line_num - 1] if line_num <= len(raw_lines) else ''
            if _is_suppressed(raw_line, W_CC_CLOBBERED_BEFORE_BRANCH):
                return
            log.warn(line_num, filename, W_CC_CLOBBERED_BEFORE_BRANCH,
                     insn=mn_upper, compare=compare_mn, branch=branch_mn)
            return

        if mn_upper in CC_NEUTRAL:
            # Transparent -- keep scanning
            continue

        # Anything else (unconditional branch, unknown) -- stop
        return


# ── Main analyzer ──────────────────────────────────────────────────────────────

def analyze_source(source, filename=None):
    """Analyze 6809 assembly source text for diagnostic issues.

    Args:
        source   (str): Assembly source text.
        filename (str): Optional filename for warning messages.

    Returns:
        DiagnosticLog: accumulated warnings (may be empty).
    """
    log = DiagnosticLog()
    lines = source.splitlines()

    # Build list of (line_num, mnemonic, operand) for non-blank, non-comment lines
    instructions = []
    for i, line in enumerate(lines, start=1):
        label, mnemonic, operand = _parse_line(line)
        if mnemonic:
            instructions.append((i, mnemonic, operand))

    raw_lines = lines  # keep raw lines for suppression checking

    # Single-line checks
    for line_num, mnemonic, operand in instructions:
        _check_indirect_predec_su(line_num, mnemonic, operand, log, filename)
        # Check suppression for W2000
        raw_line = raw_lines[line_num - 1] if line_num <= len(raw_lines) else ''
        if log.warnings and log.warnings[-1][2] == W_UNDEFINED_PREDEC1_SU:
            if _is_suppressed(raw_line, W_UNDEFINED_PREDEC1_SU):
                log.warnings.pop()

    # Backward scan from each conditional branch (W2001)
    for idx, (line_num, mnemonic, operand) in enumerate(instructions):
        if mnemonic.upper() in CONDITIONAL_BRANCHES:
            _check_cc_clobber_backward(idx, instructions, raw_lines, log, filename)

    return log


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        prog='source_diag.py',
        description='6809 assembly source diagnostic analyzer',
        add_help=False,
    )
    parser.add_argument('--help', '-h', action='help')
    parser.add_argument('source', metavar='FILE',
        help='Assembly source file to analyze')
    args = parser.parse_args()

    with open(args.source, 'r') as f:
        source = f.read()

    log = analyze_source(source, filename=args.source)

    if log.has_warnings():
        print(f"{args.source}: {log.count()} warning(s)")
        log.report(file=sys.stdout)
        sys.exit(1)
    else:
        print(f"{args.source}: no diagnostic warnings")
        sys.exit(0)


if __name__ == '__main__':
    main()
