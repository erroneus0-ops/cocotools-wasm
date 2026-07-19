"""
cocotools/test_diagnostics.py -- Regression tests for the source-level
diagnostic pass (diagnostics.py / source_diag.py).

Prior to 2026-07-17 there was NO test coverage for this module anywhere
in the repo, which is how the CC_CLOBBERING_LOADS duplicate-definition
bug (see diagnostics_finding_cc_clobbering_loads_shadowed.txt) went
unnoticed: a second module-level assignment silently shadowed the first,
complete set with a narrower one, and nothing caught it.

This file exists to close that gap. It is intentionally independent of
test_fidelity.py -- it does not assemble anything or compare against
real lwasm, since this module operates on source TEXT only and never
touches assembly output (see diagnostics.py's own architecture note).

Usage:
    python3 cocotools/test_diagnostics.py
    python3 cocotools/test_diagnostics.py --verbose
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')

from cocotools.source_diag import analyze_source
from cocotools.diagnostics import (
    W_CC_CLOBBERED_BEFORE_BRANCH,
    W_UNDEFINED_PREDEC1_SU,
)

# Assembly source snippets use traditional column-based syntax (label at
# column 1, mnemonic indented) -- this parser's _LINE_RE treats an
# un-indented first token as a LABEL, not a mnemonic, matching real
# lwasm source conventions and every other test file in this repo.

# ── W2001 (CC_CLOBBERED_BEFORE_BRANCH) tests ─────────────────────────────────
# (description, source, expected_warning_count, expected_codes)

CC_CLOBBER_TESTS = [
    # ── Regression tests for the CC_CLOBBERING_LOADS duplicate-definition
    #    bug specifically (2026-07-17 fix) -- these are the exact cases
    #    that silently produced 0 warnings before the fix, because LDX
    #    and CLRA had been dropped from the live (shadowed) set.
    ("cc-clobber-ldx-after-cmpx",
     "         CMPX  #$10\n         LDX   #$20\n         BNE   X\nX        RTS\n",
     1, [W_CC_CLOBBERED_BEFORE_BRANCH]),

    ("cc-clobber-clra-after-tsta",
     "         TSTA\n         CLRA\n         BEQ   X\nX        RTS\n",
     1, [W_CC_CLOBBERED_BEFORE_BRANCH]),

    ("cc-clobber-ldy-after-cmpy",
     "         CMPY  #$10\n         LDY   #$20\n         BNE   X\nX        RTS\n",
     1, [W_CC_CLOBBERED_BEFORE_BRANCH]),

    ("cc-clobber-clr-after-tst",
     "         TST   VAR\n         CLR   VAR\n         BEQ   X\nX        RTS\n",
     1, [W_CC_CLOBBERED_BEFORE_BRANCH]),

    # ── Pre-existing case (was already working before the fix; kept as a
    #    non-regression check that the merge didn't break the original
    #    LDD/CMPD case it was scoped down to).
    ("cc-clobber-ldd-after-cmpd",
     "         CMPD  #$10\n         LDD   #$20\n         BNE   X\nX        RTS\n",
     1, [W_CC_CLOBBERED_BEFORE_BRANCH]),

    # ── Suppression via (!W2001) comment marker ──────────────────────────
    ("cc-clobber-suppressed",
     "         CMPD  #$10\n         LDD   #$20 ; (!W2001)\n         BNE   X\nX        RTS\n",
     0, []),

    # ── Must stay clean: CC_NEUTRAL instruction between compare and branch
    ("cc-clobber-neutral-between-clean",
     "         CMPD  #$10\n         STA   VAR\n         BNE   X\nX        RTS\n",
     0, []),

    # ── Must stay clean: the high-bit-terminated string idiom. The load
    #    IS the intended CC setter here (no prior compare) -- this is the
    #    exact case the requester described designing the "no prior
    #    compare -> load is the intended CC setter" safeguard around, and
    #    it must remain unaffected by CC_CLOBBERING_LOADS' contents,
    #    since that safeguard is keyed on structure (was there a prior
    #    compare?), not on which specific mnemonic is in the set.
    ("cc-clobber-string-terminator-idiom-clean",
     "LOOP     LDA   ,X+\n         BMI   DONE\n         BRA   LOOP\nDONE     ANDA  #$7F\n         RTS\n",
     0, []),

    # ── Must stay clean: no compare/test at all anywhere before the branch
    ("cc-clobber-no-compare-clean",
     "         LDA   #$00\n         BEQ   X\nX        RTS\n",
     0, []),
]

# ── W2000 (UNDEFINED_PREDEC1_SU) tests -- pre-existing behavior, included
# for completeness since this file is establishing baseline coverage for
# the whole module, not just the bug that was just fixed.

PREDEC_TESTS = [
    ("predec-indirect-s-warns",
     "         LDA   [,-S]\n",
     1, [W_UNDEFINED_PREDEC1_SU]),

    ("predec-indirect-u-warns",
     "         LDA   [,-U]\n",
     1, [W_UNDEFINED_PREDEC1_SU]),

    ("predec-direct-s-clean",
     "         LDA   ,-S\n",
     0, []),

    ("predec-suppressed",
     "         LDA   [,-S] ; (!W2000)\n",
     0, []),
]

ALL_TESTS = [(desc, src, count, codes, 'cc-clobber')
             for desc, src, count, codes in CC_CLOBBER_TESTS] + \
            [(desc, src, count, codes, 'predec')
             for desc, src, count, codes in PREDEC_TESTS]


def run_diagnostics_tests(verbose=False):
    passed = 0
    failed = 0
    errors = []

    print(f"\nRunning {len(ALL_TESTS)} diagnostics tests...")

    for desc, src, expected_count, expected_codes, _category in ALL_TESTS:
        log = analyze_source(src, filename=desc)
        actual_codes = [code for (_ln, _fn, code, _msg) in log.warnings]

        ok = (log.count() == expected_count and actual_codes == expected_codes)

        if ok:
            if verbose:
                print(f"  PASS  [{desc}] {log.count()} warning(s)")
            passed += 1
        else:
            msg = (f"FAIL  [{desc}]\n"
                   f"       expected: count={expected_count} codes={expected_codes}\n"
                   f"       actual:   count={log.count()} codes={actual_codes}")
            print(f"  {msg}")
            errors.append(msg)
            failed += 1

    print(f"Diagnostics results: {passed} passed, {failed} failed "
          f"out of {len(ALL_TESTS)} tests")
    return failed == 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='cocotools diagnostics test suite')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    ok = run_diagnostics_tests(verbose=args.verbose)
    sys.exit(0 if ok else 1)
