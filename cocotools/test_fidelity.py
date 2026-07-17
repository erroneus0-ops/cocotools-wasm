"""
cocotools/test_fidelity.py -- Fidelity test harness

Assembles every instruction/mode combination with both cocotools and asm6809,
compares bytes exactly, reports every divergence.

This is the arbiter of truth. The audit is provisional. This is definitive.

Usage:
    python3 cocotools/test_fidelity.py
    python3 cocotools/test_fidelity.py --verbose
    python3 cocotools/test_fidelity.py --6309

Requirements:
    asm6809 binary at /home/claude/asm6809/src/asm6809
    (or set ASM6809 environment variable)
"""

import os
import sys
import json
import glob
import struct
import tempfile
import subprocess
import argparse

# LWASM: prefer environment variable, then repo-local build, then system PATH
def _find_tool(env_var, *candidates):
    if env_var in os.environ:
        return os.environ[env_var]
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[-1]  # fall through to PATH attempt

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LWASM = _find_tool('LWASM',
    os.path.join(_REPO, 'lwtools-4.24', 'lwasm', 'lwasm'),   # Linux build
    os.path.join(_REPO, 'lwtools-4.24', 'lwasm', 'lwasm.exe'),# Windows build
    'lwasm',                                                    # system PATH
)
ASM6809 = _find_tool('ASM6809',
    '/home/claude/asm6809/src/asm6809',
    'asm6809',
)

# ── Test case definitions ─────────────────────────────────────────────────────
# Each entry: (mnemonic, operand, mode_description, expect_error)
# We generate these systematically from the opcode JSON plus manual edge cases.

# Symbolic constants for test assembly
PREAMBLE_BEFORE = """\
LABEL    EQU   $1234
         ORG   $3F00
"""

# Address mode test templates
# {M} = mnemonic, {O} = operand
TESTS = [
    # Inherent
    ("NOP",  "",          "inherent",         False),
    ("RTS",  "",          "inherent",         False),
    ("RTI",  "",          "inherent",         False),
    ("SWI",  "",          "inherent",         False),
    ("SWI2", "",          "inherent",         False),
    ("SWI3", "",          "inherent",         False),
    ("DAA",  "",          "inherent",         False),
    ("SEX",  "",          "inherent",         False),
    ("MUL",  "",          "inherent",         False),
    ("CLRA", "",          "inherent",         False),
    ("CLRB", "",          "inherent",         False),
    ("COMA", "",          "inherent",         False),
    ("COMB", "",          "inherent",         False),
    ("NEGA", "",          "inherent",         False),
    ("NEGB", "",          "inherent",         False),
    ("INCA", "",          "inherent",         False),
    ("INCB", "",          "inherent",         False),
    ("DECA", "",          "inherent",         False),
    ("DECB", "",          "inherent",         False),
    ("ASLA", "",          "inherent",         False),
    ("ASLB", "",          "inherent",         False),
    ("ASRA", "",          "inherent",         False),
    ("ASRB", "",          "inherent",         False),
    ("LSLA", "",          "inherent",         False),
    ("LSLB", "",          "inherent",         False),
    ("LSRA", "",          "inherent",         False),
    ("LSRB", "",          "inherent",         False),
    ("ROLA", "",          "inherent",         False),
    ("ROLB", "",          "inherent",         False),
    ("RORA", "",          "inherent",         False),
    ("RORB", "",          "inherent",         False),
    ("TSTA", "",          "inherent",         False),
    ("TSTB", "",          "inherent",         False),
    ("ABX",  "",          "inherent",         False),

    # Immediate
    ("LDA",  "#$42",      "imm-byte",         False),
    ("LDB",  "#$42",      "imm-byte",         False),
    ("LDD",  "#$1234",    "imm-word",         False),
    ("LDX",  "#$1234",    "imm-word",         False),
    ("LDY",  "#$1234",    "imm-word",         False),
    ("LDU",  "#$1234",    "imm-word",         False),
    ("LDS",  "#$1234",    "imm-word",         False),
    ("ADDA", "#$42",      "imm-byte",         False),
    ("ADDB", "#$42",      "imm-byte",         False),
    ("ADDD", "#$1234",    "imm-word",         False),
    ("ADCA", "#$42",      "imm-byte",         False),
    ("ADCB", "#$42",      "imm-byte",         False),
    ("SUBA", "#$42",      "imm-byte",         False),
    ("SUBB", "#$42",      "imm-byte",         False),
    ("SUBD", "#$1234",    "imm-word",         False),
    ("SBCA", "#$42",      "imm-byte",         False),
    ("SBCB", "#$42",      "imm-byte",         False),
    ("ANDA", "#$42",      "imm-byte",         False),
    ("ANDB", "#$42",      "imm-byte",         False),
    ("ANDCC","#$42",      "imm-byte",         False),
    ("ORA",  "#$42",      "imm-byte",         False),
    ("ORB",  "#$42",      "imm-byte",         False),
    ("ORCC", "#$42",      "imm-byte",         False),
    ("EORA", "#$42",      "imm-byte",         False),
    ("EORB", "#$42",      "imm-byte",         False),
    ("CMPA", "#$42",      "imm-byte",         False),
    ("CMPB", "#$42",      "imm-byte",         False),
    ("CMPD", "#$1234",    "imm-word",         False),
    ("CMPX", "#$1234",    "imm-word",         False),
    ("CMPY", "#$1234",    "imm-word",         False),
    ("CMPU", "#$1234",    "imm-word",         False),
    ("CMPS", "#$1234",    "imm-word",         False),
    ("BITA", "#$42",      "imm-byte",         False),
    ("BITB", "#$42",      "imm-byte",         False),

    # Direct
    ("LDA",  "<$42",      "direct",           False),
    ("STA",  "<$42",      "direct",           False),
    ("LDD",  "<$42",      "direct",           False),
    ("STD",  "<$42",      "direct",           False),
    ("CLR",  "<$42",      "direct",           False),
    ("TST",  "<$42",      "direct",           False),
    ("INC",  "<$42",      "direct",           False),
    ("DEC",  "<$42",      "direct",           False),
    ("NEG",  "<$42",      "direct",           False),
    ("COM",  "<$42",      "direct",           False),
    ("ASL",  "<$42",      "direct",           False),
    ("ASR",  "<$42",      "direct",           False),
    ("LSL",  "<$42",      "direct",           False),
    ("LSR",  "<$42",      "direct",           False),
    ("ROL",  "<$42",      "direct",           False),
    ("ROR",  "<$42",      "direct",           False),
    ("JMP",  "<$42",      "direct",           False),
    ("JSR",  "<$42",      "direct",           False),

    # Extended
    ("LDA",  "LABEL",     "extended",         False),
    ("STA",  "LABEL",     "extended",         False),
    ("LDD",  "LABEL",     "extended",         False),
    ("JMP",  "LABEL",     "extended",         False),
    ("JSR",  "LABEL",     "extended",         False),
    ("CLR",  "LABEL",     "extended",         False),
    ("TST",  "LABEL",     "extended",         False),

    # Indexed -- zero offset
    ("LDA",  ",X",        "idx-zero",         False),
    ("LDA",  ",Y",        "idx-zero",         False),
    ("LDA",  ",U",        "idx-zero",         False),
    ("LDA",  ",S",        "idx-zero",         False),

    # Indexed -- 5-bit offset
    ("LDA",  "5,X",       "idx-5bit",         False),
    ("LDA",  "-5,X",      "idx-5bit-neg",     False),
    ("LDA",  "15,X",      "idx-5bit-max",     False),

    # Indexed -- 8-bit offset
    ("LDA",  "100,X",     "idx-8bit",         False),
    ("LDA",  "-100,X",    "idx-8bit-neg",     False),

    # Indexed -- 16-bit offset
    ("LDA",  "1000,X",    "idx-16bit",        False),
    ("LDA",  "LABEL,X",   "idx-16bit-label",  False),

    # Indexed -- accumulator offset
    ("LDA",  "A,X",       "idx-acc-a",        False),
    ("LDA",  "B,X",       "idx-acc-b",        False),
    ("LDA",  "D,X",       "idx-acc-d",        False),

    # Indexed -- post-increment
    ("LDA",  ",X+",       "idx-postinc1",     False),
    ("LDA",  ",X++",      "idx-postinc2",     False),

    # Indexed -- pre-decrement
    ("LDA",  ",-X",       "idx-predec1",      False),
    ("LDA",  ",--X",      "idx-predec2",      False),

    # Indexed -- PC-relative
    ("LDA",  "LABEL,PCR", "idx-pcr",          False),

    # Indexed indirect -- valid forms
    ("LDA",  "[,X]",      "idx-ind-zero",     False),
    ("LDA",  "[100,X]",   "idx-ind-8bit",     False),
    ("LDA",  "[1000,X]",  "idx-ind-16bit",    False),
    ("LDA",  "[D,X]",     "idx-ind-acc-d",    False),
    ("LDA",  "[,X++]",    "idx-ind-postinc2", False),
    ("LDA",  "[,--X]",    "idx-ind-predec2",  False),
    ("LDA",  "[LABEL]",   "idx-ind-ext",      False),
    ("LDA",  "[LABEL,PCR]","idx-ind-pcr",     False),

    # Indexed indirect -- INVALID (lwasm errors)
    # [,-X] -- lwasm errors, asm6809 warns+accepts. cocotools follows lwasm.
    # ("LDA",  "[,-X]",     "idx-ind-predec1-ILLEGAL", True),
    # [,X+] -- lwasm errors, asm6809 warns+accepts. cocotools follows lwasm.
    # ("LDA",  "[,X+]",     "idx-ind-postinc1-ILLEGAL", True),

    # TFR / EXG
    ("TFR",  "D,X",       "tfr-d-x",          False),
    ("TFR",  "A,B",       "tfr-a-b",          False),
    ("TFR",  "CC,DP",     "tfr-cc-dp",        False),
    ("TFR",  "X,Y",       "tfr-x-y",          False),
    ("TFR",  "S,U",       "tfr-s-u",          False),
    ("TFR",  "PC,X",      "tfr-pc-x",         False),
    ("EXG",  "D,X",       "exg-d-x",          False),
    ("EXG",  "A,B",       "exg-a-b",          False),

    # PSH / PUL
    ("PSHS", "A",         "pshs-a",           False),
    ("PSHS", "B",         "pshs-b",           False),
    ("PSHS", "D",         "pshs-d",           False),
    ("PSHS", "X",         "pshs-x",           False),
    ("PSHS", "A,B,X",     "pshs-abx",         False),
    ("PSHS", "D,X,Y",     "pshs-dxy",         False),
    ("PSHS", "PC",        "pshs-pc",          False),
    ("PULS", "A,B,X,PC",  "puls-abxpc",       False),
    ("PSHU", "A,B",       "pshu-ab",          False),
    ("PULU", "A,B,PC",    "pulu-abpc",        False),

    # LEA
    ("LEAX", ",X",        "lea-zero",         False),
    ("LEAX", "5,Y",       "lea-offset",       False),
    ("LEAX", "LABEL,PCR", "lea-pcr",          False),
    ("LEAY", ",U",        "lea-u",            False),
    ("LEAU", ",S",        "lea-s",            False),
    ("LEAS", "2,S",       "lea-s-offset",     False),

    # Branches -- short
    ("BRA",  "BRLABEL",   "bra",              False),
    ("BEQ",  "BRLABEL",   "beq",              False),
    ("BNE",  "BRLABEL",   "bne",              False),
    ("BCC",  "BRLABEL",   "bcc",              False),
    ("BCS",  "BRLABEL",   "bcs",              False),
    ("BHI",  "BRLABEL",   "bhi",              False),
    ("BLS",  "BRLABEL",   "bls",              False),
    ("BGT",  "BRLABEL",   "bgt",              False),
    ("BGE",  "BRLABEL",   "bge",              False),
    ("BLT",  "BRLABEL",   "blt",              False),
    ("BLE",  "BRLABEL",   "ble",              False),
    ("BMI",  "BRLABEL",   "bmi",              False),
    ("BPL",  "BRLABEL",   "bpl",              False),
    ("BVC",  "BRLABEL",   "bvc",              False),
    ("BVS",  "BRLABEL",   "bvs",              False),
    ("BSR",  "BRLABEL",   "bsr",              False),

    # Branches -- long
    ("LBRA", "LABEL",     "lbra",             False),
    ("LBEQ", "LABEL",     "lbeq",             False),
    ("LBNE", "LABEL",     "lbne",             False),
    ("LBCC", "LABEL",     "lbcc",             False),
    ("LBCS", "LABEL",     "lbcs",             False),
    ("LBSR", "LABEL",     "lbsr",             False),
]


# ── Behavioral tests -- error conditions and pseudo-ops ──────────────────────
# Each entry: (description, full_source, expect_error)
# These test lwasm behavioral fidelity beyond just byte output.

BEHAVIOR_TESTS = [
    # ── Error conditions ──────────────────────────────────────────────────────
    ("error-bad-operand-no-arg",
     "         ORG $3F00\n         LDA\n         END\n",
     True),

    ("error-undefined-symbol",
     "         ORG $3F00\n         BRA UNDEF\n         END\n",
     True),

    ("error-byte-overflow",
     "         ORG $3F00\n         LDA #256\n         END\n",
     True),

    ("error-bad-register-pshs",
     "         ORG $3F00\n         PSHS Z\n         END\n",
     True),

    ("error-equ-no-label",
     "         ORG $3F00\n         EQU 5\n         END\n",
     True),

    ("error-indirect-predec1",
     "         ORG $3F00\n         LDA [,-X]\n         END\n",
     True),

    ("error-indirect-postinc1",
     "         ORG $3F00\n         LDA [,X+]\n         END\n",
     True),

    # ── Pseudo-ops -- correct byte output ────────────────────────────────────
    ("pseudo-fcb-single",
     "         ORG $3F00\n         FCB $42\n         END\n",
     False),

    ("pseudo-fcb-multiple",
     "         ORG $3F00\n         FCB $42,$43,$44\n         END\n",
     False),

    ("pseudo-fcb-negative",
     "         ORG $3F00\n         FCB -1\n         END\n",
     False),

    ("pseudo-fcb-truncates-256",
     "         ORG $3F00\n         FCB 256\n         END\n",
     False),

    ("pseudo-fdb-single",
     "         ORG $3F00\n         FDB $1234\n         END\n",
     False),

    ("pseudo-fdb-negative",
     "         ORG $3F00\n         FDB -1\n         END\n",
     False),

    ("pseudo-fcc-string",
     "         ORG $3F00\n         FCC /hello/\n         END\n",
     False),

    ("pseudo-rmb",
     "         ORG $3F00\n         RMB 4\n         FCB $FF\n         END\n",
     False),

    ("pseudo-equ-label",
     "FIVE     EQU 5\n         ORG $3F00\n         LDA #FIVE\n         END\n",
     False),

    ("pseudo-equ-expression",
     "BASE     EQU $3F00\nOFFSET   EQU 5\n         ORG $3F00\n         FDB BASE+OFFSET\n         END\n",
     False),

    # ── Expression evaluation ─────────────────────────────────────────────────
    ("expr-addition",
     "         ORG $3F00\n         LDA #2+3\n         END\n",
     False),

    ("expr-subtraction",
     "         ORG $3F00\n         LDA #10-3\n         END\n",
     False),

    ("expr-multiplication",
     "         ORG $3F00\n         LDA #3*4\n         END\n",
     False),

    ("expr-bitwise-or",
     "         ORG $3F00\n         LDA #$0F|$F0\n         END\n",
     False),

    ("expr-bitwise-and",
     "         ORG $3F00\n         LDA #$FF&$0F\n         END\n",
     False),

    # ("expr-shift-left", -- lwasm doesn't support << operator)

    ("expr-unary-neg",
     "         ORG $3F00\n         LDA #-5\n         END\n",
     False),

    ("expr-current-addr",
     "         ORG $3F00\n         FDB *\n         END\n",
     False),

    # ── TFR size mismatch -- lwasm allows, produces specific bytes ────────────
    ("tfr-size-mismatch-a-x",
     "         ORG $3F00\n         TFR A,X\n         END\n",
     False),

    ("tfr-size-mismatch-d-a",
     "         ORG $3F00\n         TFR D,A\n         END\n",
     False),

    # ── Multiple ORG segments ─────────────────────────────────────────────────
    ("multi-org",
     "         ORG $3F00\n         LDA #$01\n         ORG $4000\n         LDA #$02\n         END\n",
     False),
]


# ── Structural tests -- internal state after assembly ────────────────────────
# These verify that cl.pb, cl.lint, cl.len etc. contain the correct values
# after parse/resolve/emit -- not just that the output bytes are correct.
# A function could produce correct output bytes by accident while carrying
# wrong internal state that would fail on more complex inputs.

STRUCTURAL_TESTS = [
    # (description, source, assertions: field -> expected_value)

    ("struct-immediate-lda",
     "         ORG $3F00\nTEST     LDA   #$42\n         END\n",
     {'len': 2, 'pb': 0, 'lint': 0}),

    ("struct-direct-lda",
     "         ORG $3F00\nTEST     LDA   <$42\n         END\n",
     {'len': 2, 'pb': 0, 'lint': 0}),

    ("struct-extended-lda",
     "         ORG $3F00\nTEST     LDA   $1234\n         END\n",
     {'len': 3, 'pb': 0, 'lint': 0}),

    ("struct-indexed-zero-offset",
     "         ORG $3F00\nTEST     LDA   ,X\n         END\n",
     {'len': 2, 'pb': 0x84, 'lint': 0}),

    ("struct-indexed-8bit-offset",
     "         ORG $3F00\nTEST     LDA   100,X\n         END\n",
     {'len': 3, 'pb': 0x88, 'lint': 1}),

    ("struct-indexed-16bit-offset",
     "         ORG $3F00\nTEST     LDA   1000,X\n         END\n",
     {'len': 4, 'pb': 0x89, 'lint': 2}),

    ("struct-indexed-5bit-neg-offset",
     "         ORG $3F00\nTEST     LDA   -5,X\n         END\n",
     {'len': 2, 'pb': 0x1B, 'lint': 0}),

    ("struct-indexed-acc-a",
     "         ORG $3F00\nTEST     LDA   A,X\n         END\n",
     {'len': 2, 'pb': 0x86, 'lint': 0}),

    ("struct-indexed-acc-d",
     "         ORG $3F00\nTEST     LDA   D,X\n         END\n",
     {'len': 2, 'pb': 0x8B, 'lint': 0}),

    ("struct-indexed-postinc2",
     "         ORG $3F00\nTEST     LDA   ,X++\n         END\n",
     {'len': 2, 'pb': 0x81, 'lint': 0}),

    ("struct-indexed-predec2",
     "         ORG $3F00\nTEST     LDA   ,--X\n         END\n",
     {'len': 2, 'pb': 0x83, 'lint': 0}),

    ("struct-indexed-indirect-zero",
     "         ORG $3F00\nTEST     LDA   [,X]\n         END\n",
     {'len': 2, 'pb': 0x94, 'lint': 0}),

    ("struct-indexed-indirect-16bit",
     "         ORG $3F00\nTEST     LDA   [1000,X]\n         END\n",
     {'len': 4, 'pb': 0x99, 'lint': 2}),

    ("struct-extended-indirect",
     "         ORG $3F00\nTEST     LDA   [$1234]\n         END\n",
     {'len': 4, 'pb': 0x9F, 'lint': 2}),

    ("struct-pshs-d",
     "         ORG $3F00\nTEST     PSHS  D\n         END\n",
     {'len': 2, 'pb': 0x06, 'lint': 0}),

    ("struct-pshs-pc",
     "         ORG $3F00\nTEST     PSHS  PC\n         END\n",
     {'len': 2, 'pb': 0x80, 'lint': 0}),

    ("struct-tfr-d-x",
     "         ORG $3F00\nTEST     TFR   D,X\n         END\n",
     {'len': 2, 'pb': 0x01, 'lint': 0}),

    ("struct-tfr-a-b",
     "         ORG $3F00\nTEST     TFR   A,B\n         END\n",
     {'len': 2, 'pb': 0x89, 'lint': 0}),
]


# ── Expression-simplification tests (lw_expr_simplify_l / _go) ───────────────
# These exercise Expr.simplify() directly rather than through full assembly,
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cocotools.lw_expr import Expr, TYPE_OPER, OPER_PLUS, OPER_TIMES, OPER_COM, OPER_COM8
# because several of the branches below (multi-factor like-term collection,
# the un-masked COM operator, distribution over a 3+ term sum) either don't
# reliably survive to the *output byte* level (everything's a compile-time
# constant by the time DECB bytes are emitted) or need operands that never
# resolve to plain integers (bare symbols) to exercise the symbolic paths
# at all.
#
# Expected results were captured from a standalone C program linked
# directly against a from-source build of lwtools-4.24's liblw.a, calling
# lw_expr_simplify() on hand-built expression trees and printing the
# result with the same postfix notation as Expr.__repr__ -- i.e. these are
# not "what we think the code should do", they're the actual recorded
# output of the real C implementation being translated.
EXPRESSION_SIMPLIFY_TESTS = [
    # (description, expr-builder, expected repr() after simplify())

    ("expr-com-unmasked",
     # ~5 -- source.c's COM case has NO mask (`tr = ~(...)`); only COM8
     # masks with `& 0xff`. A prior version of this translation masked
     # COM to 16 bits, turning -6 into 65530.
     lambda: _mk_oper(OPER_COM, [Expr.int(5)]),
     '-0x6'),

    ("expr-com8-masked",
     # ~5 in 8-bit mode -- SHOULD mask to 0xfa, unlike plain COM above.
     # Included alongside expr-com-unmasked so the two can't both pass by
     # accident (e.g. by masking neither, or masking both the same way).
     lambda: _mk_oper(OPER_COM8, [Expr.int(5)]),
     '0xfa'),

    ("expr-multi-factor-like-terms",
     # 2*X*Y + 3*X*Y -> 5*X*Y. A prior version of _is_like_term /
     # _base_of only ever looked at a single non-constant factor of a
     # TIMES node, so a term with *two* non-constant factors (X and Y)
     # silently lost one of them -- this collapsed to "X*5" (Y quietly
     # discarded) instead of "5*X*Y".
     lambda: _mk_oper(OPER_PLUS, [
         _mk_oper(OPER_TIMES, [Expr.int(2), Expr.var('X'), Expr.var('Y')]),
         _mk_oper(OPER_TIMES, [Expr.int(3), Expr.var('X'), Expr.var('Y')]),
     ]),
     '[3]* 0x5 V(X) V(Y)'),

    ("expr-cancel-terms",
     # X + -1*X -> 0 (like terms with coefficients summing to zero cancel
     # entirely, via the PLUS collapse-to-zero block).
     lambda: _mk_oper(OPER_PLUS, [
         Expr.var('X'),
         _mk_oper(OPER_TIMES, [Expr.int(-1), Expr.var('X')]),
     ]),
     '0x0'),

    ("expr-prune-zero-keep-others",
     # X + 0 + Y -> X + Y (zero term pruned, but two other terms remain --
     # must NOT collapse all the way down to a single operand).
     lambda: _mk_oper(OPER_PLUS, [Expr.var('X'), Expr.int(0), Expr.var('Y')]),
     '[2]+ V(X) V(Y)'),

    ("expr-collapse-single-after-zero",
     # 0 + X -> X (exactly one non-zero operand remains -> collapse to it
     # directly, matching source.c lines 449-522, not the earlier partial
     # PLUS evaluation step).
     lambda: _mk_oper(OPER_PLUS, [Expr.int(0), Expr.var('X')]),
     'V(X)'),

    ("expr-sort-const-first",
     # X + 5 -> 5 + X. lw_expr_simplify_sortconstfirst moves the literal
     # to the front of a PLUS/TIMES operand list; a prior version of this
     # translation never called it at all.
     lambda: _mk_oper(OPER_PLUS, [Expr.var('X'), Expr.int(5)]),
     '[2]+ 0x5 V(X)'),

    ("expr-distribute-three-term",
     # 3*(X+Y+Z) -> 3*X + 3*Y + 3*Z. Distribution must handle a sum of
     # any arity, not just exactly two terms.
     lambda: _mk_oper(OPER_TIMES, [
         Expr.int(3),
         _mk_oper(OPER_PLUS, [Expr.var('X'), Expr.var('Y'), Expr.var('Z')]),
     ]),
     '[3]+ [2]* 0x3 V(X) [2]* 0x3 V(Y) [2]* 0x3 V(Z)'),
]


def _mk_oper(op, operands):
    """Build a raw TYPE_OPER Expr node with the given operator and operand
    list directly (bypassing Expr.oper()'s auto-copy), for constructing
    test trees precisely."""
    from cocotools.lw_expr import Expr, TYPE_OPER
    e = Expr(TYPE_OPER, op)
    e.operands = operands
    return e


def run_expression_simplify_tests(verbose=False):
    """Run Expr.simplify() directly against recorded real-lwtools output."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from cocotools.lw_expr import ExprContext

    passed = 0
    failed = 0
    errors = []

    print(f"\nRunning {len(EXPRESSION_SIMPLIFY_TESTS)} expression-simplify tests...")

    for desc, builder, expected in EXPRESSION_SIMPLIFY_TESTS:
        ctx = ExprContext()
        e = builder()
        before = repr(e)
        e.simplify(ctx)
        actual = repr(e)

        if actual == expected:
            if verbose:
                print(f"  PASS  [{desc}] {before} -> {actual}")
            passed += 1
        else:
            msg = (f"FAIL  [{desc}]\n"
                   f"       before:   {before}\n"
                   f"       expected: {expected}\n"
                   f"       actual:   {actual}")
            print(f"  {msg}")
            errors.append(msg)
            failed += 1

    print(f"Expression-simplify results: {passed} passed, {failed} failed "
          f"out of {len(EXPRESSION_SIMPLIFY_TESTS)} tests")
    return failed == 0


def _get_line_state(source, label='TEST', mode6309=False):
    """Assemble source and return the internal state of the labeled line."""
    import sys, os, tempfile
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    from cocotools.lwasm_core import AsmState
    from cocotools.input_system import InputSystem
    from cocotools.pass1 import do_pass1
    from cocotools.passes import (do_pass2, do_pass3, do_pass4,
                                   do_pass5, do_pass6, do_pass7)
    from cocotools.lwasm_types import PRAGMA_6809

    as_ = AsmState()
    as_.input = InputSystem(as_)
    if mode6309:
        as_.pragmas &= ~PRAGMA_6809

    # Write to temp file -- input system requires a file path
    with tempfile.NamedTemporaryFile(suffix='.asm', mode='w', delete=False) as f:
        f.write(source)
        src_path = f.name

    try:
        as_.input.open(src_path)
        do_pass1(as_)
        if as_.errorcount: return None, as_.errorcount
        do_pass2(as_)
        if as_.errorcount: return None, as_.errorcount
        do_pass3(as_)
        do_pass4(as_)
        do_pass5(as_)
        do_pass6(as_)
        do_pass7(as_)
    finally:
        os.unlink(src_path)

    # Find the labeled line
    cl = as_.line_head
    while cl:
        if cl.sym == label:
            return cl, 0
        cl = cl.next
    return None, 0


def run_structural_tests(mode6309=False, verbose=False):
    """Run structural tests -- verify internal line state after assembly."""
    passed = 0
    failed = 0
    errors = []

    print(f"\nRunning {len(STRUCTURAL_TESTS)} structural tests...")

    for desc, source, expected in STRUCTURAL_TESTS:
        cl, errcount = _get_line_state(source, mode6309=mode6309)

        if cl is None or errcount > 0:
            msg = f"FAIL  [{desc}] -- assembly failed (errors: {errcount})"
            print(f"  {msg}")
            errors.append(msg)
            failed += 1
            continue

        ok = True
        mismatches = []
        for field, expected_val in expected.items():
            actual_val = getattr(cl, field, '???')
            if actual_val != expected_val:
                mismatches.append(
                    f"{field}: expected {expected_val} (0x{expected_val:02X} if int), "
                    f"got {actual_val} (0x{actual_val:02X} if int)"
                    if isinstance(expected_val, int) and isinstance(actual_val, int)
                    else f"{field}: expected {expected_val}, got {actual_val}"
                )
                ok = False

        if ok:
            if verbose:
                state = ', '.join(f"{k}={expected[k]:#04x}" if isinstance(expected[k],int) 
                                  else f"{k}={expected[k]}"
                                  for k in expected)
                print(f"  PASS  [{desc}] -- {state}")
            passed += 1
        else:
            msg = f"FAIL  [{desc}]\n       " + "\n       ".join(mismatches)
            print(f"  {msg}")
            errors.append(msg)
            failed += 1

    print(f"Structural results: {passed} passed, {failed} failed out of {len(STRUCTURAL_TESTS)} tests")
    return failed == 0


def run_behavior_tests(mode6309=False, verbose=False):
    """Run behavioral fidelity tests."""
    passed = 0
    failed = 0
    errors = []

    print(f"\nRunning {len(BEHAVIOR_TESTS)} behavioral tests...")

    for desc, source, expect_error in BEHAVIOR_TESTS:
        cocotools_bytes, cocotools_err = assemble_cocotools(source, mode6309)
        lwasm_bytes,     lwasm_err     = assemble_lwasm(source, mode6309)

        cocotools_errored = cocotools_bytes is None
        lwasm_errored     = lwasm_bytes     is None

        if expect_error:
            if cocotools_errored and lwasm_errored:
                if verbose:
                    print(f"  PASS  [{desc}] -- both error as expected")
                passed += 1
            elif not cocotools_errored and lwasm_errored:
                msg = f"FAIL  [{desc}] -- cocotools accepted, lwasm errors"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif cocotools_errored and not lwasm_errored:
                msg = f"FAIL  [{desc}] -- cocotools errors, lwasm accepts"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            else:
                msg = f"FAIL  [{desc}] -- both accepted (expected error)"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
        else:
            if cocotools_errored and lwasm_errored:
                msg = f"FAIL  [{desc}] -- both errored\n       cocotools: {cocotools_err}\n       lwasm:     {lwasm_err}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif cocotools_errored:
                msg = f"FAIL  [{desc}] -- cocotools error: {cocotools_err}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif lwasm_errored:
                msg = f"FAIL  [{desc}] -- lwasm error: {lwasm_err}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif cocotools_bytes == lwasm_bytes:
                if verbose:
                    print(f"  PASS  [{desc}] = {cocotools_bytes.hex().upper()}")
                passed += 1
            else:
                ct_hex = cocotools_bytes.hex().upper()
                lw_hex = lwasm_bytes.hex().upper()
                msg = f"FAIL  [{desc}]\n       cocotools: {ct_hex}\n       lwasm:     {lw_hex}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1

    print(f"Behavioral results: {passed} passed, {failed} failed out of {len(BEHAVIOR_TESTS)} tests")
    return failed == 0


# ── Assembly functions ────────────────────────────────────────────────────────

def assemble_cocotools(source, mode6309=False):
    """Assemble source with cocotools. Returns (bytes, error_string)."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    
    with tempfile.NamedTemporaryFile(suffix='.asm', mode='w', delete=False) as f:
        f.write(source)
        src_path = f.name
    
    out_path = src_path.replace('.asm', '.bin')
    
    try:
        cmd = [sys.executable, 'cocotools.py', 'asm', src_path, '-o', out_path]
        if mode6309:
            cmd += ['--', '-3']
        
        result = subprocess.run(cmd, capture_output=True, text=True,
                               cwd=os.path.dirname(os.path.dirname(__file__)))
        
        if result.returncode != 0:
            return None, result.stdout.strip()
        
        if os.path.exists(out_path):
            raw = open(out_path, 'rb').read()
            # Extract code from DECB binary
            code = _extract_decb(raw)
            return code, None
        return None, "no output file"
    finally:
        for p in [src_path, out_path]:
            try: os.unlink(p)
            except: pass


def assemble_lwasm(source, mode6309=False):
    """Assemble source with lwasm (primary reference). Returns (bytes, error_string)."""
    with tempfile.NamedTemporaryFile(suffix='.asm', mode='w', delete=False) as f:
        f.write(source)
        src_path = f.name

    out_path = src_path.replace('.asm', '.bin')

    try:
        cmd = [LWASM, '--decb', f'--output={out_path}']
        if mode6309:
            cmd.append('--6309')
        else:
            cmd.append('--6809')
        cmd.append(src_path)

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            return None, err

        if os.path.exists(out_path):
            raw = open(out_path, 'rb').read()
            code = _extract_decb(raw)
            return code, None
        return None, "no output file"
    finally:
        for p in [src_path, out_path]:
            try: os.unlink(p)
            except: pass


def assemble_asm6809(source, mode6309=False):
    """Assemble source with asm6809 (secondary reference). Returns (bytes, error_string)."""
    with tempfile.NamedTemporaryFile(suffix='.asm', mode='w', delete=False) as f:
        f.write(source)
        src_path = f.name
    
    out_path = src_path.replace('.asm', '.bin')
    
    try:
        cmd = [ASM6809, '--coco', '-o', out_path]
        if mode6309:
            cmd.append('--6309')
        cmd.append(src_path)
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            return None, err
        
        if os.path.exists(out_path):
            raw = open(out_path, 'rb').read()
            code = _extract_decb(raw)
            return code, None
        return None, "no output file"
    finally:
        for p in [src_path, out_path]:
            try: os.unlink(p)
            except: pass


def _extract_decb(raw):
    """Extract code bytes from DECB binary format."""
    result = b''
    i = 0
    while i < len(raw):
        if raw[i] == 0x00:  # data block
            length = (raw[i+1] << 8) | raw[i+2]
            result += raw[i+5:i+5+length]
            i += 5 + length
        elif raw[i] == 0xFF:  # EOF block
            break
        else:
            break
    return result


# ── Test runner ───────────────────────────────────────────────────────────────

def run_tests(mode6309=False, verbose=False):
    passed = 0
    failed = 0
    errors = []

    print(f"Running {len(TESTS)} fidelity tests {'(6309 mode)' if mode6309 else '(6809 mode)'}...")
    print(f"Reference: lwasm ({LWASM})")
    print()

    for mnemonic, operand, desc, expect_error in TESTS:
        src_line = f"         {mnemonic}"
        if operand:
            src_line += f"  {operand}"
        
        source = PREAMBLE_BEFORE + src_line + "\n         RTS\nBRLABEL  EQU   *\n         END\n"
        
        cocotools_bytes, cocotools_err = assemble_cocotools(source, mode6309)
        lwasm_bytes,     lwasm_err     = assemble_lwasm(source, mode6309)

        cocotools_errored = cocotools_bytes is None
        asm6809_errored   = lwasm_bytes     is None

        if expect_error:
            # Both should error
            if cocotools_errored and asm6809_errored:
                if verbose:
                    print(f"  PASS  {mnemonic} {operand:<20} [{desc}] -- both error as expected")
                passed += 1
            elif not cocotools_errored and asm6809_errored:
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}] -- cocotools accepted but lwasm errors"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif cocotools_errored and not asm6809_errored:
                msg = f"WARN  {mnemonic} {operand:<20} [{desc}] -- cocotools errors but lwasm accepts"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            else:
                msg = f"WARN  {mnemonic} {operand:<20} [{desc}] -- both accepted (expected error)"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
        else:
            # Both should succeed and produce identical bytes
            ref_bytes = lwasm_bytes
            ref_err   = lwasm_err
            ref_name  = 'lwasm'
            if cocotools_errored and asm6809_errored:
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}] -- both errored\n       cocotools: {cocotools_err}\n       {ref_name}:   {ref_err}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif cocotools_errored:
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}] -- cocotools error: {cocotools_err}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif asm6809_errored:
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}] -- {ref_name} error: {ref_err}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif cocotools_bytes == ref_bytes:
                if verbose:
                    hex_out = cocotools_bytes.hex().upper()
                    print(f"  PASS  {mnemonic} {operand:<20} [{desc}] = {hex_out}")
                passed += 1
            else:
                ct_hex = cocotools_bytes.hex().upper() if cocotools_bytes else 'None'
                lw_hex = ref_bytes.hex().upper()       if ref_bytes       else 'None'
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}]\n       cocotools: {ct_hex}\n       {ref_name}:   {lw_hex}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed out of {len(TESTS)} tests")
    
    if failed == 0:
        print("All tests passed -- cocotools is byte-for-byte faithful to lwasm 4.24")
    else:
        print(f"\n{failed} divergences found. Fix these before trusting cocotools output.")
    
    return failed == 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='cocotools fidelity test harness')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--6309', '-3', dest='mode6309', action='store_true')
    args = parser.parse_args()
    
    import shutil
    lwasm_ok = os.path.exists(LWASM) or shutil.which(LWASM) is not None
    if not lwasm_ok:
        print(f"ERROR: lwasm not found at {LWASM}")
        print("Build lwtools-4.24 or set LWASM environment variable")
        sys.exit(1)
    
    success1 = run_tests(mode6309=args.mode6309, verbose=args.verbose)
    success2 = run_behavior_tests(mode6309=args.mode6309, verbose=args.verbose)
    success3 = run_structural_tests(mode6309=args.mode6309, verbose=args.verbose)
    success4 = run_expression_simplify_tests(verbose=args.verbose)
    sys.exit(0 if (success1 and success2 and success3 and success4) else 1)
