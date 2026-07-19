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
    ("PSHS", "#$06",      "pshs-imm8",        False),
    ("PSHU", "#$81",      "pshu-imm8",        False),
    ("PSHU", "S",         "pshu-s",           False),
    ("PULS", "U",         "puls-u",           False),

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

    # Regression: insn_parse_rlist's '#' branch must return the cursor
    # position advanced by insn_parse_imm8, not the stale, unadvanced
    # outer position -- otherwise the assembler thinks the operand wasn't
    # fully consumed and raises a spurious "Bad operand" error, AND the
    # subsequent line would be at risk if the wrong remainder ever leaked
    # into further parsing.
    ("behavior-pshs-immediate-form",
     "         ORG $3F00\n         PSHS #$06\n         LDA #$01\n         END\n",
     False),

    ("behavior-pshu-immediate-form",
     "         ORG $3F00\n         PSHU #$81\n         END\n",
     False),

    ("error-pshs-register-s-invalid",
     "         ORG $3F00\n         PSHS S\n         END\n",
     True),

    ("error-pshu-register-u-invalid",
     "         ORG $3F00\n         PSHU U\n         END\n",
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

    # ── insn_parse_indexed_aux: added during the 2026-07-17 faithful
    #    translation audit (translation_packages/02_insn_parse_indexed_aux) ──
    # (6809-mode entries only -- see BEHAVIOR_TESTS_6309 below for the
    #  6309-only W-register cases, which must always run in 6309 mode
    #  regardless of the CLI's default --6809/--6309 selection.)

    # Forward reference (label defined after use) resolving to an
    # out-of-8-bit-range value -- exercises the deferred-resolve marker
    # path (cl.lint left at -1 by insn_parse_indexed_aux; decided later
    # by _insn_resolve_indexed_aux) rather than the immediate encoding
    # decided when the value is already known at parse time.
    ("indexed-fwdref-16bit",
     "         ORG $3F00\n         LDA FWDLABEL,X\n         RTS\nFWDLABEL EQU $1234\n         END\n",
     False),

    # n,PCR -- true PC-relative addressing; the offset expression is
    # adjusted for (target - (addr + linelen)) before being saved.
    ("indexed-pcr-relative",
     "         ORG $3F00\n         LDA 10,PCR\n         RTS\n         END\n",
     False),

    # n,PC (no R) -- PC used as a plain index register: same postbyte
    # opcodes as PCR but WITHOUT the relative-offset expression rewrite,
    # so the literal operand value is emitted unchanged. This is the
    # `rn == 6` (not `rn == 5 or PCASPCR`) branch.
    ("indexed-pc-plain-register",
     "         ORG $3F00\n         LDA 10,PC\n         RTS\n         END\n",
     False),

    # [<<n,X] -- forcing 5-bit offset AND indirect in the same operand is
    # illegal (checked immediately after the second '<' is consumed, only
    # when the indirect flag is already set).
    ("indexed-illegal-5bit-indirect",
     "         ORG $3F00\n         LDA [<<5,X]\n         RTS\n         END\n",
     True),

    # Explicit "0,X" vs plain ",X" -- these must NOT produce the same
    # postbyte. Writing the offset "0" explicitly sets the f0 flag, which
    # blocks collapsing to the dedicated zero-offset opcode (0x84) and
    # instead uses the plain 5-bit encoding with offset literally 0
    # (0x00). Regression test for the f0 flag, which the previous ad hoc
    # translation did not implement at all.
    ("indexed-explicit-zero-offset",
     "         ORG $3F00\n         LDA 0,X\n         RTS\n         END\n",
     False),
    ("indexed-collapsed-zero-offset",
     "         ORG $3F00\n         LDA ,X\n         RTS\n         END\n",
     False),

    # ── insn_resolve_indexed_aux: added during the 2026-07-17 faithful
    #    translation audit (translation_packages/03_insn_resolve_indexed_aux).
    #
    # These four cover paths through _insn_resolve_indexed_aux that the
    # existing "indexed-fwdref-16bit" test above does not distinguish,
    # because that test's forward-referenced value ($1234) genuinely
    # needs 16 bits regardless of *when* it is decided -- so it can't
    # tell "correctly computed 16-bit" apart from "always defaults to
    # 16-bit for any forward reference." The four tests below use small
    # final values specifically so that a wrong pass-timing/force policy
    # (i.e. shrinking to the minimal encoding once the symbol becomes
    # known, instead of staying locked at the size decided when the
    # value was still unknown) is visible as a byte mismatch.

    # Forward reference whose *final* value (5) would fit the compact
    # 5-bit postbyte encoding if resolved fresh -- but PRAGMA_FORWARDREFMAX
    # (on by default in real lwasm; see AsmState.__init__ comment in
    # cocotools/lwasm_core.py) forces resolution to the 16-bit form
    # during pass 1, before FWD is known, and insn_resolve_indexed's
    # `if (l->lint == -1)` guard means that decision is never revisited.
    # Regression test for the missing PRAGMA_FORWARDREFMAX default,
    # found and fixed during this audit.
    ("indexed-fwdref-locks-16bit-not-5bit",
     "         ORG $3F00\n         LDA FWD,X\n         RTS\nFWD      EQU 5\n         END\n",
     False),

    # Same mechanism, but the final value (100) would fit the compact
    # 8-bit postbyte encoding if resolved fresh -- must still lock to
    # 16-bit, not 8-bit.
    ("indexed-fwdref-locks-16bit-not-8bit",
     "         ORG $3F00\n         LDA FWD,X\n         RTS\nFWD      EQU 100\n         END\n",
     False),

    # A genuinely undefined symbol (never defined anywhere) in indexed
    # mode. Exercises the final `else: if (!force) return;` branch of
    # insn_resolve_indexed_aux with force=1 actually reaching the "goto
    # do16bit" arm and then failing to ever produce complete output --
    # must error exactly as lwasm does (E_INSTRUCTION_FAILED /
    # "Undefined symbol"), not silently succeed or crash.
    ("indexed-undefined-symbol-forced",
     "         ORG $3F00\n         LDA UNDEF,X\n         RTS\n         END\n",
     True),

    # n,PCR to a label far enough away (past many NOP instructions) that
    # its address is still unresolved on the first attempt. Exercises the
    # `(l->pb & 0x07) == 5` branch's as->pretendmax fudge-factor heuristic
    # (regfield 5/6 special case within the "e2 not int" path), which is
    # otherwise never reached by the existing indexed-pcr-relative test
    # (that test's target is already a resolved literal at parse time).
    ("indexed-pcr-forward-heuristic",
     "         ORG $3F00\n         LDA FAR,PCR\n" + "         NOP\n" * 40 +
     "FAR      RTS\n         END\n",
     False),

    # ── insn_parse_rtor: added during the 2026-07-17 faithful translation
    #    audit (translation_packages/06_insn_parse_rtor). ─────────────────────
    # A register pair not exercised by any prior TFR/EXG test in this file
    # (existing tests cover D,X / A,B / CC,DP / X,Y / S,U / PC,X for TFR
    # and D,X / A,B for EXG) -- new success-path coverage for EXG.
    ("rtor-exg-cc-dp",
     "         ORG $3F00\nTEST     EXG   CC,DP\n         END\n",
     False),

    # r0 < 0: first register name doesn't match any entry in the lookup
    # table at all. Exercises the `r0 < 0` half of the `||` short-circuit
    # in `if (r0 < 0 || *(*p)++ != ',')` -- this branch must NOT read or
    # advance past the comma-position character (see checklist note on
    # insn_parse_rtor above); confirmed here only at the error/no-error
    # level (both cocotools and real lwasm single-error identically),
    # since the cursor-position divergence itself isn't observable
    # through the top-level harness (see the unit-level test below for
    # that).
    ("rtor-bad-first-register",
     "         ORG $3F00\nTEST     TFR   Q,X\n         END\n",
     True),

    # r1 < 0: valid first register and comma, but the second register
    # name doesn't match. Exercises the nested `if (r1 < 0)` branch.
    ("rtor-bad-second-register",
     "         ORG $3F00\nTEST     TFR   X,Q\n         END\n",
     True),

    # Missing comma: valid first register, but the next character is a
    # space instead of ','. This is the exact branch where C's
    # `*(*p)++ != ','` consumes one character unconditionally (r0 >= 0)
    # before comparing -- the branch the previous translation got wrong
    # (it never advanced p here at all). At the whole-assembler level
    # this still just produces a single "Bad operand" error from both
    # cocotools and real lwasm (cl.err gates the outer unconsumed-operand
    # check before the wrong cursor position could ever matter) -- so
    # this test only confirms the branch is reached and single-errors
    # correctly; see the direct unit-level test below for a check of the
    # actual cursor position C requires.
    ("rtor-missing-comma",
     "         ORG $3F00\nTEST     TFR   A B\n         END\n",
     True),

    # ── lw_expr_parse_expr: operator table shadowing (declaration order,
    #    NOT longest-match) ───────────────────────────────────────────────
    # "<" is declared before "<=" in the C operators[] table and is a
    # complete prefix of it, so the C matching loop commits to "<" and
    # never reaches "<=" -- the dangling "=" then fails to parse as a
    # term. Confirmed against real lwasm 4.24: "Bad operand".
    ("expr-le-operator-unreachable",
     "         ORG $3F00\nRESULT   EQU 5<=10\n         FCB RESULT\n         END\n",
     True),

    # Same shadowing, ">" before ">=".
    ("expr-ge-operator-unreachable",
     "         ORG $3F00\nRESULT   EQU 10>=5\n         FCB RESULT\n         END\n",
     True),

    # Same shadowing, but via the single-char "!" (bwor alias) instead of
    # a genuine relational operator: "!" is declared before "!=" and
    # shadows it the same way.
    ("expr-ne-operator-unreachable",
     "         ORG $3F00\nRESULT   EQU 5!=6\n         FCB RESULT\n         END\n",
     True),

    # Control case: "<>" (lwasm's non-shadowed spelling of NE) is declared
    # before the single-char "<", so it is never shadowed and parses fine.
    ("expr-ne-altspelling-works",
     "         ORG $3F00\nRESULT   EQU 5<>6\n         FCB RESULT\n         END\n",
     False),

    # ── lw_expr_parse_expr: NULL propagation ──────────────────────────────
    # A term followed by trailing input that is neither a recognized
    # operator nor a terminator character is a syntax error in the C
    # source (lw_expr_destroy(term1); return NULL;), not "return the term
    # we already have". Confirmed against real lwasm 4.24: "Bad operand".
    ("expr-trailing-unrecognized-char",
     "         ORG $3F00\nRESULT   EQU 5@\n         FCB RESULT\n         END\n",
     True),

    # A recognized, sufficiently-high-precedence operator with nothing
    # valid after it (dangling operator) is also a full syntax error in
    # C (term2 comes back NULL, so term1 is destroyed too) -- not a
    # successful parse of the left operand alone.
    ("expr-dangling-operator",
     "         ORG $3F00\nRESULT   EQU 5+\n         FCB RESULT\n         END\n",
     True),

    # ── lw_expr_parse_expr: matching/precedence interaction ───────────────
    # At prec=50 (recursing into the right side of a bwand "&"), the
    # single-char "!" (bwor alias, prec 50) shadows "!=" (prec 55) and
    # is found first regardless of precedence; since 50 <= 50 it is
    # handed back unconsumed, so the OUTER (prec=0) call then consumes
    # it as bwor, leaving a dangling "=3" that fails to parse as a term.
    # The whole expression is a syntax error. A precedence-filtered
    # search (skipping "!" because its precedence is too low for the
    # *inner* prec=50 call) would incorrectly still find "!=" and accept
    # it -- confirmed against real lwasm 4.24, which rejects this
    # entirely with "Bad operand".
    ("expr-operator-precedence-interaction",
     "         ORG $3F00\nRESULT   EQU 1&2!=3\n         FCB RESULT\n         END\n",
     True),

    # ── lw_expr_parse_expr: ordinary end-of-input still works ────────────
    # Regression guard for the '\\0' vs '' sentinel fix: a bare, complete
    # expression with nothing following it must still parse successfully
    # all the way to end of input.
    ("expr-simple-end-of-input",
     "         ORG $3F00\nRESULT   EQU 5+3\n         FCB RESULT\n         END\n",
     False),
]


# ── 6309-only behavioral tests ────────────────────────────────────────────────
# These exercise the rn==4 (W register) branch of insn_parse_indexed_aux,
# which is only reachable when PRAGMA_6809 is off. They always assemble in
# 6309 mode regardless of the --6309 CLI flag, since BEHAVIOR_TESTS above
# (and the harness generally) assembles its whole list in one mode at a time
# selected by that single flag, and W is illegal input under PRAGMA_6809.

BEHAVIOR_TESTS_6309 = [
    # 6309 W-register indexed forms: zero-offset, post-inc-2, pre-dec-2,
    # and their indirect equivalents -- rn==4 is a wholly separate branch
    # in insn_parse_indexed_aux with its own fixed opcodes (not derived
    # by shifting a register number the way X/Y/U/S are).
    ("indexed-w-register-forms-6309",
     "         ORG $3F00\n         LDA ,W\n         LDA ,W++\n"
     "         LDA ,--W\n         LDA [,W]\n         LDA [,W++]\n"
     "         RTS\n         END\n",
     False),

    # n,W forced to 8-bit ('<' prefix) is illegal -- W has no 8-bit
    # offset form, only 0-bit (collapsed) or 16-bit.
    ("indexed-w-forced-8bit-illegal-6309",
     "         ORG $3F00\n         LDA <5,W\n         RTS\n         END\n",
     True),

    # n,W with a large value -- must pick the 16-bit W-specific opcodes
    # (0xAF / 0xB0), not the X/Y/U/S-style 0x89/0x99.
    ("indexed-w-16bit-6309",
     "         ORG $3F00\n         LDA 1000,W\n         RTS\n         END\n",
     False),

    # insn_resolve_indexed_aux audit (translation_packages/03): same
    # forward-reference lock-to-worst-case behavior as the 6809 X/Y/U/S
    # tests above, but through the regfield==4 (W) branch, which has its
    # own opcode pair (0xAF/0xB0) distinct from the 0x89 used by X/Y/U/S.
    # FWD's final value (5) has no compact W encoding at all (W only has
    # 0-offset and 16-bit forms) so this also confirms the lock doesn't
    # accidentally produce the W zero-offset opcode instead.
    ("indexed-w-fwdref-locks-16bit-6309",
     "         ORG $3F00\n         LDA FWD,W\n         RTS\nFWD      EQU 5\n         END\n",
     False),

    # insn_emit_rtor audit (translation_packages/07): ADCR/ADDR/ANDR/CMPR/
    # EORR/ORR/SBCR/SUBR are 6309-only rtor-family instructions whose
    # opcode (e.g. 0x1031) is > 0xFF -- this exercises lwasm_emitop's
    # two-byte-opcode split (emit high byte, then low byte, then cl.pb)
    # via insn_emit_rtor, a code path TFR/EXG (opcodes 0x1f/0x1e) never
    # reach since their opcodes fit in one byte. Full byte comparison
    # against real lwasm confirms the 3-byte sequence (0x10, 0x31, pb).
    ("rtor-two-byte-opcode-adcr-6309",
     "         ORG $3F00\nTEST     ADCR  A,B\n         END\n",
     False),

    # insn_emit_tfm audit (translation_packages/12): all four TFM variants,
    # each selecting a different two-byte opcode from ops[0..3] via
    # cl.lint (0x1138/0x1139/0x113a/0x113b), then the postbyte from cl.pb.
    # Like ADCR above, every TFM opcode is > 0xFF, so this also re-confirms
    # the emitop high-byte/low-byte split, but through insn_emit_tfm's own
    # call site (l->lint as the opcode, l->pb as the postbyte) rather than
    # the ops[0]-only path used by rtor/inh-family emit functions.
    ("tfm-postinc-both-6309",
     "         ORG $3F00\nTEST     TFM   D+,X+\n         END\n",
     False),

    ("tfm-postdec-both-6309",
     "         ORG $3F00\nTEST     TFM   X-,Y-\n         END\n",
     False),

    ("tfm-r0-only-6309",
     "         ORG $3F00\nTEST     TFM   Y+,U\n         END\n",
     False),

    ("tfm-r1-only-6309",
     "         ORG $3F00\nTEST     TFM   S,D+\n         END\n",
     False),

    # Illegal register for TFM -- A is valid for TFR/EXG (rtor family) but
    # NOT for TFM, which only accepts D/X/Y/U/S (insn_parse_tfm's
    # `r0 > 4 or r1 > 4` check). Confirms insn_emit_tfm is never reached
    # (E_REGISTER_BAD registered at parse time) and no bytes are emitted
    # for the bad operand.
    ("tfm-illegal-register-6309",
     "         ORG $3F00\nTEST     TFM   A,X+\n         END\n",
     True),

    # insn_emit_bitbit audit (translation_packages/14): CC register
    # (lint=0), direct-page address. pb = (0<<6)|(3<<3)|5 = 0x1D.
    # Opcode 0x1130 is > 0xFF, so this also re-confirms the two-byte
    # opcode emit path, this time via the ops[0]-only call site (unlike
    # insn_emit_tfm, which reaches its opcode through cl.lint instead).
    ("bitbit-band-cc-direct-page-6309",
     "         ORG $3F00\nTEST     BAND  CC,3,5,$10\n         END\n",
     False),

    # B register (lint=2) -> pb = (2<<6)|(2<<3)|6 = 0x96.
    ("bitbit-stbt-b-register-6309",
     "         ORG $3F00\nTEST     STBT  B,2,6,$20\n         END\n",
     False),

    # A register (lint=1), bit numbers at the extremes of the valid
    # 0-7 range (0 and 7) -> pb = (1<<6)|(0<<3)|7 = 0x47.
    ("bitbit-beor-a-register-bit-extremes-6309",
     "         ORG $3F00\nTEST     BEOR  A,0,7,$00\n         END\n",
     False),

    # Bit number 8 is out of the valid 0-7 range -> E_BITNUMBER_INVALID.
    # Confirms cocotools registers an error (and lwasm's CLI therefore
    # exits non-zero / emits no output) exactly like real lwasm, rather
    # than silently clamping v1 to 0 and emitting anyway.
    ("bitbit-invalid-bitnumber-6309",
     "         ORG $3F00\nTEST     BAND  CC,8,5,$10\n         END\n",
     True),

    # Address resolves outside the direct page in effect (dpval=0 by
    # default here) -> (addr & 0xFFFF) - (dpval<<8) exceeds 0xFF ->
    # E_BYTE_OVERFLOW. This exercises the early `return` in the C source
    # that skips emitop/emit/emitexpr entirely once byte overflow is
    # detected -- no partial bytes should reach the output.
    ("bitbit-byte-overflow-6309",
     "         ORG $3F00\nTEST     BAND  CC,3,5,$1234\n         END\n",
     True),

    # Bit-number operand is an undefined symbol -- lw_expr_istype never
    # sees an int-typed expression for id 0, exercising the
    # E_BITNUMBER_UNRESOLVED defensive path (the `e and e.istype(...)`
    # guard matters here in Python: fetch_expr can return None, and
    # None.istype(...) would raise AttributeError where C's null-safe
    # lw_expr_istype just returns false).
    ("bitbit-bitnumber-unresolved-6309",
     "         ORG $3F00\nTEST     BAND  CC,UNDEF,5,$10\n         END\n",
     True),

    # insn_parse_logicmem / insn_emit_logicmem audit (translation_packages/
    # 15 and 16): AIM/EIM/OIM/TIM ("logic op immediate mask, to memory")
    # exercise both the mask-value parse and the general addressing mode
    # for the memory operand.

    # Direct-page mode -- opcode ops[0]=0x02 for AIM, mask $0F, addr $20.
    ("logicmem-aim-direct-page-6309",
     "         ORG $3F00\nTEST     AIM   #$0F,$20\n         END\n",
     False),

    # Extended mode -- address doesn't fit the direct page in effect,
    # so the general addressing parser picks ops[2]=0x71 for OIM.
    ("logicmem-oim-extended-6309",
     "         ORG $3F00\nTEST     OIM   #$80,$1234\n         END\n",
     False),

    # Indexed, 5-bit offset -- ops[1]=0x65 for EIM, offset 5 fits in the
    # 5-bit signed field so no extra offset byte is emitted.
    ("logicmem-eim-indexed-5bit-6309",
     "         ORG $3F00\nTEST     EIM   #$FF,5,X\n         END\n",
     False),

    # Indexed, indirect 8-bit offset -- ops[1]=0x6b for TIM; indirect
    # addressing forces the 8/16-bit indexed form even for a small offset
    # that would otherwise fit in 5 bits, since 5-bit offset has no
    # indirect form.
    ("logicmem-tim-indexed-indirect-6309",
     "         ORG $3F00\nTEST     TIM   #$3C,[10,X]\n         END\n",
     False),

    # Unresolved mask expression (undefined symbol) -> insn_emit_logicmem's
    # E_IMMEDIATE_UNRESOLVED path. Also exercises the same `e and
    # e.istype(...)` null-safety guard pattern as insn_emit_bitbit, since
    # fetch_expr(100) can return None.
    ("logicmem-immediate-unresolved-6309",
     "         ORG $3F00\nTEST     AIM   #UNDEF,$20\n         END\n",
     True),
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

    # f0 flag: explicit "0,X" must NOT collapse to the dedicated
    # zero-offset opcode (0x84) -- it must use the plain 5-bit encoding
    # with the offset literally 0 (0x00), post-resolve lint == 0 ("0
    # extra bytes needed", not a leftover 5-bit-forced sentinel).
    ("struct-indexed-explicit-zero-f0",
     "         ORG $3F00\nTEST     LDA   0,X\n         END\n",
     {'len': 2, 'pb': 0x00, 'lint': 0}),

    # n,PC (no R): same opcode family as PCR but resolved as a literal
    # register-indexed value, not a relative offset.
    ("struct-indexed-pc-plain-register",
     "         ORG $3F00\nTEST     LDA   10,PC\n         END\n",
     {'len': 3, 'pb': 0x8C, 'lint': 1}),

    ("struct-pshs-d",
     "         ORG $3F00\nTEST     PSHS  D\n         END\n",
     {'len': 2, 'pb': 0x06, 'lint': 0}),

    ("struct-pshs-pc",
     "         ORG $3F00\nTEST     PSHS  PC\n         END\n",
     {'len': 2, 'pb': 0x80, 'lint': 0}),

    # Regression for the '#' branch aliasing bug: len/lint must reflect
    # the immediate encoding path (insn_parse_imm8), and pb stays 0 since
    # the immediate form encodes the register mask directly in the operand
    # byte rather than in cl.pb.
    ("struct-pshs-imm8",
     "         ORG $3F00\nTEST     PSHS  #$06\n         END\n",
     {'len': 2, 'pb': 0x00, 'lint': 1}),

    # U and S share bit 0x40 -- only one is ever legal per PSHS/PSHU
    # context, so this bit means "the other stack's pointer" depending
    # on which of the two push/pull instructions is in play.
    ("struct-pshu-s",
     "         ORG $3F00\nTEST     PSHU  S\n         END\n",
     {'len': 2, 'pb': 0x40, 'lint': 0}),

    ("struct-puls-u",
     "         ORG $3F00\nTEST     PULS  U\n         END\n",
     {'len': 2, 'pb': 0x40, 'lint': 0}),

    ("struct-tfr-d-x",
     "         ORG $3F00\nTEST     TFR   D,X\n         END\n",
     {'len': 2, 'pb': 0x01, 'lint': 0}),

    ("struct-tfr-a-b",
     "         ORG $3F00\nTEST     TFR   A,B\n         END\n",
     {'len': 2, 'pb': 0x89, 'lint': 0}),

    # insn_emit_rtor audit (translation_packages/07): the tests above only
    # check cl.pb/cl.len/cl.lint, which are set at *parse* time by
    # insn_parse_rtor -- they'd pass even if insn_emit_rtor itself never
    # ran or wrote nothing. These check cl.output directly (the field
    # insn_emit_rtor's two lwasm_emitop/lwasm_emit calls actually write),
    # confirming the opcode byte (from instab[cl.insn].ops[0]) is emitted
    # before cl.pb, in that order, with no extra bytes.
    ("struct-tfr-d-x-output-bytes",
     "         ORG $3F00\nTEST     TFR   D,X\n         END\n",
     {'output': bytearray([0x1f, 0x01])}),

    ("struct-exg-a-b-output-bytes",
     "         ORG $3F00\nTEST     EXG   A,B\n         END\n",
     {'output': bytearray([0x1e, 0x89])}),

    # ── insn_emit_rlist / lwasm_cycle_calc_rlist coverage ──────────────────
    # cycle_adj is set at *emit* time (source.c line 107), not at parse or
    # resolve time, so these exercise insn_emit_rlist's normal (non-imm8)
    # branch and check the actual per-register cycle tally: 1 cycle for
    # each 8-bit register (CC,A,B,DP -- pb bits 0-3), 2 cycles for each
    # 16-bit register (X,Y,U/S,PC -- pb bits 4-7).

    # PSHS D -> pb=0x06 (A,B bits) -> 1+1 = 2
    ("struct-pshs-d-cycle-adj",
     "         ORG $3F00\nTEST     PSHS  D\n         END\n",
     {'pb': 0x06, 'cycle_adj': 2}),

    # PSHS PC -> pb=0x80 (PC bit, a 16-bit register) -> 2
    ("struct-pshs-pc-cycle-adj",
     "         ORG $3F00\nTEST     PSHS  PC\n         END\n",
     {'pb': 0x80, 'cycle_adj': 2}),

    # PSHS A,B,X -> pb = 0x02|0x04|0x10 = 0x16 -> 1+1+2 = 4
    ("struct-pshs-abx-cycle-adj",
     "         ORG $3F00\nTEST     PSHS  A,B,X\n         END\n",
     {'pb': 0x16, 'cycle_adj': 4}),

    # PULS A,B,X,PC -> pb = 0x02|0x04|0x10|0x80 = 0x96 -> 1+1+2+2 = 6
    ("struct-puls-abxpc-cycle-adj",
     "         ORG $3F00\nTEST     PULS  A,B,X,PC\n         END\n",
     {'pb': 0x96, 'cycle_adj': 6}),

    # PSHS #$06 takes the insn_emit_imm8 branch (cl.lint == 1), which
    # returns before the cycle_adj = lwasm_cycle_calc_rlist(cl) line is
    # ever reached. cycle_adj must stay at the value cycle_update_count()
    # set during cl.emitop() inside insn_emit_imm8 -- i.e. 0, not a stale
    # or miscalculated rlist tally.
    ("struct-pshs-imm8-cycle-adj",
     "         ORG $3F00\nTEST     PSHS  #$06\n         END\n",
     {'pb': 0x00, 'cycle_adj': 0}),
]


# ── Unit-level tests -- direct function calls, bypassing full assembly ───────
# Some C behavior never reaches an externally-observable difference through
# the full assemble-and-compare-bytes harness above, because a downstream
# guard (here: pass1's `!(cl->err)` check before reporting "unconsumed
# operand") happens to swallow the consequence every time. That doesn't make
# the underlying C behavior optional to replicate -- a different call site,
# or a future change to that downstream guard, could make the divergence
# visible. These tests call the translated function directly and check its
# return value / arguments precisely against what the C source specifies.
#
# Added during the 2026-07-17 insn_parse_rtor audit
# (translation_packages/06_insn_parse_rtor): C's
# `if (r0 < 0 || *(*p)++ != ',')` advances the cursor by one character
# UNCONDITIONALLY whenever r0 >= 0 -- even down the "not a comma" error
# path -- because `*(*p)++` is a read-and-advance that happens before the
# comparison, not after. The previous translation only advanced the
# cursor on the comma-found (success) path. See insn_parse_rtor's own
# checklist comment in cocotools/insn_funcs.py for the full analysis.

UNIT_TESTS_RTOR = [
    # (description, operand_string, expected_remaining, expected_errorcount)

    # r0 >= 0 ('A' matches), next char is a space, not a comma. C reads
    # the space, advances past it, THEN finds it isn't ',' and errors.
    # Expected remaining is "B" (space consumed) -- NOT " B".
    ("rtor-unit-missing-comma-consumes-char", "A B", "B", 1),

    # Same shape, but with two non-register characters after the valid
    # first register, to make sure only exactly one char is consumed
    # (not e.g. skipped-to-next-token past both).
    ("rtor-unit-missing-comma-consumes-exactly-one-char", "A  X", " X", 1),

    # r0 < 0 (bogus first register): the `||` must short-circuit, so the
    # cursor must NOT advance past the first character at all -- it
    # should still be sitting right where lookupreg2 left it (lookupreg2
    # itself does not advance p on a failed match).
    ("rtor-unit-bad-r0-no-advance", "Q,X", "Q,X", 1),

    # Success path (comma present): cursor must land exactly after both
    # registers, with nothing consumed beyond that.
    ("rtor-unit-success-exact-cursor", "A,B", "", 0),
]


def run_unit_tests(verbose=False):
    """Run direct-call unit tests (currently: insn_parse_rtor cursor tests)."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from cocotools.lwasm_core import AsmState, Line
    from cocotools.insn_funcs import insn_parse_rtor
    from cocotools.instab import INSTAB

    tfr_idx = None
    for i, ie in enumerate(INSTAB):
        if ie.parse is insn_parse_rtor:
            tfr_idx = i
            break

    passed = 0
    failed = 0
    errors = []

    print(f"\nRunning {len(UNIT_TESTS_RTOR)} unit tests...")

    for desc, operand, expected_remaining, expected_errcount in UNIT_TESTS_RTOR:
        as_ = AsmState()
        cl = Line(as_)
        cl.insn = tfr_idx

        remaining = insn_parse_rtor(as_, cl, operand)

        ok = (remaining == expected_remaining and
              as_.errorcount == expected_errcount)

        if ok:
            if verbose:
                print(f"  PASS  [{desc}] remaining={remaining!r} "
                      f"errorcount={as_.errorcount}")
            passed += 1
        else:
            msg = (f"FAIL  [{desc}]\n"
                   f"       operand:            {operand!r}\n"
                   f"       expected remaining: {expected_remaining!r}\n"
                   f"       actual remaining:   {remaining!r}\n"
                   f"       expected errcount:  {expected_errcount}\n"
                   f"       actual errcount:    {as_.errorcount}")
            print(f"  {msg}")
            errors.append(msg)
            failed += 1

    print(f"Unit results: {passed} passed, {failed} failed "
          f"out of {len(UNIT_TESTS_RTOR)} tests")
    return failed == 0


# ── Direct-call unit tests: lw_expr_parse_term ────────────────────────────────
# These bypass the full assembler entirely and call cocotools.lw_expr's
# internal parser functions directly, using a stub `parse_term` callback
# (ExprContext.parse_term) that records whether -- and with what -- it was
# invoked. This is the only way to prove the two bugs fixed in this audit
# (see lw_expr.py's _parse_term docstring), because the real assembler's
# own atom parser (AsmState._parse_term in lwasm_core.py) happens to carry
# its own redundant "not c" check, which silently absorbs the '\0'-vs-''
# sentinel bug and makes it invisible at the full-program output-byte
# level. A bare unit test of lw_expr_parse_term itself has no such safety
# net and exposes both bugs directly.
#
# Each entry: (description, input_string, expr_width, expected_result_repr,
#              expected_stub_called)
#   expected_result_repr: repr() of the returned Expr, or 'None'
#   expected_stub_called: whether the stub parse_term should have been
#     invoked at all, per the true C control flow in source.c

UNIT_TESTS_PARSE_TERM = [
    # ── Bug 1: '\0' vs '' end-of-input sentinel ──────────────────────────
    # True end of input: C's `if (!**p) return NULL;` fires immediately,
    # WITHOUT ever calling parse_term. existing.py's `c == '\\0'` check
    # can never be true (Ptr.peek() returns '' at end, never '\\0'), so
    # existing.py fell through every branch and called the stub anyway.
    ("parse-term-true-eof-no-stub-call",
     "", 0, "None", False),

    # Same bug, reached via the unary '+' goto (self re-entry): after
    # consuming the lone '+', the recursive call hits true end-of-input
    # and must also return NULL without calling parse_term.
    ("parse-term-unary-plus-then-eof-no-stub-call",
     "+", 0, "None", False),

    # ── Bug 2: Python isspace() vs C isspace() (checklist: use c_isspace) ─
    # ASCII File Separator (0x1C) is NOT whitespace under C's isspace()
    # in the C locale, so the true C control flow falls through to
    # `return parse_term(p, priv);` and the stub SHOULD be called.
    # existing.py's `c.isspace()` returns True for '\\x1c' (Python
    # considers it whitespace), so it wrongly returned None early
    # without ever reaching the stub.
    ("parse-term-fs-control-char-reaches-stub",
     "\x1c", 0, "None", True),

    # Genuine C whitespace (plain space) must still terminate the term
    # immediately without calling the stub -- regression guard that the
    # c_isspace() fix doesn't over-correct and start calling the stub on
    # real whitespace.
    ("parse-term-real-space-still-terminates",
     " ", 0, "None", False),

    # ── Regression / branch coverage (not bugs -- confirms behavior that
    #    was already correct is preserved by the fix) ────────────────────
    ("parse-term-paren-wraps-atom",
     "(5)", 0, "0x5", True),

    ("parse-term-unmatched-paren-is-syntax-error",
     "(5", 0, "None", True),

    ("parse-term-unary-minus-builds-neg-node",
     "-5", 0, "[1]NEG 0x5", True),

    ("parse-term-unary-complement-16bit-builds-com-node",
     "~5", 0, "[1]COM 0x5", True),

    ("parse-term-unary-complement-8bit-builds-com8-node",
     "~5", 8, "[1]COM8 0x5", True),

    ("parse-term-unary-caret-alias-for-complement",
     "^5", 0, "[1]COM 0x5", True),
]


def run_parse_term_unit_tests(verbose=False):
    """Direct-call unit tests for lw_expr_parse_term (cocotools.lw_expr._parse_term).

    Calls cocotools.lw_expr._parse_term directly rather than going through
    the public parse_expr() entry point. This matters: _parse_expr has its
    own separate (and separately-scoped) top-of-function guard that also
    checks `c.isspace()` before ever calling _parse_term -- going through
    parse_expr() would let that outer guard intercept FS/whitespace input
    before it reached the function actually under test here. Calling
    _parse_term directly isolates exactly the function this audit covers.

    Uses compact=True (matching AsmState.parse_expr's actual default --
    lw_parse_expr_compact is used unless PRAGMA_NEWSOURCE is set, which
    it isn't by default) rather than False. This isn't just cosmetic:
    _skip_ws's non-compact branch (`if not compact: while p.peek() not in
    ('\\0',) and p.peek() in ' \\t\\r\\n': p.advance()`) has its own,
    separate, pre-existing bug -- `'' in ' \\t\\r\\n'` is True in Python
    (the empty string is a substring of everything), so the loop never
    terminates once p.peek() reaches '' (true end of input): confirmed
    directly, `_skip_ws(Ptr(''), False)` hangs forever. That bug belongs
    to lw_expr_parse_next_tok (a different C function, not covered by
    this package's source.c or checklist.md) and is explicitly out of
    scope here -- flagged in SUMMARY.md for a future audit rather than
    fixed in passing. compact=True sidesteps it entirely (matching how
    the real assembler actually calls this code by default) without
    weakening what these tests prove about lw_expr_parse_term itself.
    """
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from cocotools.lw_expr import Ptr, ExprContext, _parse_term, Expr

    passed = 0
    failed = 0
    errors = []

    print(f"\nRunning {len(UNIT_TESTS_PARSE_TERM)} lw_expr_parse_term unit tests...")

    for desc, s, expr_width, expected_repr, expect_stub_called in UNIT_TESTS_PARSE_TERM:
        call_log = []

        def stub_parse_term(p, ctx, _log=call_log):
            # Minimal atom parser: recognizes a run of decimal digits,
            # anything else is "no term matched" (None), same contract
            # as the real lwasm_parse_term callback.
            _log.append(p.pos)
            start = p.pos
            while p.peek().isdigit():
                p.advance()
            if p.pos == start:
                return None
            return Expr.int(int(s[start:p.pos]))

        ctx = ExprContext()
        ctx.parse_term = stub_parse_term
        ctx.expr_width = expr_width

        p = Ptr(s)
        result = _parse_term(p, ctx, True)
        actual_repr = repr(result) if result is not None else "None"
        stub_called = len(call_log) > 0

        ok = (actual_repr == expected_repr and stub_called == expect_stub_called)

        if ok:
            if verbose:
                print(f"  PASS  [{desc}] result={actual_repr} stub_called={stub_called}")
            passed += 1
        else:
            msg = (f"FAIL  [{desc}]\n"
                   f"       input:                {s!r}\n"
                   f"       expected result:      {expected_repr}\n"
                   f"       actual result:        {actual_repr}\n"
                   f"       expected stub_called: {expect_stub_called}\n"
                   f"       actual stub_called:   {stub_called}")
            print(f"  {msg}")
            errors.append(msg)
            failed += 1

    print(f"lw_expr_parse_term unit results: {passed} passed, {failed} failed "
          f"out of {len(UNIT_TESTS_PARSE_TERM)} tests")
    return failed == 0


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


def run_behavior_tests(mode6309=False, verbose=False, tests=None, label=None):
    """Run behavioral fidelity tests."""
    passed = 0
    failed = 0
    errors = []

    if tests is None:
        tests = BEHAVIOR_TESTS
    label = label or ('behavioral (6309)' if mode6309 and tests is not BEHAVIOR_TESTS else 'behavioral')

    print(f"\nRunning {len(tests)} {label} tests...")

    for desc, source, expect_error in tests:
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

    print(f"{label.capitalize()} results: {passed} passed, {failed} failed out of {len(tests)} tests")
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
    success2b = run_behavior_tests(mode6309=True, verbose=args.verbose,
                                    tests=BEHAVIOR_TESTS_6309, label='behavioral (6309-only)')
    success3 = run_structural_tests(mode6309=args.mode6309, verbose=args.verbose)
    success4 = run_expression_simplify_tests(verbose=args.verbose)
    success5 = run_unit_tests(verbose=args.verbose)
    success6 = run_parse_term_unit_tests(verbose=args.verbose)
    sys.exit(0 if (success1 and success2 and success2b and success3 and success4 and success5 and success6) else 1)
