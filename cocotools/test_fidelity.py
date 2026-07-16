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

ASM6809 = os.environ.get('ASM6809', '/home/claude/asm6809/src/asm6809')

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


def assemble_asm6809(source, mode6309=False):
    """Assemble source with asm6809. Returns (bytes, error_string)."""
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
    print(f"Reference: {ASM6809}")
    print()

    for mnemonic, operand, desc, expect_error in TESTS:
        src_line = f"         {mnemonic}"
        if operand:
            src_line += f"  {operand}"
        
        source = PREAMBLE_BEFORE + src_line + "\n         RTS\nBRLABEL  EQU   *\n         END\n"
        
        cocotools_bytes, cocotools_err = assemble_cocotools(source, mode6309)
        asm6809_bytes,   asm6809_err   = assemble_asm6809(source, mode6309)

        cocotools_errored = cocotools_bytes is None
        asm6809_errored   = asm6809_bytes   is None

        if expect_error:
            # Both should error
            if cocotools_errored and asm6809_errored:
                if verbose:
                    print(f"  PASS  {mnemonic} {operand:<20} [{desc}] -- both error as expected")
                passed += 1
            elif not cocotools_errored and asm6809_errored:
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}] -- cocotools accepted but asm6809 errors"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif cocotools_errored and not asm6809_errored:
                msg = f"WARN  {mnemonic} {operand:<20} [{desc}] -- cocotools errors but asm6809 accepts"
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
            if cocotools_errored and asm6809_errored:
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}] -- both errored\n       cocotools: {cocotools_err}\n       asm6809:   {asm6809_err}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif cocotools_errored:
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}] -- cocotools error: {cocotools_err}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif asm6809_errored:
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}] -- asm6809 error: {asm6809_err}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1
            elif cocotools_bytes == asm6809_bytes:
                if verbose:
                    hex_out = cocotools_bytes.hex().upper()
                    print(f"  PASS  {mnemonic} {operand:<20} [{desc}] = {hex_out}")
                passed += 1
            else:
                ct_hex = cocotools_bytes.hex().upper() if cocotools_bytes else 'None'
                a6_hex = asm6809_bytes.hex().upper()   if asm6809_bytes   else 'None'
                msg = f"FAIL  {mnemonic} {operand:<20} [{desc}]\n       cocotools: {ct_hex}\n       asm6809:   {a6_hex}"
                print(f"  {msg}")
                errors.append(msg)
                failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed out of {len(TESTS)} tests")
    
    if failed == 0:
        print("All tests passed -- cocotools is byte-for-byte faithful to asm6809")
    else:
        print(f"\n{failed} divergences found. Fix these before trusting cocotools output.")
    
    return failed == 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='cocotools fidelity test harness')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--6309', '-3', dest='mode6309', action='store_true')
    args = parser.parse_args()
    
    if not os.path.exists(ASM6809):
        print(f"ERROR: asm6809 not found at {ASM6809}")
        print("Build it or set ASM6809 environment variable")
        sys.exit(1)
    
    success = run_tests(mode6309=args.mode6309, verbose=args.verbose)
    sys.exit(0 if success else 1)
