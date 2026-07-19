"""
cocotools/diagnostics.py -- 6809 source diagnostic warnings

Analyzes 6809 assembly SOURCE TEXT for patterns that are syntactically
valid and accepted by lwasm but produce undefined behavior on real 6809
hardware, or common programming mistakes.

ARCHITECTURE NOTE:
This module operates on source text BEFORE or ALONGSIDE assembly --
NOT inside the lwasm translation layer. The lwasm translation (lwasm.py,
insn_funcs.py, lwasm_core.py, passes.py etc.) must remain a faithful
reproduction of lwasm behavior, bugs and all, to survive lwasm updates.

Diagnostics belong here, outside the translation, as a separate analysis
pass. The cocotools API layer calls both:
    1. The lwasm translation (produces bytes)
    2. The diagnostic analyzer (produces warnings)

This way lwasm translation updates never touch diagnostic code and
diagnostic improvements never risk breaking the translation.

Reference: Motorola MC6809 Programming Reference Manual
           ugufru/coco CLAUDE.md (community-documented gotchas)
"""

# ── Warning codes ──────────────────────────────────────────────────────────────

W_UNDEFINED_PREDEC1_SU   = 2000   # [,-S] or [,-U] indirect pre-decrement (undef on 6809, absent on 6309)
W_CC_CLOBBERED_BEFORE_BRANCH = 2001  # instruction sets CC then D loaded before branch
W_SUGGEST_PSHS           = 2002   # use PSHS/PULS instead of indexed on S


DIAGNOSTIC_MESSAGES = {
    W_CC_CLOBBERED_BEFORE_BRANCH: (
        "Instruction '{insn}' modifies CC flags set by '{compare}' before '{branch}'. "
        "Branch reads stale flags. Move '{branch}' before '{insn}', or re-compare after '{insn}'. "
        "To suppress intentionally: add (!W2001) to this line's comment."
    ),
    W_UNDEFINED_PREDEC1_SU: (
        "Indirect pre-decrement by 1 on {reg} -- [,-{reg}] -- is undefined by Motorola. "
        "Exists on some 6809 silicon but absent on 6309. Portability hazard. "
        "Direct form ,-{reg} is valid. "
        "To suppress intentionally: add (!W2000) to this line's comment."
    ),
    W_SUGGEST_PSHS: (
        "Indexed addressing on S/U stack registers with pre-decrement by 1 is "
        "undefined. Use PSHS/PSHU for stack operations."
    ),
}


def format_diagnostic(code, **kwargs):
    """Format a diagnostic message with keyword substitutions."""
    template = DIAGNOSTIC_MESSAGES.get(code, f"Unknown diagnostic {code}")
    try:
        return template.format(**kwargs)
    except KeyError:
        return template


# ── Register bit patterns for S and U ─────────────────────────────────────────
# From the 6809 postbyte table:
#   X = 0x00 (bits 6-5 = 00)
#   Y = 0x20 (bits 6-5 = 01)
#   U = 0x40 (bits 6-5 = 10)
#   S = 0x60 (bits 6-5 = 11)
# With bit 7 set for standard indexed: X=$80, Y=$A0, U=$C0, S=$E0

REGBITS_S = 0x60   # S register bits (before bit 7 set)
REGBITS_U = 0x40   # U register bits (before bit 7 set)
REGBITS_S_INDEXED = 0xE0   # S in indexed postbyte
REGBITS_U_INDEXED = 0xC0   # U in indexed postbyte

# Instructions that set CC flags used by conditional branches
CC_SETTING_COMPARE = {
    # Explicit comparison/test instructions -- exist ONLY to set CC flags.
    'CMPA', 'CMPB', 'CMPD', 'CMPX', 'CMPY', 'CMPU', 'CMPS',
    'TSTA', 'TSTB', 'TST',
    'BITA', 'BITB',
    # Arithmetic -- sets CC as meaningful output
    'ADDA', 'ADDB', 'ADDD', 'ADCA', 'ADCB',
    'SUBA', 'SUBB', 'SUBD', 'SBCA', 'SBCB',
    # Logic -- sets CC as meaningful output
    'ANDA', 'ANDB', 'ANDCC',
    'ORA',  'ORB',  'ORCC',
    'EORA', 'EORB',
    'COMA', 'COMB', 'COM',
    # Shifts and rotates -- C/N/Z set meaningfully
    'LSLA', 'LSLB', 'LSL',
    'LSRA', 'LSRB', 'LSR',
    'ASLA', 'ASLB', 'ASL',
    'ASRA', 'ASRB', 'ASR',
    'ROLA', 'ROLB', 'ROL',
    'RORA', 'RORB', 'ROR',
    # Inc/Dec/Neg -- N/Z/V set meaningfully
    'NEGA', 'NEGB', 'NEG',
    'DECA', 'DECB', 'DEC',
    'INCA', 'INCB', 'INC',
    # NOTE: LDA/LDB/LDD/LDX/CLR etc. intentionally excluded.
    # Loads and clears set N/Z as a side effect of data movement,
    # not as the programmer's intent. They are not compares.
}

# Instructions that are CC-neutral -- a load between a compare and a
# branch that passes through one of these is still suspicious.
CC_NEUTRAL = {
    'STA', 'STB', 'STD', 'STX', 'STY', 'STU', 'STS',
    'PSHS', 'PULS', 'PSHU', 'PULU',
    'NOP',
    'TFR', 'EXG',
    'LEAX', 'LEAY', 'LEAU', 'LEAS',
    'JSR', 'BSR',
}

# Instructions that clobber N/Z/V/C via ordinary data movement -- the
# suspect middle instruction a programmer accidentally inserts between a
# compare/test and the branch that depends on it. Loading any of D's
# constituent parts, or any index/stack register, or clearing any
# accumulator, sets N/Z (and clears V/C on CLR) as a side effect of the
# move -- not as the programmer's intent -- and will silently invalidate
# a preceding CMPx/TSTx/BITx if it lands between that compare and its
# branch.
#
# NOTE (2026-07-17): this used to be defined twice in this module -- a
# complete version here, immediately followed by a narrower
# {'LDA','LDB','LDD'}-only redefinition that silently won (plain Python
# name rebinding, no error). That meant LDX/LDY/LDU/LDS/CLRA/CLRB/CLR
# never triggered W2001 at all, including the CMPX/LDX/BNE and
# TSTA/CLRA/BEQ patterns -- exactly the class of mistake this diagnostic
# exists to catch. See diagnostics_finding_cc_clobbering_loads_shadowed.txt
# for the full writeup. Fixed by merging into this single definition;
# no other code changes were needed since source_diag.py already
# consumes this set generically (by membership, not by mnemonic), and
# the "no prior compare -> load is the intended CC setter" safeguard in
# source_diag.py's _check_cc_clobber_backward() is unaffected by the
# set's contents -- it's keyed on structure, not on which specific
# mnemonic tripped it.
CC_CLOBBERING_LOADS = {
    'LDA', 'LDB', 'LDD', 'LDX', 'LDY', 'LDU', 'LDS',
    'CLRA', 'CLRB', 'CLR',
}

# Conditional branch mnemonics
CONDITIONAL_BRANCHES = {
    'BEQ', 'BNE', 'BLT', 'BGT', 'BLE', 'BGE',
    'BLO', 'BHI', 'BLS', 'BHS', 'BCC', 'BCS',
    'BMI', 'BPL', 'BVS', 'BVC',
    'LBEQ', 'LBNE', 'LBLT', 'LBGT', 'LBLE', 'LBGE',
    'LBLO', 'LBHI', 'LBLS', 'LBHS', 'LBCC', 'LBCS',
    'LBMI', 'LBPL', 'LBVS', 'LBVC',
}


# ── Diagnostic checks ──────────────────────────────────────────────────────────

def check_predec1_su(reg_bits_with_bit7, mnemonic):
    """
    Check if a pre-decrement by 1 (,-R) uses S or U register.
    Returns (warning_code, kwargs) or None if clean.

    reg_bits_with_bit7: the postbyte register field with bit 7 set
                        e.g. 0xE0 for S, 0xC0 for U
    mnemonic: the instruction mnemonic string e.g. 'STA'
    """
    if reg_bits_with_bit7 == REGBITS_S_INDEXED:
        return (W_UNDEFINED_PREDEC1_SU, {
            'reg': 'S',
            's': 'S',
            'insn': mnemonic,
        })
    if reg_bits_with_bit7 == REGBITS_U_INDEXED:
        return (W_UNDEFINED_PREDEC1_SU, {
            'reg': 'U',
            's': 'U',
            'insn': mnemonic,
        })
    return None


def check_cc_clobber_sequence(prev_mnemonic, curr_mnemonic, next_mnemonic):
    """
    Check for the pattern: COMPARE, LOAD-D, BRANCH
    where the load clobbers CC flags set by the compare.

    prev_mnemonic: instruction before current (e.g. 'CMPD')
    curr_mnemonic: current instruction (e.g. 'LDD')
    next_mnemonic: instruction after current (e.g. 'BNE')

    Returns (warning_code, kwargs) or None if clean.
    """
    if (prev_mnemonic in CC_SETTING_COMPARE and
        curr_mnemonic in CC_CLOBBERING_LOADS and
        next_mnemonic in CONDITIONAL_BRANCHES):
        return (W_CC_CLOBBERED_BEFORE_BRANCH, {
            'insn': curr_mnemonic,
            'compare': prev_mnemonic,
            'branch': next_mnemonic,
        })
    return None


# ── Diagnostic accumulator ─────────────────────────────────────────────────────

class DiagnosticLog:
    """
    Accumulates diagnostic warnings during assembly.
    Separate from the error system -- warnings do not halt assembly.
    """

    def __init__(self):
        self.warnings = []   # list of (line_num, filename, code, message)

    def warn(self, line_num, filename, code, **kwargs):
        msg = format_diagnostic(code, **kwargs)
        self.warnings.append((line_num, filename, code, msg))

    def report(self, file=None):
        """Print all accumulated warnings."""
        import sys
        out = file or sys.stderr
        for line_num, filename, code, msg in self.warnings:
            loc = f"{filename}:{line_num}" if filename else f"line {line_num}"
            print(f"  WARNING [{loc}] W{code}: {msg}", file=out)

    def has_warnings(self):
        return bool(self.warnings)

    def count(self):
        return len(self.warnings)

    def clear(self):
        self.warnings = []
