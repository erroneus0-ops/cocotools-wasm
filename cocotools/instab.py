"""
cocotools/instab.py -- 6809 Instruction Table
Faithful translation of lwasm's instab.c (William Astle, GPL v3)
Source: http://lwtools.projects.l-w.ca/

Each entry in INSTAB:
  key   = mnemonic (uppercase)
  value = dict with:
    'imm'   -- immediate opcode (None if not supported)
    'dir'   -- direct page opcode (None if not supported)
    'idx'   -- indexed opcode (None if not supported)
    'ext'   -- extended opcode (None if not supported)
    'inh'   -- inherent opcode (None if not supported)
    'parse' -- parser class name (see lwasm.py)

Opcodes:
  int < 0x100   -- single byte opcode
  int >= 0x1000 -- two byte opcode (high byte is prefix: 0x10 or 0x11)
  None          -- addressing mode not supported for this instruction

Parser classes:
  'inh'    -- inherent (no operand)
  'gen8'   -- general addressing, 8-bit immediate
  'gen16'  -- general addressing, 16-bit immediate
  'gen0'   -- general addressing, no immediate mode
  'rel8'   -- 8-bit relative branch
  'rel16'  -- 16-bit relative branch
  'relgen' -- auto-size relative (short preferred, long if needed)
  'rtor'   -- register to register (TFR, EXG)
  'rlist'  -- register list (PSHS/PULS/PSHU/PULU)
  'imm8'   -- immediate only (ANDCC, ORCC, CWAI)
  'leax'   -- LEA instructions (indexed only)
  'mem'    -- memory only, no immediate (CLR, NEG, etc.)
"""

# Opcode prefix constants
P10 = 0x1000    # 0x10 prefix
P11 = 0x1100    # 0x11 prefix

INSTAB = {
    # ── 8-bit load/store ─────────────────────────────────────────────────────
    'LDA':  {'imm': 0x86, 'dir': 0x96, 'idx': 0xA6, 'ext': 0xB6, 'parse': 'gen8'},
    'LDB':  {'imm': 0xC6, 'dir': 0xD6, 'idx': 0xE6, 'ext': 0xF6, 'parse': 'gen8'},
    'STA':  {'imm': None, 'dir': 0x97, 'idx': 0xA7, 'ext': 0xB7, 'parse': 'gen0'},
    'STB':  {'imm': None, 'dir': 0xD7, 'idx': 0xE7, 'ext': 0xF7, 'parse': 'gen0'},

    # ── 16-bit load/store ────────────────────────────────────────────────────
    'LDD':  {'imm': 0xCC, 'dir': 0xDC, 'idx': 0xEC, 'ext': 0xFC, 'parse': 'gen16'},
    'LDX':  {'imm': 0x8E, 'dir': 0x9E, 'idx': 0xAE, 'ext': 0xBE, 'parse': 'gen16'},
    'LDY':  {'imm': P10|0x8E, 'dir': P10|0x9E, 'idx': P10|0xAE, 'ext': P10|0xBE, 'parse': 'gen16'},
    'LDU':  {'imm': 0xCE, 'dir': 0xDE, 'idx': 0xEE, 'ext': 0xFE, 'parse': 'gen16'},
    'LDS':  {'imm': P10|0xCE, 'dir': P10|0xDE, 'idx': P10|0xEE, 'ext': P10|0xFE, 'parse': 'gen16'},
    'STD':  {'imm': None, 'dir': 0xDD, 'idx': 0xED, 'ext': 0xFD, 'parse': 'gen0'},
    'STX':  {'imm': None, 'dir': 0x9F, 'idx': 0xAF, 'ext': 0xBF, 'parse': 'gen0'},
    'STY':  {'imm': None, 'dir': P10|0x9F, 'idx': P10|0xAF, 'ext': P10|0xBF, 'parse': 'gen0'},
    'STU':  {'imm': None, 'dir': 0xDF, 'idx': 0xEF, 'ext': 0xFF, 'parse': 'gen0'},
    'STS':  {'imm': None, 'dir': P10|0xDF, 'idx': P10|0xEF, 'ext': P10|0xFF, 'parse': 'gen0'},

    # ── Arithmetic ───────────────────────────────────────────────────────────
    'ADDA': {'imm': 0x8B, 'dir': 0x9B, 'idx': 0xAB, 'ext': 0xBB, 'parse': 'gen8'},
    'ADDB': {'imm': 0xCB, 'dir': 0xDB, 'idx': 0xEB, 'ext': 0xFB, 'parse': 'gen8'},
    'ADDD': {'imm': 0xC3, 'dir': 0xD3, 'idx': 0xE3, 'ext': 0xF3, 'parse': 'gen16'},
    'ADCA': {'imm': 0x89, 'dir': 0x99, 'idx': 0xA9, 'ext': 0xB9, 'parse': 'gen8'},
    'ADCB': {'imm': 0xC9, 'dir': 0xD9, 'idx': 0xE9, 'ext': 0xF9, 'parse': 'gen8'},
    'SUBA': {'imm': 0x80, 'dir': 0x90, 'idx': 0xA0, 'ext': 0xB0, 'parse': 'gen8'},
    'SUBB': {'imm': 0xC0, 'dir': 0xD0, 'idx': 0xE0, 'ext': 0xF0, 'parse': 'gen8'},
    'SUBD': {'imm': 0x83, 'dir': 0x93, 'idx': 0xA3, 'ext': 0xB3, 'parse': 'gen16'},
    'SBCA': {'imm': 0x82, 'dir': 0x92, 'idx': 0xA2, 'ext': 0xB2, 'parse': 'gen8'},
    'SBCB': {'imm': 0xC2, 'dir': 0xD2, 'idx': 0xE2, 'ext': 0xF2, 'parse': 'gen8'},
    'MUL':  {'inh': 0x3D, 'parse': 'inh'},
    'DAA':  {'inh': 0x19, 'parse': 'inh'},
    'SEX':  {'inh': 0x1D, 'parse': 'inh'},
    'ABX':  {'inh': 0x3A, 'parse': 'inh'},

    # ── Increment/Decrement ──────────────────────────────────────────────────
    'INCA': {'inh': 0x4C, 'parse': 'inh'},
    'INCB': {'inh': 0x5C, 'parse': 'inh'},
    'INC':  {'imm': None, 'dir': 0x0C, 'idx': 0x6C, 'ext': 0x7C, 'parse': 'mem'},
    'DECA': {'inh': 0x4A, 'parse': 'inh'},
    'DECB': {'inh': 0x5A, 'parse': 'inh'},
    'DEC':  {'imm': None, 'dir': 0x0A, 'idx': 0x6A, 'ext': 0x7A, 'parse': 'mem'},

    # ── Logic ────────────────────────────────────────────────────────────────
    'ANDA': {'imm': 0x84, 'dir': 0x94, 'idx': 0xA4, 'ext': 0xB4, 'parse': 'gen8'},
    'ANDB': {'imm': 0xC4, 'dir': 0xD4, 'idx': 0xE4, 'ext': 0xF4, 'parse': 'gen8'},
    'ORA':  {'imm': 0x8A, 'dir': 0x9A, 'idx': 0xAA, 'ext': 0xBA, 'parse': 'gen8'},
    'ORB':  {'imm': 0xCA, 'dir': 0xDA, 'idx': 0xEA, 'ext': 0xFA, 'parse': 'gen8'},
    'EORA': {'imm': 0x88, 'dir': 0x98, 'idx': 0xA8, 'ext': 0xB8, 'parse': 'gen8'},
    'EORB': {'imm': 0xC8, 'dir': 0xD8, 'idx': 0xE8, 'ext': 0xF8, 'parse': 'gen8'},
    'ANDCC':{'imm': 0x1C, 'parse': 'imm8'},
    'ORCC': {'imm': 0x1A, 'parse': 'imm8'},
    'BITA': {'imm': 0x85, 'dir': 0x95, 'idx': 0xA5, 'ext': 0xB5, 'parse': 'gen8'},
    'BITB': {'imm': 0xC5, 'dir': 0xD5, 'idx': 0xE5, 'ext': 0xF5, 'parse': 'gen8'},

    # ── Shift/Rotate ─────────────────────────────────────────────────────────
    'ASLA': {'inh': 0x48, 'parse': 'inh'},
    'ASLB': {'inh': 0x58, 'parse': 'inh'},
    'ASL':  {'imm': None, 'dir': 0x08, 'idx': 0x68, 'ext': 0x78, 'parse': 'mem'},
    'LSLA': {'inh': 0x48, 'parse': 'inh'},   # same as ASLA
    'LSLB': {'inh': 0x58, 'parse': 'inh'},
    'LSL':  {'imm': None, 'dir': 0x08, 'idx': 0x68, 'ext': 0x78, 'parse': 'mem'},
    'ASRA': {'inh': 0x47, 'parse': 'inh'},
    'ASRB': {'inh': 0x57, 'parse': 'inh'},
    'ASR':  {'imm': None, 'dir': 0x07, 'idx': 0x67, 'ext': 0x77, 'parse': 'mem'},
    'LSRA': {'inh': 0x44, 'parse': 'inh'},
    'LSRB': {'inh': 0x54, 'parse': 'inh'},
    'LSR':  {'imm': None, 'dir': 0x04, 'idx': 0x64, 'ext': 0x74, 'parse': 'mem'},
    'ROLA': {'inh': 0x49, 'parse': 'inh'},
    'ROLB': {'inh': 0x59, 'parse': 'inh'},
    'ROL':  {'imm': None, 'dir': 0x09, 'idx': 0x69, 'ext': 0x79, 'parse': 'mem'},
    'RORA': {'inh': 0x46, 'parse': 'inh'},
    'RORB': {'inh': 0x56, 'parse': 'inh'},
    'ROR':  {'imm': None, 'dir': 0x06, 'idx': 0x66, 'ext': 0x76, 'parse': 'mem'},

    # ── Compare ──────────────────────────────────────────────────────────────
    'CMPA': {'imm': 0x81, 'dir': 0x91, 'idx': 0xA1, 'ext': 0xB1, 'parse': 'gen8'},
    'CMPB': {'imm': 0xC1, 'dir': 0xD1, 'idx': 0xE1, 'ext': 0xF1, 'parse': 'gen8'},
    'CMPD': {'imm': P10|0x83, 'dir': P10|0x93, 'idx': P10|0xA3, 'ext': P10|0xB3, 'parse': 'gen16'},
    'CMPX': {'imm': 0x8C, 'dir': 0x9C, 'idx': 0xAC, 'ext': 0xBC, 'parse': 'gen16'},
    'CMPY': {'imm': P10|0x8C, 'dir': P10|0x9C, 'idx': P10|0xAC, 'ext': P10|0xBC, 'parse': 'gen16'},
    'CMPU': {'imm': P11|0x83, 'dir': P11|0x93, 'idx': P11|0xA3, 'ext': P11|0xB3, 'parse': 'gen16'},
    'CMPS': {'imm': P11|0x8C, 'dir': P11|0x9C, 'idx': P11|0xAC, 'ext': P11|0xBC, 'parse': 'gen16'},
    'TSTA': {'inh': 0x4D, 'parse': 'inh'},
    'TSTB': {'inh': 0x5D, 'parse': 'inh'},
    'TST':  {'imm': None, 'dir': 0x0D, 'idx': 0x6D, 'ext': 0x7D, 'parse': 'mem'},

    # ── Clear/Negate/Complement ──────────────────────────────────────────────
    'CLRA': {'inh': 0x4F, 'parse': 'inh'},
    'CLRB': {'inh': 0x5F, 'parse': 'inh'},
    'CLR':  {'imm': None, 'dir': 0x0F, 'idx': 0x6F, 'ext': 0x7F, 'parse': 'mem'},
    'NEGA': {'inh': 0x40, 'parse': 'inh'},
    'NEGB': {'inh': 0x50, 'parse': 'inh'},
    'NEG':  {'imm': None, 'dir': 0x00, 'idx': 0x60, 'ext': 0x70, 'parse': 'mem'},
    'COMA': {'inh': 0x43, 'parse': 'inh'},
    'COMB': {'inh': 0x53, 'parse': 'inh'},
    'COM':  {'imm': None, 'dir': 0x03, 'idx': 0x63, 'ext': 0x73, 'parse': 'mem'},

    # ── Jumps and Calls ──────────────────────────────────────────────────────
    'JMP':  {'imm': None, 'dir': 0x0E, 'idx': 0x6E, 'ext': 0x7E, 'parse': 'gen0'},
    'JSR':  {'imm': None, 'dir': 0x9D, 'idx': 0xAD, 'ext': 0xBD, 'parse': 'gen0'},
    'BSR':  {'rel': 0x8D, 'parse': 'rel8'},
    'LBSR': {'rel': 0x17, 'parse': 'rel16'},
    'RTS':  {'inh': 0x39, 'parse': 'inh'},
    'RTI':  {'inh': 0x3B, 'parse': 'inh'},

    # ── Branches (short) ─────────────────────────────────────────────────────
    'BRA':  {'rel': 0x20, 'parse': 'rel8'},
    'BRN':  {'rel': 0x21, 'parse': 'rel8'},
    'BHI':  {'rel': 0x22, 'parse': 'rel8'},
    'BLS':  {'rel': 0x23, 'parse': 'rel8'},
    'BHS':  {'rel': 0x24, 'parse': 'rel8'},  # same as BCC
    'BCC':  {'rel': 0x24, 'parse': 'rel8'},
    'BLO':  {'rel': 0x25, 'parse': 'rel8'},  # same as BCS
    'BCS':  {'rel': 0x25, 'parse': 'rel8'},
    'BNE':  {'rel': 0x26, 'parse': 'rel8'},
    'BEQ':  {'rel': 0x27, 'parse': 'rel8'},
    'BVC':  {'rel': 0x28, 'parse': 'rel8'},
    'BVS':  {'rel': 0x29, 'parse': 'rel8'},
    'BPL':  {'rel': 0x2A, 'parse': 'rel8'},
    'BMI':  {'rel': 0x2B, 'parse': 'rel8'},
    'BGE':  {'rel': 0x2C, 'parse': 'rel8'},
    'BLT':  {'rel': 0x2D, 'parse': 'rel8'},
    'BGT':  {'rel': 0x2E, 'parse': 'rel8'},
    'BLE':  {'rel': 0x2F, 'parse': 'rel8'},

    # ── Branches (long) ──────────────────────────────────────────────────────
    'LBRA': {'rel': 0x16, 'parse': 'rel16'},
    'LBRN': {'rel': P10|0x21, 'parse': 'rel16'},
    'LBHI': {'rel': P10|0x22, 'parse': 'rel16'},
    'LBLS': {'rel': P10|0x23, 'parse': 'rel16'},
    'LBHS': {'rel': P10|0x24, 'parse': 'rel16'},
    'LBCC': {'rel': P10|0x24, 'parse': 'rel16'},
    'LBLO': {'rel': P10|0x25, 'parse': 'rel16'},
    'LBCS': {'rel': P10|0x25, 'parse': 'rel16'},
    'LBNE': {'rel': P10|0x26, 'parse': 'rel16'},
    'LBEQ': {'rel': P10|0x27, 'parse': 'rel16'},
    'LBVC': {'rel': P10|0x28, 'parse': 'rel16'},
    'LBVS': {'rel': P10|0x29, 'parse': 'rel16'},
    'LBPL': {'rel': P10|0x2A, 'parse': 'rel16'},
    'LBMI': {'rel': P10|0x2B, 'parse': 'rel16'},
    'LBGE': {'rel': P10|0x2C, 'parse': 'rel16'},
    'LBLT': {'rel': P10|0x2D, 'parse': 'rel16'},
    'LBGT': {'rel': P10|0x2E, 'parse': 'rel16'},
    'LBLE': {'rel': P10|0x2F, 'parse': 'rel16'},

    # ── LEA instructions (indexed only) ──────────────────────────────────────
    'LEAX': {'idx': 0x30, 'parse': 'leax'},
    'LEAY': {'idx': 0x31, 'parse': 'leax'},
    'LEAS': {'idx': 0x32, 'parse': 'leax'},
    'LEAU': {'idx': 0x33, 'parse': 'leax'},

    # ── Stack ────────────────────────────────────────────────────────────────
    'PSHS': {'imm': 0x34, 'parse': 'rlist'},
    'PULS': {'imm': 0x35, 'parse': 'rlist'},
    'PSHU': {'imm': 0x36, 'parse': 'rlist'},
    'PULU': {'imm': 0x37, 'parse': 'rlist'},

    # ── Register transfer ────────────────────────────────────────────────────
    'TFR':  {'imm': 0x1F, 'parse': 'rtor'},
    'EXG':  {'imm': 0x1E, 'parse': 'rtor'},

    # ── Miscellaneous ────────────────────────────────────────────────────────
    'NOP':  {'inh': 0x12, 'parse': 'inh'},
    'SYNC': {'inh': 0x13, 'parse': 'inh'},
    'CWAI': {'imm': 0x3C, 'parse': 'imm8'},
    'SWI':  {'inh': 0x3F, 'parse': 'inh'},
    'SWI2': {'inh': P10|0x3F, 'parse': 'inh'},
    'SWI3': {'inh': P11|0x3F, 'parse': 'inh'},
}

# ── Register encoding tables ──────────────────────────────────────────────────

# Register name -> (register number for TFR/EXG postbyte)
RTOR_REGS = {
    'D': 0, 'X': 1, 'Y': 2, 'U': 3, 'S': 4, 'PC': 5,
    'A': 8, 'B': 9, 'CC': 10, 'DP': 11,
}

# Register name -> bit position in PSHS/PULS register list byte
RLIST_BITS = {
    'CC': 0x01, 'A': 0x02, 'B': 0x04, 'DP': 0x08,
    'X':  0x10, 'Y': 0x20, 'U': 0x40, 'S': 0x40,  # U and S share bit (PSHS vs PSHU)
    'PC': 0x80,
}

# Indexed base register -> postbyte bits [6:5]
INDEXED_REG_BITS = {
    'X': 0b00, 'Y': 0b01, 'U': 0b10, 'S': 0b11,
}

# Verify key entries
if __name__ == '__main__':
    # Spot-check against known lwasm output
    checks = [
        ('LDA', 'imm', 0x86),
        ('LDB', 'idx', 0xE6),
        ('CMPB','imm', 0xC1),
        ('BEQ', 'rel', 0x27),
        ('BCS', 'rel', 0x25),
        ('STA', 'idx', 0xA7),
        ('JSR', 'ext', 0xBD),
        ('RTS', 'inh', 0x39),
        ('NOP', 'inh', 0x12),
        ('LEAX','idx', 0x30),
        ('LEAY','idx', 0x31),
        ('LDD', 'imm', 0xCC),
        ('STD', 'dir', 0xDD),
        ('LDS', 'imm', P10|0xCE),
        ('LBNE','rel', P10|0x26),
    ]
    errors = 0
    for mnem, mode, expected in checks:
        got = INSTAB[mnem][mode]
        if got != expected:
            print(f'FAIL: {mnem} {mode}: expected ${expected:04X}, got ${got:04X}')
            errors += 1
    if errors == 0:
        print(f'All {len(checks)} spot checks passed')
    print(f'Total instructions: {len(INSTAB)}')
