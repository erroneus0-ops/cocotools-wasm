"""
cocotools/lwasm.py — 6809 Two-Pass Assembler
Phase 1: DECB and raw output, all 6809 instructions, no macros or conditionals.

Faithful translation of lwasm behaviour (William Astle, LWTools, GPL v3).
Source: http://lwtools.projects.l-w.ca/

Key design decisions matching lwasm:
  - PCR addressing defaults to 16-bit when the target is a forward reference.
    Once committed in Pass 1, the 16-bit size is kept in Pass 2 even if the
    offset now fits in 8 bits.  This matches the lwasm reference binaries.
  - Auto direct/extended: symbol value < 0x100 and high byte == DP -> direct.
    Unknown symbol in Pass 1 -> extended (conservative).
  - DECB preamble: 0x00 + len16 + load_addr16; postamble: 0xFF + 0x00 0x00 + exec16.
"""

import re
from .instab import INSTAB

# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class AsmError(Exception):
    def __init__(self, msg, lineno=None):
        if lineno is not None:
            super().__init__(f"line {lineno}: {msg}")
        else:
            super().__init__(msg)
        self.lineno = lineno


# ─────────────────────────────────────────────────────────────────────────────
# Addressing mode constants
# ─────────────────────────────────────────────────────────────────────────────

IMM = 'imm'   # immediate: #expr
DIR = 'dir'   # direct page: <expr  or  expr with high-byte == DP
IDX = 'idx'   # indexed: expr,REG  or  ,REG++  etc.
EXT = 'ext'   # extended: >expr  or  expr with high-byte != DP
INH = 'inh'   # inherent: no operand

# ─────────────────────────────────────────────────────────────────────────────
# Register tables
# ─────────────────────────────────────────────────────────────────────────────

# Postbyte register bits for indexed addressing (bits [6:5])
IDX_REGS = {'X': 0, 'Y': 1, 'U': 2, 'S': 3}

# TFR/EXG register encoding
TFR_REGS = {
    'D': 0, 'X': 1, 'Y': 2, 'U': 3, 'S': 4, 'PC': 5,
    'A': 8, 'B': 9, 'CC': 10, 'DP': 11,
}

# PSHS/PULS register bitmask (S-stack)
RLIST_S = {
    'CC': 0x01, 'A': 0x02, 'B': 0x04, 'DP': 0x08,
    'X': 0x10, 'Y': 0x20, 'U': 0x40, 'PC': 0x80,
}
# PSHU/PULU register bitmask (U-stack)
RLIST_U = {
    'CC': 0x01, 'A': 0x02, 'B': 0x04, 'DP': 0x08,
    'X': 0x10, 'Y': 0x20, 'S': 0x40, 'PC': 0x80,
}

# Directives that produce bytes
BYTE_DIRECTIVES = {'FCB', 'FDB', 'FCC', 'FCS', 'FCN', 'RMB', 'ZMB',
                   'ORG', 'EQU', 'SET', 'END', 'SETDP'}

# ─────────────────────────────────────────────────────────────────────────────
# Expression evaluator
# ─────────────────────────────────────────────────────────────────────────────
# Grammar (lowest to highest precedence):
#   expr    ::= bitwise (('+' | '-') bitwise)*
#   bitwise ::= term (('|' | '&' | '^') term)*
#   term    ::= factor (('*' | '/') factor)*
#   factor  ::= ('-' | '~') factor | '(' expr ')' | atom
#   atom    ::= hex | bin | oct | dec | char | '*' | symbol
#
# Special: '*' in atom position = current PC.
# '*' in term position (between two factors) = multiplication.

_UNRESOLVED = object()   # sentinel: symbol not yet in table

def _eval_expr(s, pos, symbols, pc, lineno):
    """Recursive descent. Returns (value_or_UNRESOLVED, new_pos)."""
    val, pos = _parse_bitwise(s, pos, symbols, pc, lineno)
    while pos < len(s) and s[pos] in '+-':
        op = s[pos]; pos += 1
        rhs, pos = _parse_bitwise(s, pos, symbols, pc, lineno)
        if val is _UNRESOLVED or rhs is _UNRESOLVED:
            val = _UNRESOLVED
        elif op == '+':
            val = val + rhs
        else:
            val = val - rhs
    return val, pos

def _parse_bitwise(s, pos, symbols, pc, lineno):
    val, pos = _parse_term(s, pos, symbols, pc, lineno)
    while pos < len(s) and s[pos] in '|&^':
        op = s[pos]; pos += 1
        rhs, pos = _parse_term(s, pos, symbols, pc, lineno)
        if val is _UNRESOLVED or rhs is _UNRESOLVED:
            val = _UNRESOLVED
        elif op == '|':
            val = val | rhs
        elif op == '&':
            val = val & rhs
        else:
            val = val ^ rhs
    return val, pos

def _parse_term(s, pos, symbols, pc, lineno):
    val, pos = _parse_factor(s, pos, symbols, pc, lineno)
    while pos < len(s) and s[pos] in '*/':
        op = s[pos]; pos += 1
        rhs, pos = _parse_factor(s, pos, symbols, pc, lineno)
        if val is _UNRESOLVED or rhs is _UNRESOLVED:
            val = _UNRESOLVED
        elif op == '*':
            val = val * rhs
        else:
            val = val // rhs
    return val, pos

def _parse_factor(s, pos, symbols, pc, lineno):
    s = s.strip() if pos == 0 else s
    # skip whitespace
    while pos < len(s) and s[pos] == ' ':
        pos += 1
    if pos >= len(s):
        raise AsmError(f"unexpected end of expression: '{s}'", lineno)
    if s[pos] == '-':
        val, pos = _parse_factor(s, pos + 1, symbols, pc, lineno)
        return (_UNRESOLVED if val is _UNRESOLVED else -val), pos
    if s[pos] == '~':
        val, pos = _parse_factor(s, pos + 1, symbols, pc, lineno)
        return (_UNRESOLVED if val is _UNRESOLVED else (~val & 0xFFFF)), pos
    if s[pos] == '(':
        val, pos = _eval_expr(s, pos + 1, symbols, pc, lineno)
        while pos < len(s) and s[pos] == ' ':
            pos += 1
        if pos >= len(s) or s[pos] != ')':
            raise AsmError(f"missing ')' in expression: '{s}'", lineno)
        return val, pos + 1
    return _parse_atom(s, pos, symbols, pc, lineno)

def _parse_atom(s, pos, symbols, pc, lineno):
    while pos < len(s) and s[pos] == ' ':
        pos += 1
    if pos >= len(s):
        raise AsmError(f"expected value in expression: '{s}'", lineno)
    ch = s[pos]

    # Hex literal: $XXXX
    if ch == '$':
        end = pos + 1
        while end < len(s) and s[end] in '0123456789ABCDEFabcdef':
            end += 1
        if end == pos + 1:
            raise AsmError(f"invalid hex literal: '{s[pos:]}'", lineno)
        return int(s[pos+1:end], 16), end

    # Binary literal: %BBBB
    if ch == '%':
        end = pos + 1
        while end < len(s) and s[end] in '01':
            end += 1
        return int(s[pos+1:end], 2), end

    # Octal literal: @OOO
    if ch == '@':
        end = pos + 1
        while end < len(s) and s[end] in '01234567':
            end += 1
        return int(s[pos+1:end], 8), end

    # Hex literal: 0xXXXX
    if ch == '0' and pos + 1 < len(s) and s[pos+1] in 'xX':
        end = pos + 2
        while end < len(s) and s[end] in '0123456789ABCDEFabcdef':
            end += 1
        return int(s[pos+2:end], 16), end

    # Character literal: 'C  or  'C'  (closing quote optional)
    if ch == "'":
        if pos + 1 >= len(s):
            raise AsmError(f"empty character literal", lineno)
        char_val = ord(s[pos+1])
        new_pos  = pos + 2
        if new_pos < len(s) and s[new_pos] == "'":
            new_pos += 1   # consume optional closing quote
        return char_val, new_pos

    # Current PC: * (only in atom position, not multiplication)
    if ch == '*':
        return pc, pos + 1

    # Decimal literal
    if ch.isdigit():
        end = pos
        while end < len(s) and s[end].isdigit():
            end += 1
        return int(s[pos:end]), end

    # Symbol
    if ch.isalpha() or ch == '_':
        end = pos
        while end < len(s) and (s[end].isalnum() or s[end] in '_.$'):
            end += 1
        name = s[pos:end]
        if name.upper() in symbols:
            v = symbols[name.upper()]
            return (v if v is not None else _UNRESOLVED), end
        return _UNRESOLVED, end

    raise AsmError(f"unexpected character '{ch}' in expression: '{s}'", lineno)


def eval_expr(s, symbols, pc, lineno=None):
    """
    Evaluate expression string s.
    Returns int, or _UNRESOLVED if any symbol is undefined.
    """
    s = s.strip()
    val, pos = _eval_expr(s, 0, symbols, pc, lineno)
    # consume trailing whitespace
    while pos < len(s) and s[pos] == ' ':
        pos += 1
    if pos != len(s):
        raise AsmError(f"junk at end of expression: '{s[pos:]}'", lineno)
    return val


def is_unresolved(v):
    return v is _UNRESOLVED


# ─────────────────────────────────────────────────────────────────────────────
# Source line tokenizer
# ─────────────────────────────────────────────────────────────────────────────

def tokenize_line(raw, lineno):
    """
    Parse one source line.
    Returns (label, mnemonic, operand) — all str or None.
    Mnemonic is uppercased. Label case is preserved.
    """
    line = raw.rstrip('\n\r')

    # Strip comment (but not inside string literals)
    out = []
    in_str = False
    for ch in line:
        if ch == '"':
            in_str = not in_str
        if ch == ';' and not in_str:
            break
        out.append(ch)
    line = ''.join(out).rstrip()

    if not line.strip():
        return None, None, None

    # Determine label: present if line starts with non-whitespace
    label = None
    rest = line

    if line and line[0] not in ' \t':
        # Token at column 0 is a label
        # It may optionally end with a colon
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_$.]*)(:?)\s*(.*)', line)
        if m:
            label = m.group(1)
            rest = m.group(3)
        else:
            # Unexpected — treat whole line as error
            raise AsmError(f"cannot parse line: '{line}'", lineno)
    else:
        rest = line.lstrip()

    if not rest:
        return label, None, None

    # Split mnemonic from operand
    parts = rest.split(None, 1)
    mnemonic = parts[0].upper()
    operand = parts[1].strip() if len(parts) > 1 else None

    return label, mnemonic, operand


# ─────────────────────────────────────────────────────────────────────────────
# Indexed postbyte encoder
# ─────────────────────────────────────────────────────────────────────────────

def encode_indexed(operand, pc, instr_end, symbols, lineno, committed_size=None):
    """
    Encode an indexed operand.  Returns bytes (postbyte + any offset bytes).
    pc: address of the instruction opcode byte.
    instr_end: address of the first byte AFTER this instruction (for PCR calc).
    committed_size: if not None, the number of bytes already committed for the
                    postbyte+offset portion (used to preserve Pass 1 decisions).
    """
    indirect = False
    op = operand.strip()

    # Check for outer brackets: [...]  -> indirect
    if op.startswith('[') and op.endswith(']'):
        indirect = True
        op = op[1:-1].strip()

    # Extended indirect: [absolute_addr]  (no comma, no register)
    # Detected by: indirect=True and no comma in operand, or comma but not a
    # recognised register after it.
    if indirect and ',' not in op:
        # Evaluate as 16-bit address
        val = eval_expr(op, symbols, pc, lineno)
        if is_unresolved(val):
            val = 0
        val &= 0xFFFF
        return bytes([0x9F, (val >> 8) & 0xFF, val & 0xFF])

    # Split on comma to get offset and register parts
    # Handle the tricky case of  ,-R  and ,--R  (no offset before comma)
    if ',' not in op:
        raise AsmError(f"indexed operand missing comma: '{operand}'", lineno)

    comma = op.index(',')
    offset_str = op[:comma].strip()
    reg_str    = op[comma+1:].strip().upper()

    # PCR / PC relative
    if reg_str in ('PCR', 'PC'):
        val = eval_expr(offset_str, symbols, pc, lineno)
        if is_unresolved(val):
            # Forward reference: commit to 16-bit
            use16 = True
        else:
            rel = val - instr_end
            # If we already committed a size in Pass 1, honour it
            if committed_size == 2:
                use16 = False   # 1 postbyte + 1 offset byte
            elif committed_size == 3:
                use16 = True    # 1 postbyte + 2 offset bytes
            else:
                use16 = not (-128 <= rel <= 127)

        if use16:
            if is_unresolved(val):
                rel = 0
            else:
                rel = val - instr_end
            hi = (rel >> 8) & 0xFF
            lo = rel & 0xFF
            result = bytes([0x8D, hi, lo])
        else:
            rel = (val - instr_end) & 0xFF
            result = bytes([0x8C, rel])

        if indirect:
            pb = result[0] | 0x10
            result = bytes([pb]) + result[1:]
        return result

    # Auto-increment / auto-decrement
    if reg_str.endswith('++'):
        base = reg_str[:-2]
        if base not in IDX_REGS:
            raise AsmError(f"unknown index register '{base}'", lineno)
        rb = IDX_REGS[base]
        pb = 0x81 | (rb << 5)
        if indirect: pb |= 0x10
        return bytes([pb])

    if reg_str.endswith('+'):
        base = reg_str[:-1]
        if base not in IDX_REGS:
            raise AsmError(f"unknown index register '{base}'", lineno)
        rb = IDX_REGS[base]
        pb = 0x80 | (rb << 5)
        # No-increment ,[R]+ has no indirect form in 6809
        return bytes([pb])

    if reg_str.startswith('--'):
        base = reg_str[2:]
        if base not in IDX_REGS:
            raise AsmError(f"unknown index register '{base}'", lineno)
        rb = IDX_REGS[base]
        pb = 0x83 | (rb << 5)
        if indirect: pb |= 0x10
        return bytes([pb])

    if reg_str.startswith('-'):
        base = reg_str[1:]
        if base not in IDX_REGS:
            raise AsmError(f"unknown index register '{base}'", lineno)
        rb = IDX_REGS[base]
        pb = 0x82 | (rb << 5)
        return bytes([pb])

    # Accumulator offset: A,R  B,R  D,R
    if offset_str.upper() in ('A', 'B', 'D'):
        if reg_str not in IDX_REGS:
            raise AsmError(f"unknown index register '{reg_str}'", lineno)
        rb = IDX_REGS[reg_str]
        acc_pb = {'A': 0x86, 'B': 0x85, 'D': 0x8B}[offset_str.upper()]
        pb = acc_pb | (rb << 5)
        if indirect: pb |= 0x10
        return bytes([pb])

    # No-offset: ,R
    if offset_str == '':
        if reg_str not in IDX_REGS:
            raise AsmError(f"unknown index register '{reg_str}'", lineno)
        rb = IDX_REGS[reg_str]
        pb = 0x84 | (rb << 5)
        if indirect: pb |= 0x10
        return bytes([pb])

    # Numeric offset: n,R
    if reg_str not in IDX_REGS:
        raise AsmError(f"unknown index register '{reg_str}'", lineno)
    rb = IDX_REGS[reg_str]

    val = eval_expr(offset_str, symbols, pc, lineno)
    if is_unresolved(val):
        # Use 16-bit by default
        pb = 0x89 | (rb << 5)
        if indirect: pb |= 0x10
        return bytes([pb, 0x00, 0x00])

    # Choose 5-bit, 8-bit, or 16-bit based on value and committed_size
    if committed_size == 1:
        # 5-bit signed: just postbyte
        offset5 = val & 0x1F
        pb = offset5 | (rb << 5)
        return bytes([pb])
    elif committed_size == 2:
        pb = 0x88 | (rb << 5)
        if indirect: pb |= 0x10
        return bytes([pb, val & 0xFF])
    elif committed_size == 3:
        pb = 0x89 | (rb << 5)
        if indirect: pb |= 0x10
        return bytes([pb, (val >> 8) & 0xFF, val & 0xFF])
    else:
        # Auto-choose
        if not indirect and -16 <= val <= 15:
            offset5 = val & 0x1F
            pb = offset5 | (rb << 5)
            return bytes([pb])
        elif -128 <= val <= 127:
            pb = 0x88 | (rb << 5)
            if indirect: pb |= 0x10
            return bytes([pb, val & 0xFF])
        else:
            pb = 0x89 | (rb << 5)
            if indirect: pb |= 0x10
            return bytes([pb, (val >> 8) & 0xFF, val & 0xFF])


def indexed_size(operand, symbols, pc, lineno):
    """
    Estimate the size (in bytes) of the postbyte+offset for an indexed operand.
    For PCR forward refs, always returns 3 (16-bit).
    Returns (size, is_forward_ref).
    """
    indirect = False
    op = operand.strip()
    if op.startswith('[') and op.endswith(']'):
        indirect = True
        op = op[1:-1].strip()

    # Extended indirect: [addr]
    if indirect and ',' not in op:
        return 3, False  # postbyte(1) + addr16(2)

    if ',' not in op:
        raise AsmError(f"indexed operand missing comma: '{operand}'", lineno)

    comma = op.index(',')
    offset_str = op[:comma].strip()
    reg_str    = op[comma+1:].strip().upper()

    if reg_str in ('PCR', 'PC'):
        val = eval_expr(offset_str, symbols, pc, lineno)
        if is_unresolved(val):
            return 3, True   # forward ref -> 16-bit
        rel = val - (pc + 2)  # rough: will be refined in emit
        if -128 <= rel <= 127:
            return 2, False
        return 3, False

    if reg_str in ('++', '--') or reg_str.endswith('++') or reg_str.endswith('+') \
            or reg_str.startswith('--') or reg_str.startswith('-'):
        return 1, False

    if offset_str == '':
        return 1, False

    if offset_str.upper() in ('A', 'B', 'D'):
        return 1, False

    # Numeric offset
    val = eval_expr(offset_str, symbols, pc, lineno)
    if is_unresolved(val):
        return 3, True
    if not indirect and -16 <= val <= 15:
        return 1, False
    if -128 <= val <= 127:
        return 2, False
    return 3, False


# ─────────────────────────────────────────────────────────────────────────────
# Opcode emission helpers
# ─────────────────────────────────────────────────────────────────────────────

def opcode_bytes(opcode):
    """Return 1 or 2 bytes for an opcode (handles P10/P11 prefix)."""
    if opcode >= 0x1000:
        prefix = (opcode >> 8) & 0xFF
        op     = opcode & 0xFF
        return bytes([prefix, op])
    return bytes([opcode & 0xFF])


def opcode_size(opcode):
    return 2 if opcode >= 0x1000 else 1


def _main_opcode(entry):
    """Return the first non-None opcode value in an INSTAB entry."""
    for key in ('rel', 'inh', 'imm', 'dir', 'idx', 'ext'):
        v = entry.get(key)
        if v is not None:
            return v
    return 0x00


# ─────────────────────────────────────────────────────────────────────────────
# Instruction size estimation (Pass 1)
# ─────────────────────────────────────────────────────────────────────────────

def instruction_size(mnemonic, operand, symbols, pc, dp, lineno):
    """
    Estimate instruction size in bytes.
    Returns (size, is_pcr_forward_ref).
    is_pcr_forward_ref=True means we committed to 16-bit PCR; Pass 2 must honour that.
    """
    if mnemonic not in INSTAB:
        raise AsmError(f"unknown mnemonic '{mnemonic}'", lineno)

    entry   = INSTAB[mnemonic]
    parse   = entry['parse']
    op_size = opcode_size(_main_opcode(entry))

    # Inherent: just the opcode
    if parse == 'inh':
        return opcode_size(entry['inh']), False

    # Immediate-only (ANDCC, ORCC, CWAI)
    if parse == 'imm8':
        return opcode_size(entry['imm']) + 1, False

    # Relative branches: always 2 bytes (opcode + 8-bit offset)
    if parse == 'rel8':
        return opcode_size(entry['rel']) + 1, False

    # Long relative branches: always 4 bytes (opcode(1-2) + 16-bit offset)
    if parse == 'rel16':
        return opcode_size(entry['rel']) + 2, False

    # Auto-size relative (LBRA/LBXX with relgen): always use long form
    if parse == 'relgen':
        # Use long form (rel16)
        return opcode_size(entry['rel']) + 2, False

    # LEA instructions: indexed only
    if parse == 'leax':
        if operand is None:
            raise AsmError(f"LEA requires indexed operand", lineno)
        idx_sz, fwd = indexed_size(operand, symbols, pc, lineno)
        return 1 + idx_sz, fwd    # opcode(1) + postbyte+offset

    # Register list (PSHS/PULS/PSHU/PULU): opcode + 1 byte mask
    if parse == 'rlist':
        return opcode_size(entry['imm']) + 1, False

    # Register-to-register (TFR/EXG): opcode + 1 byte
    if parse == 'rtor':
        return opcode_size(entry['imm']) + 1, False

    # No operand given: try inherent
    if operand is None:
        if 'inh' in entry and entry['inh'] is not None:
            return opcode_size(entry['inh']), False
        raise AsmError(f"'{mnemonic}' requires operand", lineno)

    op = operand.strip()

    # Immediate
    if op.startswith('#'):
        opc = entry.get('imm')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no immediate mode", lineno)
        imm_sz = 1 if parse in ('gen8', 'imm8') else 2
        return opcode_size(opc) + imm_sz, False

    # Forced direct
    if op.startswith('<'):
        opc = entry.get('dir')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no direct mode", lineno)
        return opcode_size(opc) + 1, False

    # Forced extended
    if op.startswith('>'):
        opc = entry.get('ext')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no extended mode", lineno)
        return opcode_size(opc) + 2, False

    # Indexed (contains comma, or starts/ends with brackets, or ,reg pattern)
    if op.startswith('[') or _is_indexed(op):
        opc = entry.get('idx')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no indexed mode", lineno)
        idx_sz, fwd = indexed_size(op, symbols, pc, lineno)
        return opcode_size(opc) + idx_sz, fwd

    # Auto direct/extended
    parse_class = parse
    val = eval_expr(op, symbols, pc, lineno)
    if is_unresolved(val):
        # Unknown forward ref: use extended
        opc = entry.get('ext') or entry.get('dir')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no memory mode", lineno)
        if entry.get('ext') is not None:
            return opcode_size(entry['ext']) + 2, False
        return opcode_size(entry['dir']) + 1, False
    elif (val >> 8) == dp and entry.get('dir') is not None:
        return opcode_size(entry['dir']) + 1, False
    else:
        opc = entry.get('ext')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no extended mode", lineno)
        return opcode_size(opc) + 2, False


def _is_indexed(op):
    """Heuristic: does this operand look like an indexed expression?"""
    # Contains comma (register offset), or auto-inc/dec patterns
    if not op:
        return False
    # Check for ,REG patterns
    if ',' in op:
        # Split on comma: right side should be a register or auto-inc variant
        comma = op.index(',')
        reg = op[comma+1:].strip().upper()
        # Remove trailing + or leading -
        reg_base = reg.rstrip('+').lstrip('-')
        if reg_base in ('X', 'Y', 'U', 'S', 'PC', 'PCR') or reg in IDX_REGS:
            return True
        if reg.endswith('++') or reg.endswith('+') or reg.startswith('--') \
                or reg.startswith('-'):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Instruction byte emission (Pass 2)
# ─────────────────────────────────────────────────────────────────────────────

def instruction_bytes(mnemonic, operand, symbols, pc, dp, lineno,
                      committed_size=None, committed_pcr16=False):
    """
    Emit bytes for one instruction.  committed_size is the total size from Pass 1.
    committed_pcr16=True means we must use 16-bit PCR regardless of offset.
    """
    if mnemonic not in INSTAB:
        raise AsmError(f"unknown mnemonic '{mnemonic}'", lineno)

    entry  = INSTAB[mnemonic]
    parse  = entry['parse']

    # Inherent
    if parse == 'inh':
        return opcode_bytes(entry['inh'])

    # Immediate-only (ANDCC, ORCC, CWAI)
    if parse == 'imm8':
        opc = entry['imm']
        if operand is None or not operand.strip().startswith('#'):
            raise AsmError(f"'{mnemonic}' requires #immediate", lineno)
        val = eval_expr(operand.strip()[1:], symbols, pc, lineno)
        if is_unresolved(val): val = 0
        return opcode_bytes(opc) + bytes([val & 0xFF])

    # Register-to-register (TFR/EXG)
    if parse == 'rtor':
        opc = entry['imm']
        if operand is None:
            raise AsmError(f"'{mnemonic}' requires register pair", lineno)
        parts = [r.strip().upper() for r in operand.split(',')]
        if len(parts) != 2:
            raise AsmError(f"'{mnemonic}' requires two registers", lineno)
        if parts[0] not in TFR_REGS or parts[1] not in TFR_REGS:
            raise AsmError(f"unknown register in '{operand}'", lineno)
        rb = (TFR_REGS[parts[0]] << 4) | TFR_REGS[parts[1]]
        return opcode_bytes(opc) + bytes([rb])

    # Register list (PSHS/PULS/PSHU/PULU)
    if parse == 'rlist':
        opc = entry['imm']
        if operand is None:
            raise AsmError(f"'{mnemonic}' requires register list", lineno)
        # Determine if this is a U-stack operation
        use_u = mnemonic in ('PSHU', 'PULU')
        rmap  = RLIST_U if use_u else RLIST_S
        mask  = 0
        for reg in operand.upper().split(','):
            reg = reg.strip()
            if reg not in rmap:
                raise AsmError(f"unknown register '{reg}' in list", lineno)
            mask |= rmap[reg]
        return opcode_bytes(opc) + bytes([mask])

    # No operand: inherent fallback
    if operand is None:
        if 'inh' in entry and entry['inh'] is not None:
            return opcode_bytes(entry['inh'])
        raise AsmError(f"'{mnemonic}' requires operand", lineno)

    op = operand.strip()

    # Relative branches
    if parse in ('rel8', 'rel16', 'relgen'):
        target = eval_expr(op, symbols, pc, lineno)
        if is_unresolved(target): target = pc + 2

        if parse == 'rel8':
            opc = entry['rel']
            instr_end = pc + opcode_size(opc) + 1
            rel = target - instr_end
            if not (-128 <= rel <= 127):
                raise AsmError(
                    f"branch to '{op}' out of 8-bit range ({rel:+d})", lineno)
            return opcode_bytes(opc) + bytes([rel & 0xFF])

        if parse == 'rel16':
            opc = entry['rel']
            instr_end = pc + opcode_size(opc) + 2
            rel = target - instr_end
            return opcode_bytes(opc) + bytes([(rel >> 8) & 0xFF, rel & 0xFF])

        if parse == 'relgen':
            # Always long form
            opc = entry['rel']
            instr_end = pc + opcode_size(opc) + 2
            rel = target - instr_end
            return opcode_bytes(opc) + bytes([(rel >> 8) & 0xFF, rel & 0xFF])

    # LEA instructions (indexed only)
    if parse == 'leax':
        opc = entry['idx']
        opc_b = opcode_bytes(opc)
        instr_end = pc + len(opc_b) + (committed_size - len(opc_b)
                                        if committed_size else 3)
        cs = committed_size - len(opc_b) if committed_size else None
        idx_b = encode_indexed(op, pc, instr_end, symbols, lineno,
                                committed_size=cs)
        return opc_b + idx_b

    # Immediate
    if op.startswith('#'):
        opc = entry.get('imm')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no immediate mode", lineno)
        val = eval_expr(op[1:], symbols, pc, lineno)
        if is_unresolved(val): val = 0
        if parse in ('gen8', 'imm8'):
            return opcode_bytes(opc) + bytes([val & 0xFF])
        else:
            return opcode_bytes(opc) + bytes([(val >> 8) & 0xFF, val & 0xFF])

    # Forced direct
    if op.startswith('<'):
        opc = entry.get('dir')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no direct mode", lineno)
        val = eval_expr(op[1:], symbols, pc, lineno)
        if is_unresolved(val): val = 0
        return opcode_bytes(opc) + bytes([val & 0xFF])

    # Forced extended
    if op.startswith('>'):
        opc = entry.get('ext')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no extended mode", lineno)
        val = eval_expr(op[1:], symbols, pc, lineno)
        if is_unresolved(val): val = 0
        val &= 0xFFFF
        return opcode_bytes(opc) + bytes([(val >> 8) & 0xFF, val & 0xFF])

    # Indexed
    if op.startswith('[') or _is_indexed(op):
        opc = entry.get('idx')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no indexed mode", lineno)
        opc_b = opcode_bytes(opc)
        instr_end = pc + (committed_size if committed_size else len(opc_b) + 3)
        cs = (committed_size - len(opc_b)) if committed_size else None
        idx_b = encode_indexed(op, pc, instr_end, symbols, lineno,
                                committed_size=cs)
        return opc_b + idx_b

    # Auto direct/extended
    val = eval_expr(op, symbols, pc, lineno)
    if is_unresolved(val):
        # Default to extended with placeholder
        opc = entry.get('ext') or entry.get('dir')
        if entry.get('ext') is not None:
            return opcode_bytes(entry['ext']) + bytes([0x00, 0x00])
        return opcode_bytes(entry['dir']) + bytes([0x00])
    elif committed_size is not None:
        # Honour Pass 1 decision
        total_opc = opcode_size(entry.get('dir', entry.get('ext', 1)))
        operand_sz = committed_size - total_opc
        if operand_sz == 1:
            opc = entry.get('dir')
            return opcode_bytes(opc) + bytes([val & 0xFF])
        else:
            opc = entry.get('ext')
            val &= 0xFFFF
            return opcode_bytes(opc) + bytes([(val >> 8) & 0xFF, val & 0xFF])
    elif (val >> 8) == dp and entry.get('dir') is not None:
        opc = entry['dir']
        return opcode_bytes(opc) + bytes([val & 0xFF])
    else:
        opc = entry.get('ext')
        if opc is None:
            raise AsmError(f"'{mnemonic}' has no extended mode", lineno)
        val &= 0xFFFF
        return opcode_bytes(opc) + bytes([(val >> 8) & 0xFF, val & 0xFF])


# ─────────────────────────────────────────────────────────────────────────────
# Directive size estimation and emission
# ─────────────────────────────────────────────────────────────────────────────

def directive_size(mnemonic, operand, symbols, pc, lineno):
    """Return size in bytes for a directive in Pass 1."""
    if mnemonic in ('ORG', 'EQU', 'SET', 'END', 'SETDP'):
        return 0

    if operand is None:
        raise AsmError(f"'{mnemonic}' requires operand", lineno)

    if mnemonic == 'FCB':
        return len(_split_operands(operand))

    if mnemonic == 'FDB':
        return len(_split_operands(operand)) * 2

    if mnemonic in ('FCC', 'FCS', 'FCN'):
        s = _parse_string(operand, mnemonic, lineno)
        extra = 1 if mnemonic in ('FCS', 'FCN') else 0
        return len(s) + extra

    if mnemonic in ('RMB', 'ZMB'):
        val = eval_expr(operand, symbols, pc, lineno)
        return 0 if is_unresolved(val) else int(val)

    raise AsmError(f"unknown directive '{mnemonic}'", lineno)


def directive_bytes(mnemonic, operand, symbols, pc, lineno):
    """Emit bytes for a directive in Pass 2.  Returns bytes object or None."""
    if mnemonic in ('EQU', 'SET', 'END', 'SETDP'):
        return b''

    if mnemonic == 'ORG':
        return b''  # ORG handled by Assembler

    if operand is None:
        raise AsmError(f"'{mnemonic}' requires operand", lineno)

    if mnemonic == 'FCB':
        result = bytearray()
        for item in _split_operands(operand):
            val = eval_expr(item.strip(), symbols, pc, lineno)
            if is_unresolved(val): val = 0
            result.append(val & 0xFF)
        return bytes(result)

    if mnemonic == 'FDB':
        result = bytearray()
        for item in _split_operands(operand):
            val = eval_expr(item.strip(), symbols, pc, lineno)
            if is_unresolved(val): val = 0
            val &= 0xFFFF
            result += bytes([(val >> 8) & 0xFF, val & 0xFF])
        return bytes(result)

    if mnemonic == 'FCC':
        return _parse_string(operand, mnemonic, lineno)

    if mnemonic == 'FCS':
        s = bytearray(_parse_string(operand, mnemonic, lineno))
        s[-1] |= 0x80
        return bytes(s)

    if mnemonic == 'FCN':
        return _parse_string(operand, mnemonic, lineno) + b'\x00'

    if mnemonic in ('RMB', 'ZMB'):
        val = eval_expr(operand, symbols, pc, lineno)
        if is_unresolved(val): val = 0
        return bytes(int(val))   # zero-filled

    raise AsmError(f"unknown directive '{mnemonic}'", lineno)


def _split_operands(operand):
    """Split comma-separated operands, respecting string literals."""
    items = []
    current = []
    in_str = False
    for ch in operand:
        if ch == '"':
            in_str = not in_str
        if ch == ',' and not in_str:
            items.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        items.append(''.join(current).strip())
    return items


def _parse_string(operand, directive, lineno):
    """Parse a quoted string operand.  Returns bytes."""
    s = operand.strip()
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        raise AsmError(f"'{directive}' operand must be a quoted string", lineno)
    return s[1:-1].encode('ascii')


# ─────────────────────────────────────────────────────────────────────────────
# Two-pass assembler
# ─────────────────────────────────────────────────────────────────────────────

class _Line:
    __slots__ = ('lineno', 'raw', 'label', 'mnemonic', 'operand',
                 'address', 'size', 'pcr16')
    def __init__(self, lineno, raw, label, mnemonic, operand):
        self.lineno   = lineno
        self.raw      = raw
        self.label    = label
        self.mnemonic = mnemonic
        self.operand  = operand
        self.address  = None
        self.size     = None
        self.pcr16    = False   # True if committed to 16-bit PCR in Pass 1


class Assembler:
    """
    Two-pass 6809 assembler.

    Usage:
        asm = Assembler()
        segments, exec_addr = asm.assemble(source_text)
        # segments: list of (load_addr: int, data: bytes)
        # exec_addr: int or None
    """

    def __init__(self, dp=0x00):
        self.dp         = dp
        self.symbols    = {}
        self.exec_addr  = None

    def assemble(self, source):
        lines = self._tokenize(source)

        # Pass 1: build symbol table and estimate sizes
        self._pass1(lines)

        # Pass 2: emit bytes (sizes locked from Pass 1)
        segments = self._pass2(lines)

        return segments, self.exec_addr

    # ── Tokenization ──────────────────────────────────────────────────────────

    def _tokenize(self, source):
        lines = []
        for i, raw in enumerate(source.splitlines(), 1):
            try:
                label, mnemonic, operand = tokenize_line(raw, i)
            except AsmError:
                raise
            except Exception as e:
                raise AsmError(str(e), i)
            lines.append(_Line(i, raw, label, mnemonic, operand))
        return lines

    # ── Pass 1 ────────────────────────────────────────────────────────────────

    def _pass1(self, lines):
        self.symbols    = {}
        self.exec_addr  = None
        pc              = 0

        for ln in lines:
            ln.address = pc

            # Handle label
            if ln.label:
                key = ln.label.upper()
                if ln.mnemonic in ('EQU', 'SET') and ln.operand is not None:
                    val = eval_expr(ln.operand, self.symbols, pc, ln.lineno)
                    self.symbols[key] = None if is_unresolved(val) else int(val)
                    ln.size = 0
                    continue
                else:
                    self.symbols[key] = pc

            if ln.mnemonic is None:
                ln.size = 0
                continue

            mn = ln.mnemonic

            if mn == 'ORG':
                if ln.operand:
                    val = eval_expr(ln.operand, self.symbols, pc, ln.lineno)
                    if not is_unresolved(val):
                        pc = int(val)
                        ln.address = pc
                ln.size = 0
                continue

            if mn == 'END':
                if ln.operand:
                    val = eval_expr(ln.operand, self.symbols, pc, ln.lineno)
                    if not is_unresolved(val):
                        self.exec_addr = int(val)
                ln.size = 0
                continue

            if mn == 'SETDP':
                if ln.operand:
                    val = eval_expr(ln.operand, self.symbols, pc, ln.lineno)
                    if not is_unresolved(val):
                        self.dp = int(val)
                ln.size = 0
                continue

            if mn in BYTE_DIRECTIVES or mn not in INSTAB:
                try:
                    sz = directive_size(mn, ln.operand, self.symbols, pc, ln.lineno)
                except AsmError:
                    raise
                ln.size = sz
                pc += sz
                continue

            # Instruction
            try:
                sz, pcr16 = instruction_size(
                    mn, ln.operand, self.symbols, pc, self.dp, ln.lineno)
            except AsmError:
                raise
            ln.size  = sz
            ln.pcr16 = pcr16
            pc       += sz

    # ── Pass 2 ────────────────────────────────────────────────────────────────

    def _pass2(self, lines):
        pc       = 0
        segments = []    # list of (load_addr, bytearray)
        current_load = 0
        current_data = bytearray()

        def flush_segment():
            nonlocal current_data, current_load
            if current_data:
                segments.append((current_load, bytes(current_data)))
                current_data = bytearray()

        for ln in lines:
            if ln.mnemonic == 'ORG':
                # New segment
                if ln.operand:
                    val = eval_expr(ln.operand, self.symbols, pc, ln.lineno)
                    if not is_unresolved(val):
                        flush_segment()
                        pc           = int(val)
                        current_load = pc
                continue

            if ln.mnemonic is None and ln.size == 0:
                continue

            if ln.mnemonic in ('EQU', 'SET', 'END', 'SETDP') or ln.size == 0:
                continue

            mn = ln.mnemonic
            if mn is None:
                continue

            is_dir = (mn in BYTE_DIRECTIVES or mn not in INSTAB)
            try:
                if is_dir:
                    data = directive_bytes(mn, ln.operand, self.symbols, pc, ln.lineno)
                else:
                    data = instruction_bytes(
                        mn, ln.operand, self.symbols, pc, self.dp, ln.lineno,
                        committed_size=ln.size,
                        committed_pcr16=ln.pcr16)
            except AsmError:
                raise
            except Exception as e:
                raise AsmError(str(e), ln.lineno)

            if len(data) != ln.size:
                raise AsmError(
                    f"size mismatch for '{mn}': "
                    f"Pass 1 said {ln.size}, Pass 2 emitted {len(data)}",
                    ln.lineno)

            current_data += data
            pc           += ln.size

        flush_segment()
        return segments


# ─────────────────────────────────────────────────────────────────────────────
# Output formatters
# ─────────────────────────────────────────────────────────────────────────────

def make_decb(segments, exec_addr=0):
    """
    Pack assembled segments into DECB binary format.

    Preamble per segment: 0x00, len_hi, len_lo, load_hi, load_lo
    Postamble:            0xFF, 0x00, 0x00, exec_hi, exec_lo
    """
    out = bytearray()
    for load_addr, data in segments:
        length = len(data)
        out += bytes([
            0x00,
            (length    >> 8) & 0xFF, length    & 0xFF,
            (load_addr >> 8) & 0xFF, load_addr & 0xFF,
        ])
        out += data
    exec_addr = exec_addr or 0
    out += bytes([
        0xFF, 0x00, 0x00,
        (exec_addr >> 8) & 0xFF, exec_addr & 0xFF,
    ])
    return bytes(out)


def make_raw(segments):
    """Concatenate all segment data (no headers)."""
    return b''.join(data for _, data in segments)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def assemble(source, fmt='decb', dp=0):
    """
    Assemble 6809 source text.

    Args:
        source (str): Assembly source text.
        fmt    (str): Output format — 'decb' (default) or 'raw'.
        dp     (int): Initial direct page register value (default 0).

    Returns:
        bytes: Assembled binary in the requested format.

    Raises:
        AsmError: On any assembly error.
    """
    asm = Assembler(dp=dp)
    segments, exec_addr = asm.assemble(source)

    if not segments:
        raise AsmError("no code generated")

    if fmt == 'decb':
        return make_decb(segments, exec_addr or 0)
    elif fmt == 'raw':
        return make_raw(segments)
    else:
        raise AsmError(f"unknown output format '{fmt}'")
