"""
cocotools/c_compat.py -- C-semantics compatibility primitives

Python and C disagree on the fundamental behavior of several operations
that look identical at the syntax level. A line-by-line C-to-Python
translation that reaches for Python's "natural" operator in these spots
will produce code that runs, passes tests with easy inputs, and is
silently wrong the moment a real program exercises the divergent case.
This module collects the primitives needed to reproduce C's actual
behavior exactly, so translated code can call a named function instead of
re-deriving the right semantics (or missing that a divergence exists at
all) at every call site.

This is intentionally NOT "more Pythonic" than plain //, %, or manual
pointer-walking loops -- it is deliberately C-shaped, on purpose, because
the goal of this codebase is behavioral fidelity to a specific C program,
not idiomatic Python. See UPDATING.md for the reasoning.

Currently implemented (all found necessary during the lwasm audit,
2026-07-13):
  - _c_trunc_div / _c_trunc_mod : truncating-toward-zero division/modulo
  - Ptr                          : mutable string cursor (C's char **p)

Stubbed but not yet needed by this codebase (documented so a future
C source file that DOES need them doesn't require rediscovering the
underlying issue from scratch):
  - c_int8 / c_uint8 / c_int16 / c_uint16 / c_int32 / c_uint32 wraparound
  - c_strlen-style null-terminated-buffer walking, for C idioms where
    `while (*p)` is doing double duty as both "keep going" and "this is
    how the caller knows the length"
"""

# ---------------------------------------------------------------------------
# Truncating integer division / modulo (C's "/" and "%")
#
# C's "/" and lwasm's "\" (intdiv, defined identically to "/" in the C
# source) truncate toward zero. Python's native "//" floors toward
# negative infinity instead, and disagrees with C whenever the two
# operands have different signs:
#
#     C:      -7 / 2  == -3      -7 % 2  == -1
#     Python: -7 // 2 == -4      -7 % 2  ==  1
#
# Found live in cocotools/lw_expr.py's OPER_MOD and OPER_INTDIV handling
# (2026-07-13 audit, fixed same day). Any C source using "/" or "%" on
# values that could ever be negative needs one of these, not the native
# Python operators.
# ---------------------------------------------------------------------------

def c_trunc_div(a, b):
    """Integer division truncating toward zero, matching C's '/' operator.

    Uses only integer arithmetic (no float involved), so it is exact for
    arbitrarily large values -- unlike the tempting-looking int(a / b),
    which can lose precision once |a| or |b| exceeds float53 mantissa
    range. Never actually hit in 6809/6309 assembly (16/32-bit values),
    but free to get right and cheap to keep that way.
    """
    q = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        q = -q
    return q


def c_trunc_mod(a, b):
    """Remainder matching C's '%' operator (sign follows the dividend,
    not the divisor -- Python's native '%' is floor-based and follows the
    divisor's sign instead, which disagrees with C on mixed-sign operands).
    """
    return a - c_trunc_div(a, b) * b


# Backward-compatible aliases matching the names used at the call sites
# fixed during the 2026-07-13 audit (cocotools/lw_expr.py). Prefer the
# c_trunc_div / c_trunc_mod names above in new code; these exist so the
# already-deployed fix doesn't need touching to adopt this module.
_c_trunc_div = c_trunc_div


# ---------------------------------------------------------------------------
# Mutable string cursor (C's `char **p` idiom)
#
# A very common C pattern is a function that takes a pointer-to-pointer
# and advances the CALLER's read position by writing through it:
#
#     void parse_thing(char **p) { ...; (*p)++; ...; }
#
# Python strings are immutable and there is no address-of operator, so
# this can't be reproduced with a bare `str` argument -- the callee has
# no way to mutate what the caller sees. Ptr wraps a string with an
# internal position index and mutates *itself* in place, which every
# caller holding a reference to the same Ptr object will observe --
# functionally equivalent to C's pointer-to-pointer advancement.
# ---------------------------------------------------------------------------

class Ptr:
    """Mutable cursor over a string, standing in for C's `char **p`."""

    __slots__ = ('s', 'pos')

    def __init__(self, s, pos=0):
        self.s   = s
        self.pos = pos

    def peek(self):
        """Return the character at the current position, or '' at end."""
        return self.s[self.pos] if self.pos < len(self.s) else ''

    def advance(self, n=1):
        """Move the cursor forward n characters (like C's (*p) += n)."""
        self.pos += n

    def startswith(self, prefix):
        return self.s.startswith(prefix, self.pos)

    def at_end(self):
        return self.pos >= len(self.s)

    def remaining(self):
        """Return everything from the current position to the end --
        useful when a C function's caller expects the advanced *p value
        back as a return, rather than relying on mutation being visible."""
        return self.s[self.pos:]

    def __repr__(self):
        return f"Ptr(pos={self.pos}, remaining={self.remaining()!r})"


# ---------------------------------------------------------------------------
# NOT YET IMPLEMENTED -- documented stubs
#
# Neither of these has been needed by lwasm/cocotools specifically (its
# values stay within ranges that don't trigger these issues, and its
# string handling doesn't lean on null-termination-as-length-check in a
# way that's been hit yet). Left here, unbuilt, so that IF a future
# C source file (an lwasm update, or an entirely different C program)
# needs them, the category of problem is already named and the shape of
# the fix is already scoped -- rather than being rediscovered as a fresh
# surprise the way MOD/INTDIV was.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Fixed-width integer wraparound
#
# C's fixed-width integer types (int8_t, uint8_t, int16_t, uint16_t,
# int32_t, uint32_t) silently wrap when values overflow their declared
# width. Python integers are arbitrary precision and never wrap.
#
# In lwasm these arise in:
#   - Postbyte construction: pb |= (v & 0x1F)  -- 5-bit signed offset
#   - DP value masking: dpval & 0xff
#   - Complement: ~value needs & 0xFF to stay 8-bit
#   - Any accumulation that C declares as a specific integer type
#
# Systematic scan of lwasm C source (July 2026) found these patterns:
#   insn_indexed.c: v & 0x1F (5-bit signed offset encoding)
#   insn_gen.c:     (v >> 8) & 0xFF (DP page byte extraction)
#   insn_gen.c:     pb |= offs & 0x1F (5-bit offset into postbyte)
#   pseudo.c:       dpval & 0xFF (DP register masking)
#   lw_expr.c:      ~value & 0xFF (bitwise complement truncated to byte)
#
# Usage: call c_uint8(x) wherever C declares uint8_t or masks with 0xFF
#        call c_int8(x)  wherever C signed-extends an 8-bit value
#        call c_uint16(x) wherever C declares uint16_t or masks with 0xFFFF
#        call c_int16(x)  wherever C signed-extends a 16-bit value
#        call c_5bit(x)   for 5-bit signed indexed offset encoding (v & 0x1F)
# ---------------------------------------------------------------------------

def c_uint8(value):
    """Truncate to unsigned 8-bit, matching C's uint8_t semantics."""
    return value & 0xFF

def c_int8(value):
    """Truncate to signed 8-bit, matching C's int8_t semantics."""
    value = value & 0xFF
    return value if value < 128 else value - 256

def c_uint16(value):
    """Truncate to unsigned 16-bit, matching C's uint16_t semantics."""
    return value & 0xFFFF

def c_int16(value):
    """Truncate to signed 16-bit, matching C's int16_t semantics."""
    value = value & 0xFFFF
    return value if value < 32768 else value - 65536

def c_uint32(value):
    """Truncate to unsigned 32-bit, matching C's uint32_t semantics."""
    return value & 0xFFFFFFFF

def c_int32(value):
    """Truncate to signed 32-bit, matching C's int32_t semantics."""
    value = value & 0xFFFFFFFF
    return value if value < 2147483648 else value - 4294967296

def c_5bit(value):
    """Mask to 5-bit unsigned, used for 5-bit signed indexed offset encoding.
    
    In C: pb = ((rn & 0x03) << 5) | (v & 0x1F)
    The 5-bit field encodes -16..+15 in two's complement, but the mask
    operation itself is unsigned -- the signedness is in the interpretation
    by the CPU, not in the encoding.
    """
    return value & 0x1F

def c_complement8(value):
    """Bitwise complement truncated to 8 bits, matching C's ~uint8_t.
    
    In C: uint8_t r = ~x;  (wraps to 8 bits)
    In Python: ~x produces an unbounded negative integer.
    
    Found in lw_expr.c: tr = ~(E->operands->p->value) & 0xff
    """
    return (~value) & 0xFF

def c_int_wrap(value, bits, signed=True):
    """General fixed-width integer wraparound.
    
    Prefer the specific c_uint8/c_int8/c_uint16/c_int16 functions above
    for the common cases. Use this for non-standard widths.
    """
    mask = (1 << bits) - 1
    value = value & mask
    if signed and value >= (1 << (bits - 1)):
        value -= (1 << bits)
    return value


# ---------------------------------------------------------------------------
# goto -- structured control flow replacement
#
# C uses goto for forward/backward jumps that break out of nested logic.
# Found 27 goto occurrences in lwasm (insn_indexed.c, insn_gen.c, pseudo.c).
#
# lwasm's goto patterns fall into three categories:
#
# 1. Forward jump to shared error exit:
#    C:   goto out;   (at the end: out: return;)
#    Py:  return      (just return early -- same effect)
#
# 2. Forward jump to shared code path:
#    C:   goto do16bit;  (jumps to a 16-bit encoding block)
#    Py:  Refactor into a helper function or use a flag variable.
#         _do_16bit(l) or set lint=2 and fall through.
#
# 3. Forward jump to a different parsing mode:
#    C:   goto indexed;  (jumps to indexed addressing parse)
#    Py:  Call the indexed parse function directly.
#
# The existing Python translation handles these via early returns and
# helper function calls. No additional primitives needed -- just careful
# restructuring at each goto site.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# isspace / toupper / C character classification
#
# C's ctype.h functions (isspace, toupper, isalpha, isdigit, isalnum)
# are used throughout lwasm for character classification during parsing.
# Python equivalents are straightforward but need care with locale.
#
# Found in lwasm:
#   isspace(**p) -- whitespace check during token scanning
#   toupper(**p) -- case-insensitive register name matching
#
# Python equivalents:
#   isspace(c)  -> c.isspace() (c in space/tab/newline/etc.)
#   toupper(c)  -> c.upper()
#   isalpha(c)  -> c.isalpha()
#   isdigit(c)  -> c.isdigit()
#   isalnum(c)  -> c.isalnum()
#
# CRITICAL: Python's str.isspace() returns False for '' (empty string).
# C's isspace('NUL') is also false, so they agree. But lwasm checks
# **p == 'NUL' as end-of-string; Python uses p.at_end() or p.peek() == ''.
# The Ptr class already handles this correctly.
#
# No additional primitives needed -- Python string methods are sufficient.
# Document here to prevent re-discovery during translation.
# ---------------------------------------------------------------------------

def c_isspace(c):
    """C isspace() equivalent -- whitespace check for parsing."""
    return c in (' ', '\t', '\r', '\n', '\f', '\v')


def c_toupper(c):
    """C toupper() equivalent -- single character uppercase."""
    return c.upper() if c else ''


# ---------------------------------------------------------------------------
# Null-terminated string walking
#
# C's while (*p) { ...; p++; } idiom walks null-terminated strings.
# The Ptr class handles the cursor advancement, but null-termination
# as an end condition maps to Ptr.at_end() or Ptr.peek() == ''.
#
# Found in lw_expr.c and pseudo.c for pragma string parsing.
# No additional primitives needed -- Ptr.peek() == '' is the Python
# equivalent of C's *p == 'NUL' (end of string / null terminator).
# ---------------------------------------------------------------------------

def c_strlen_walk(buf, start=0):
    """Walk a null-terminated string, returning the content up to null.
    
    C idiom: while (*p) { ... p++; }
    Python: use Ptr and check Ptr.peek() == '' for end condition.
    
    This function is provided for cases where you genuinely need the
    C strlen behavior on a Python str or bytes object.
    """
    end = start
    while end < len(buf) and buf[end] != '\\0' and buf[end] != 0:
        end += 1
    return buf[start:end]
