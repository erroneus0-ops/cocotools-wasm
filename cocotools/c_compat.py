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

def c_int_wrap(value, bits, signed=True):
    """
    STUB -- not yet implemented, not yet needed.

    Would reproduce C's fixed-width integer wraparound: unlike Python's
    arbitrary-precision int, a C `int8_t`/`uint16_t`/etc. silently wraps
    (or is undefined-behavior-but-wraps-in-practice, for signed overflow
    on nearly every real compiler) when a value exceeds its declared
    width. A translated C function that relies on, e.g., an 8-bit
    counter wrapping from 255 back to 0 will NOT do that automatically
    in Python -- the value just keeps growing.

    Intended signature: mask to `bits` bits, then reinterpret as signed
    two's-complement if signed=True.
    """
    raise NotImplementedError(
        "c_int_wrap: not yet needed by any audited cocotools file; "
        "implement if a future C source relies on fixed-width wraparound."
    )


def c_strlen_walk(buf, start=0):
    """
    STUB -- not yet implemented, not yet needed.

    Would reproduce the common C idiom where a null-terminated buffer's
    trailing \\0 is doing double duty as both "stop iterating here" and
    "this is how long the string actually is" -- a single sentinel byte
    serving as an implicit length field. Python strings/bytes carry their
    own length as a real property, so a direct translation of a
    `while (*p) { ...; p++; }` loop needs to notice that the null check
    was ALSO functioning as a length check, and preserve both behaviors
    rather than just the "keep looping" half.

    Intended behavior: return the length of the null-terminated run in
    `buf` starting at `start`, without needing an explicit length passed
    in -- i.e. the Python-side reconstruction of the implicit C contract.
    """
    raise NotImplementedError(
        "c_strlen_walk: not yet needed by any audited cocotools file; "
        "implement if a future C source relies on null-termination as "
        "an implicit length field rather than an explicit one."
    )
