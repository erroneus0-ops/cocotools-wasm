# Function-Level Translation Guide
## lwasm C → Python: Pre-Translation Checklist and Interaction Risk Catalog

### Purpose

This guide supports the function-level translation of lwasm 4.24 from C to Python.
It exists because program-level translation produces code that looks correct but
contains invisible behavioral divergences. Function-level translation with systematic
pre-analysis and test verification is the only approach that produces provably faithful
output.

The translation is part of a project aimed at teaching assembly language programming
to adults who missed this foundational education. Errors in the assembler produce
wrong binary output silently — the learner assumes they are wrong, not the tool.
Fidelity is not a quality preference. It is the minimum requirement.

---

### The Process

For every C function, in order:

1. **Apply the pre-translation checklist** (below) to the C source
2. **Flag all risk patterns found** with their mitigation
3. **Translate the function** applying mitigations at flagged sites
4. **Write test cases** covering all branches including flagged sites
5. **Run the fidelity harness** — `python cocotools/test_fidelity.py`
6. **Do not proceed to the next function until all tests pass**

No exceptions. No "this looks right." Tests pass or they don't.

---

### Pre-Translation Checklist

Apply this to the C source of each function before writing Python.

#### □ 1. Integer width at assignment sites

For every assignment `x = expr`, ask: what type is `x` in C?

| C type | Python risk | Mitigation |
|--------|-------------|------------|
| `uint8_t` | Python int grows unbounded | `c_uint8(expr)` |
| `int8_t` | Python int doesn't sign-extend | `c_int8(expr)` |
| `uint16_t` | Python int grows unbounded | `c_uint16(expr)` |
| `int16_t` | Python int doesn't sign-extend | `c_int16(expr)` |
| `int` (general) | Usually safe — Python int is larger | Check if result is used as byte |

**Safe patterns** (no action needed):
- `v & 0x1F` — Python `&` on negatives uses two's complement, matches C
- `pb | 0x89` — intermediate results fit in 8 bits for all lwasm postbytes
- `PRAGMA_CLEARBIT` complement — Python arbitrary int `&` works correctly

**Risky patterns** (need compat primitive):
- `~value` stored into an 8-bit context → use `c_complement8(value)`
- Accumulation across multiple operations where C type constrains intermediate → add explicit mask

#### □ 2. Division and modulo with potentially negative operands

Any `/` or `%` in C on values that could be negative:
- C truncates toward zero
- Python floors toward negative infinity
- They disagree when operands have different signs: `-7 / 2` is `-3` in C, `-4` in Python

**Mitigation:** use `c_trunc_div(a, b)` and `c_trunc_mod(a, b)` from `c_compat.py`

Already present in `lw_expr.py` for OPER_INTDIV and OPER_MOD.
Check all other `/` and `%` occurrences in the function being translated.

#### □ 3. `char **p` pointer parameters

Any parameter declared `char **p` in C is a mutable cursor — the function
advances the caller's read position as a side effect.

**Mitigation:** pass a `Ptr` object. The same `Ptr` instance must be passed
to all functions in the call chain that should share the cursor position.
Never create a new `Ptr` from `p.remaining()` and pass that — it creates
an independent cursor and breaks aliasing.

**Aliasing check:** if a function receives two `char **` parameters, verify
whether they could ever point into the same buffer. If so, ensure both
map to the same `Ptr` instance in the Python translation.

#### □ 4. `goto` statements

lwasm has 27 goto statements across `insn_indexed.c`, `insn_gen.c`, and `pseudo.c`.
Each falls into one of three patterns:

**Pattern A — Forward jump to shared exit:**
```c
if (error_condition) goto out;
...
out:
    return;
```
Python mitigation: `return` early. Clean.

**Pattern B — Forward jump to shared code block:**
```c
if (need_16bit) goto do16bit;
...
do16bit:
    l->lint = 2;
    pb = 0x89 | ...;
    return;
```
Python mitigation: extract `do16bit` logic as a helper function.
Variables it needs become parameters. Document why the helper exists.

**Pattern C — Forward jump to alternate parse path:**
```c
if (some_condition) goto indexed;
...
indexed:
    insn_parse_indexed_aux(as, l, p);
```
Python mitigation: call the function directly at the goto site.

**Variable scope risk:** check whether the goto skips over variable
declarations that the destination code uses. In lwasm's specific cases
this does not appear to occur, but verify for each instance.

#### □ 5. `char` signedness in comparisons

C's `char` may be signed or unsigned depending on platform and compiler.
lwasm is written for gcc on Linux where `char` is signed by default.

Risk: `*p > 127` in C with signed char is always false (values are -128..127).
In Python, `Ptr.peek()` returns a single character — comparing with `>` uses
Unicode code point values (always positive). Usually equivalent, but:

**Check:** any comparison of `*p` against values > 127 or < 0.
These are rare in lwasm (it handles ASCII assembly source) but verify.

#### □ 6. Function argument evaluation order

C does not guarantee the order in which function arguments are evaluated.
Python evaluates left to right.

**Risk pattern:** `f((*p)++, *p)` — in C the compiler chooses evaluation order,
producing potentially different results on different compilers.
In Python, left-to-right is guaranteed.

**Check:** any function call where an argument both reads and advances `*p`
(or equivalent mutable state). In lwasm this is rare due to William Astle's
clean coding style, but scan each function for `(*p)++` in argument position.

If found: determine what order lwasm's actual behavior depends on
(test against lwasm 4.24), then ensure Python's left-to-right order
produces the same result. If not, reorder the arguments or use temporaries.

#### □ 7. Integer promotion in compound expressions

C promotes small integer types to `int` before arithmetic. This means
intermediate results in `uint8_t a + uint8_t b` never overflow — they
compute as `int`. The result is only truncated if assigned back to `uint8_t`.

Python integers are already arbitrary precision — no promotion needed,
no truncation unless explicit.

**Risk:** compound expressions where C's implicit promotion prevents
overflow that Python also doesn't overflow (safe) versus expressions
where the final C assignment truncates (needs explicit mask).

**Rule:** only add truncation mask where the C declares the destination
variable as a fixed-width type AND the expression could produce a value
outside that range.

#### □ 8. Bitwise complement `~`

`~value` in C on a `uint8_t` produces an `int` result that is then
truncated back to `uint8_t` by the assignment. `~value` in Python
produces an arbitrary negative integer.

**Check:** any `~` in the function. Determine the width of the
destination. Apply `c_complement8(v)` for 8-bit or `c_uint16(~v)` for 16-bit.

Already handled in `lw_expr.py` (OPER_COM and OPER_COM8).
Check all other `~` occurrences.

#### □ 9. String table register lookups

`lwasm_lookupreg2` and `lwasm_lookupreg3` scan a packed string table
and advance the caller's `char **p`. These are translated as
`AsmState.lookupreg2` and `AsmState.lookupreg3` using `Ptr`.

**Check:** after each call to lookupreg2/3, verify the Python `Ptr`
is the same instance that was passed in, and that subsequent use of
the Ptr reflects the advanced position correctly.

---

### Known Safe Patterns (no action needed)

These C patterns look risky but are actually safe in Python:

| Pattern | Why safe |
|---------|----------|
| `v & 0x1F` (5-bit mask) | Python `&` uses two's complement on negatives — matches C |
| `rn << 5` into postbyte | Max value `3 << 5 = 0x60`; combined with any lwasm base `<= 0x89` stays ≤ `0xFF` |
| `pragma &= ~PRAGMA_CLEARBIT` | Python arbitrary int `&` with negative complement works correctly |
| `pb \| 0x84` etc. | All lwasm postbyte OR operations stay within 8 bits by construction |
| `~pragma` in pragma manipulation | Pragma is a Python int; bit manipulation works correctly |

---

### Compat Primitives Reference

All in `cocotools/c_compat.py`. Import what you need:

```python
from .c_compat import (
    c_uint8, c_int8, c_uint16, c_int16,    # width constraints
    c_5bit,                                   # 5-bit indexed offset
    c_complement8,                            # ~v & 0xFF
    c_trunc_div, c_trunc_mod,                # C division semantics
    c_isspace, c_toupper,                    # character classification
    Ptr,                                      # mutable string cursor
)
```

---

### goto Locations in lwasm

For reference — all 27 goto sites:

**`insn_indexed.c`:**
- Line 748: `goto do16bit` — Pattern B, 16-bit encoding path

**`insn_gen.c`:**
- Line 60: `goto out` — Pattern A, error exit
- Line 72: `goto indexed` — Pattern C, indexed parse
- Line 104: `goto indexed` — Pattern C, indexed parse
- Line 119: `goto out` — Pattern A
- Line 123: `goto out` — Pattern A
- Line 134: `goto out` — Pattern A
- Line 149: `goto out` — Pattern A
- (and 19 more — all Pattern A or B)

**`pseudo.c`:**
- Multiple Pattern A exits

---

### The Educational Stakes

This assembler will be used by adults learning 6809 assembly language,
many of whom have no prior low-level programming experience. When the
assembler produces wrong binary output silently, the learner cannot
distinguish between "I wrote wrong assembly" and "the tool is wrong."
They assume they are wrong. They learn incorrectly or give up.

A faithful translation is not optional. The fidelity harness
(`python cocotools/test_fidelity.py`) is the arbiter of correctness.
193 tests currently pass against lwasm 4.24. Every translated function
must leave all 193 passing and add new tests for its own behavior.

The pre-translation checklist exists to prevent the category of bugs
that look correct but aren't — the bugs that pass casual review,
produce plausible output for easy inputs, and fail silently on the
inputs that matter.

---

### Function Translation Template

```python
# ---------------------------------------------------------------------------
# FUNCTION: function_name
# SOURCE:   lwasm/filename.c line N
# TRANSLATED: YYYY-MM-DD
#
# Pre-translation checklist results:
#   □ Integer width: [findings or "no fixed-width assignments"]
#   □ Division/modulo: [findings or "none"]
#   □ char **p: [findings or "N/A"]
#   □ goto: [findings or "none"]
#   □ char signedness: [findings or "safe"]
#   □ Argument order: [findings or "safe"]
#   □ Promotion: [findings or "safe"]
#   □ Complement: [findings or "none"]
#   □ lookupreg: [findings or "N/A"]
#
# Interaction risks: [list any, or "none identified"]
# Mitigations applied: [list, or "none needed"]
# ---------------------------------------------------------------------------
def function_name(as_, cl, ...):
    ...
```

---

*Last updated: July 2026*
*Reference: lwtools 4.24 — http://www.lwtools.ca/hg/index.cgi/file/0baeffe2747f*
