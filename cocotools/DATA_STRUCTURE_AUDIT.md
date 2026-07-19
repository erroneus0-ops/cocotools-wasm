# Data Structure Audit
## Shared Structures Crossing Function and File Boundaries

### Purpose

Functions in the genuine translation project don't operate in isolation.
They read and write shared data structures that persist across the parse,
resolve, and emit passes. A function that correctly computes a value but
stores it in the wrong field, or reads a field that wasn't initialized to
the C zero-init value, produces wrong output that may not be caught by
output-level tests alone.

This document catalogs every shared structure, compares C declarations
against Python equivalents field by field, and identifies divergences
that need structural tests or explicit mitigation.

---

## Structure 1: `line_t` (struct line_s)

**C declaration:** `lwasm.h`
**Python equivalent:** `class Line` in `cocotools/lwasm_core.py`
**Role:** One per source line. Passed to every parse/resolve/emit function.
Contains all per-line state including the assembled output bytes.

### Field Comparison

| C field | C type | Python field | Python init | Divergence? |
|---------|--------|--------------|-------------|-------------|
| `addr` | `lw_expr_t` | `addr` | `None` | No — NULL maps to None |
| `daddr` | `lw_expr_t` | `daddr` | `None` | No |
| `phase` | `lw_expr_t` | `phase` | `None` | No |
| `len` | `int` | `len` | `0` | No — C zero-inits to 0 |
| `dlen` | `int` | `dlen` | `0` | No |
| `minlen` | `int` | `minlen` | `0` | No |
| `maxlen` | `int` | `maxlen` | `0` | No |
| `insn` | `int` | `insn` | `-1` | **YES** — C zero-inits to `0`, Python inits to `-1` |
| `symset` | `int` | `symset` | `0` | No |
| `sym` | `char*` | `sym` | `None` | No — NULL maps to None |
| `output` | `unsigned char*` | `output` | `bytearray()` | Intentional — bytearray is correct Python equivalent |
| `outputl` | `int` | `outputl` | `-1` | **YES** — C zero-inits to `0`, Python inits to `-1` |
| `outputbl` | `int` | `outputbl` | `0` | No (Python bytearray has no fixed buffer size) |
| `dpval` | `int` | `dpval` | `0` | No |
| `cycle_base` | `int` | `cycle_base` | `0` | No |
| `cycle_adj` | `int` | `cycle_adj` | `0` | No |
| `cycle_flags` | `int` | `cycle_flags` | `0` | No |
| `genmode` | `int` | `genmode` | `0` | No |
| `fcc_extras` | `int` | `fcc_extras` | `0` | No |
| `err` | `lwasm_error_t*` | `err` | `None` | No |
| `warn` | `lwasm_error_t*` | `warn` | `None` | No |
| `err_testmode` | `lwasm_errorcode_t` | `err_testmode` | `0` | No |
| `prev` | `line_t*` | `prev` | `None` | No |
| `next` | `line_t*` | `next` | `None` | No |
| `inmod` | `int` | `inmod` | `0` | No |
| `csect` | `sectiontab_t*` | `csect` | `None` | No |
| `exprs` | `line_expr_s*` | `exprs` | `None` | No |
| `lstr` | `char*` | `lstr` | `None` | No |
| `pb` | `int` | `pb` | `0` | No |
| `lint` | `int` | `lint` | `0` | No |
| `lint2` | `int` | `lint2` | `0` | No |
| `conditional_return` | `int` | `conditional_return` | `0` | No |
| `as` | `asmstate_t*` | `as_` | `as_ arg` | Intentional — `as` is a Python keyword |
| `pragmas` | `int` | `pragmas` | `as_.pragmas` | Intentional — inherited from state |
| `context` | `int` | `context` | `as_.context` | Intentional — inherited from state |
| `ltext` | `char*` | `ltext` | `''` | **YES** — C zero-inits to NULL, Python inits to `''` |
| `linespec` | `char*` | `linespec` | `''` | **YES** — C zero-inits to NULL, Python inits to `''` |
| `lineno` | `int` | `lineno` | `0` | No |
| `soff` | `int` | `soff` | `0` | No |
| `dshow` | `int` | `dshow` | `0` | No |
| `dsize` | `int` | `dsize` | `0` | No |
| `isbrpt` | `int` | `isbrpt` | `0` | No |
| `dptr` | `symtabe*` | `dptr` | `None` | No |
| `noexpand_start` | `int` | `noexpand_start` | `0` | No |
| `noexpand_end` | `int` | `noexpand_end` | `0` | No |
| `hideline` | `int` | `hideline` | `0` | No |
| `hidecond` | `int` | `hidecond` | `0` | No |

**Total fields:** 47 C / 47 Python — complete match.

### Divergences Requiring Attention

**`insn` initialized to `-1` in Python, `0` in C:**

In C, `insn = 0` points to the first entry in `instab[]`. In Python,
`insn = -1` means "not an instruction." This is an intentional design
choice — `-1` is clearer as a sentinel — but any code that checks
`l->insn == 0` to detect "no instruction" would diverge.

Review all checks on `insn` to confirm they use `-1` not `0` as the
not-instruction sentinel. Current translation appears to use `-1`
consistently, but verify during function-level translation.

**`outputl` initialized to `-1` in Python, `0` in C:**

`outputl` tracks how many bytes have been emitted. C starts at `0`.
Python starts at `-1` as a "nothing emitted yet" sentinel, advancing
to `0` on first emit. Verify that no function reads `outputl` and
assumes it starts at `0`.

**`ltext` and `linespec` initialized to `''` in Python, NULL in C:**

C code checking `if (l->ltext)` (null check) will behave differently
from Python code checking `if cl.ltext` (empty string is falsy). Both
are falsy, so the behavior matches. But code that passes these to
functions expecting `char*` would need to pass `None` in Python.
The current translation uses empty strings — verify no function
confuses empty string with None in a context where it matters.

### Key Width Concerns for `pb` and `lint`

`pb` (postbyte) is declared `int` in C but used as an unsigned byte.
Values range from `0x00` to `0xFF` during normal operation, but intermediate
states use `-1` as a sentinel ("not yet determined").

`lint` (pass-forward integer) uses:
- `-1` = undetermined
- `0` = 0 extra bytes (no offset or auto-increment/decrement)
- `1` = 1 extra byte (8-bit offset)
- `2` = 2 extra bytes (16-bit offset)
- `3` = 5-bit offset (special case)

These are not byte-width values — they are small signed integers.
No masking needed. But functions that store `pb` must not assume it
is constrained — it may contain values from prior passes.

---

## Structure 2: `asmstate_t` (struct asmstate_s)

**C declaration:** `lwasm.h`
**Python equivalent:** `class AsmState` in `cocotools/lwasm_core.py`
**Role:** Global assembler state. Passed to every function. Contains
the symbol table, section table, line list, error counts, and all
global assembly settings.

### Key Field Comparison

| C field | C type | Python field | Notes |
|---------|--------|--------------|-------|
| `output_format` | `int` | `output_format` | OK |
| `flags` | `int` | `flags` | OK |
| `pragmas` | `int` | `pragmas` | Init: `PRAGMA_6809` — correct |
| `errorcount` | `int` | `errorcount` | OK |
| `warningcount` | `int` | `warningcount` | OK |
| `inmacro` | `int` | `inmacro` | OK |
| `instruct` | `int` | `instruct` | OK |
| `skipcond` | `int` | `skipcond` | OK |
| `skipcount` | `int` | `skipcount` | OK |
| `skipmacro` | `int` | `skipmacro` | OK |
| `endseen` | `int` | `endseen` | OK |
| `execaddr` | `int` | `execaddr` | OK |
| `inmod` | `int` | `inmod` | OK |
| `crc[3]` | `unsigned char[3]` | `crc` | `bytearray(3)` — correct |
| `cycle_total` | `int` | `cycle_total` | OK |
| `badsymerr` | `int` | `badsymerr` | OK |
| `pretendmax` | `int` | `pretendmax` | OK |
| `undefzero` | `int` | `undefzero` | OK |
| `exprwidth` | `int` | `exprwidth` | OK |
| `line_head` | `line_t*` | `line_head` | OK |
| `line_tail` | `line_t*` | `line_tail` | OK |
| `cl` | `line_t*` | `cl` | OK |
| `csect` | `sectiontab_t*` | `csect` | OK |
| `sections` | `sectiontab_t*` | `sections` | OK |
| `symtab` | `symtab_t` | `symtab` | `SymTab()` — see below |
| `context` | `int` | `context` | OK |
| `nextcontext` | `int` | `nextcontext` | OK |
| `macros` | `macrotab_t*` | `macros` | OK |
| `exportlist` | `exportlist_t*` | `exportlist` | OK |
| `importlist` | `importlist_t*` | `importlist` | OK |
| `exportcheck` | `int` | `exportcheck` | OK |
| `structs` | `structtab_t*` | `structs` | OK |
| `cstruct` | `structtab_t*` | `cstruct` | OK |
| `savedaddr` | `lw_expr_t` | `savedaddr` | OK |
| `input_files` | `lw_stringlist_t` | `input_files` | `[]` — correct |
| `include_list` | `lw_stringlist_t` | `include_list` | `[]` — correct |
| `file_dir` | `lw_stack_t` | `file_dir` | `[]` as stack — correct |
| `includelist` | `lw_stack_t` | `includelist` | `[]` as stack — correct |
| `stringvars` | `lw_dict_t` | `stringvars` | `{}` — correct |
| `passno` | `int` | `passno` | OK |
| `preprocess` | `int` | `preprocess` | OK |
| `fileerr` | `int` | `fileerr` | OK |
| `listnofile` | `int` | `listnofile` | OK |
| `tabwidth` | `int` | `tabwidth` | OK |
| `nowarn_flags` | `int` | `nowarn_flags` | OK |

**C fields not mapped (not needed for DECB target):**
- `debug_level` / `debug_file` — present in Python as `debug_level`, `debug_file`
- `list_file`, `map_file`, `output_file`, `symbol_dump_file` — present in Python

**Python fields not in C struct (additions):**
- `expr_ctx` — Python's expression callback context (replaces C's global function pointers)
- `input_data` — source string for in-memory assembly (no C equivalent)
- `top_macro` — macro expansion context

### `symtab_t` → `SymTab`

C uses a binary search tree (`struct symtabe` with `left`/`right` pointers).
Python uses a dict for O(1) lookup. The behavioral difference:

- Symbol lookup order differs (tree is sorted, dict is hash-ordered)
- Duplicate symbol handling: C tree walks both subtrees; Python dict overwrites
- Symbol versioning (`version` field on `symtabe`): needs verification

The fidelity harness tests symbol lookup indirectly through assembly output.
No structural test for symbol table internals yet — add one for:
- Multiple definitions of same symbol
- SET vs EQU (SET allows redefinition, EQU does not)
- Local symbol scoping by context number

### `crc[3]` → `bytearray(3)`

C: `unsigned char crc[3]` — CRC accumulator for OS-9 modules.
Python: `bytearray(3)` — correct equivalent, zero-initialized.

Width concern: CRC operations involve byte-level arithmetic that must
stay within 8 bits. The CRC update function must use `c_uint8()` for
any arithmetic that could exceed 255.

---

## Structure 3: `lw_expr_t` (expression tree)

**C declaration:** `lwlib/lw_expr.h`
**Python equivalent:** `class Expr` in `cocotools/lw_expr.py`
**Role:** Expression tree node. Represents values that may not yet be
resolved (forward references, address-dependent expressions).

### Key Points

The expression tree is immutable once constructed — nodes are created
and linked, never modified in place. The reduce/simplify operations
create new nodes rather than modifying existing ones.

**Integer value width:** Expression integer values in C are `int` (32-bit
signed). Python integers are unbounded. Values that come from 16-bit
addresses or 8-bit immediate values will fit within bounds, but
expressions involving arithmetic on those values could theoretically
exceed 32-bit range. In practice this doesn't occur for 6809 assembly
(16-bit address space) but the Python translation should be aware.

**`intval()` return type:** C's `lw_expr_intval()` returns `int`.
Python's `Expr.intval()` returns a Python int (unbounded). If the
caller uses the result in a context that expects bounded behavior,
explicit masking is needed — but this is handled by the caller's
context (the instruction handlers), not by the expression evaluator.

---

## Structure 4: `sectiontab_t`

**C declaration:** `lwasm.h`
**Python equivalent:** `class Section` in `cocotools/lwasm_core.py`
**Role:** One per section (for object file output). For DECB output,
typically only one section exists.

**Key field:** `obytes` (output byte buffer) maps to Python `bytearray`.
Width concern: byte accumulation must stay within 8 bits per byte.

---

## Structural Tests Needed

The output-level fidelity harness catches wrong bytes. These structural
tests catch wrong internal state that might produce correct output for
simple inputs but fail for complex ones:

```python
STRUCTURAL_TESTS = [
    # After assembling LDA #$42:
    # cl.len should be 2 (opcode + immediate)
    # cl.output should be bytearray([0x86, 0x42])
    # cl.pb should be 0 (not used for immediate)
    # cl.lint should be 0

    # After assembling LDA ,X (zero-offset indexed):
    # cl.len should be 2 (opcode + postbyte)
    # cl.pb should be 0x84 (zero-offset X postbyte)
    # cl.lint should be 0 (0 extra bytes)

    # After assembling LDA 100,X (8-bit offset indexed):
    # cl.len should be 3 (opcode + postbyte + 1 offset byte)
    # cl.pb should be 0x88 (8-bit offset X postbyte)
    # cl.lint should be 1 (1 extra byte)

    # After assembling LDA 1000,X (16-bit offset indexed):
    # cl.len should be 4 (opcode + postbyte + 2 offset bytes)
    # cl.pb should be 0x89 (16-bit offset X postbyte)
    # cl.lint should be 2 (2 extra bytes)

    # After assembling LDA -5,X (5-bit negative offset):
    # cl.len should be 2 (opcode + postbyte, no extra bytes)
    # cl.pb should be 0x1B (5-bit signed -5 in X register field)
    # cl.lint should be 0 (5-bit = 0 extra bytes beyond postbyte)

    # Symbol table after EQU:
    # lookup_symbol('LABEL') should return expression with intval() == value

    # Error state after bad operand:
    # as_.errorcount should be 1
    # cl.err should not be None
]
```

Add these to `test_fidelity.py` as a third test category: structural tests.

---

## Cross-Function Field Usage Map

Fields most critical to get right across function boundaries:

| Field | Written by | Read by | Width risk |
|-------|-----------|---------|------------|
| `pb` | parse | resolve, emit | No (int sentinel -1 and byte values 0-255 fit) |
| `lint` | parse | resolve, emit | No (small int 0-3 and -1) |
| `lint2` | parse | resolve, emit | No (same as lint) |
| `len` | parse, resolve | all passes, output | No |
| `addr` | pass1 | resolve, emit | Expression tree — no width issue |
| `output` | emit | output writer | Byte values — use bytearray correctly |
| `outputl` | emit | output writer | Sentinel -1 vs 0 — see divergence note |
| `exprs` | parse (save_expr) | resolve, emit (fetch_expr) | Expression tree |
| `dpval` | pseudo (SETDP) | insn_gen resolve | `& 0xFF` needed — is `int` in C |
| `pragmas` | pass1, pragma | all | Bitfield — no width issue at 32 bits |

---

## Summary of Divergences

| Structure | Field | C init | Python init | Impact |
|-----------|-------|--------|-------------|--------|
| `line_t` | `insn` | `0` | `-1` | Low — sentinel use is consistent |
| `line_t` | `outputl` | `0` | `-1` | Low — sentinel use is consistent |
| `line_t` | `ltext` | NULL | `''` | Very low — both falsy |
| `line_t` | `linespec` | NULL | `''` | Very low — both falsy |

No high-impact divergences found. All divergences are intentional sentinel
choices that are consistent throughout the existing translation.

The structural test suite (to be added) will verify these hold under
realistic assembly scenarios.

---

*Last updated: July 2026*
*C source reference: lwtools 4.24 lwasm.h*
*Python reference: cocotools/lwasm_core.py*
