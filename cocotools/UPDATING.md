# Reconciling a Future lwtools Release Against cocotools

This document exists so that "a new lwtools version came out, update
cocotools to match" is a bounded, checklist-driven task -- not a
from-scratch re-audit. Read this before touching any file.

Written after an eleven-session audit (2026-07-13) that found three
confirmed critical bugs, fixed all three, and closed most of the
codebase's previously-unaudited surface area. If you're reading this
because that audit is now "too long ago to remember," start here.

---

## 1. The version this codebase is pinned to

`cocotools.py` (repo root) declares:

```python
LWASM_BASE_VERSION = "4.24"
LWASM_BASE_DATE    = "2024"   # approximate
```

**First step, always:** confirm what version you're reconciling *against*
(this constant) and what version you're reconciling *to* (whatever just
shipped). Update this constant once -- and only once -- reconciliation is
actually complete, not before. Don't let it drift from reality.

## 2. The file-to-file mapping (this is the whole trick)

cocotools is a near-1:1 file mapping to LWTools' C source, not a
from-scratch reimplementation. That means reconciliation is: diff the new
C source against the pinned version, file by file, and only touch the
Python files whose corresponding C file actually changed.

| cocotools/*.py     | Corresponds to (lwtools)                              |
|---------------------|--------------------------------------------------------|
| `lw_expr.py`         | `lwlib/lw_expr.c`                                      |
| `instab.py`          | `lwasm/instab.c`, the instruction table itself          |
| `insn_funcs.py`       | `lwasm/insn_gen.c`, `insn_indexed.c`, `insn_tfm.c`, `insn_logicmem.c`, `insn_bitbit.c`, `insn_inh.c` |
| `lwasm_core.py`       | Core `line_t`/`asmstate_t` structures, symbol table, `lwasm_reduce_expr` |
| `pseudo.py`           | `lwasm/pseudo.c`                                       |
| `pass1.py`            | `lwasm/pass1.c`                                        |
| `passes.py`           | `lwasm/pass2.c` through `pass7.c`, plus `output.c`       |
| `input_system.py`     | `lwasm/input.c`                                        |
| `listing.py`          | `lwasm/list.c`                                         |
| `decb.py`             | DECB-format-specific logic (no single C equivalent; CoCo-specific) |
| *(no cocotools file)* | `lwasm/macro.c` -- **not yet implemented at all**, see Section 5 |

If a changed upstream C file has no corresponding Python file (only
`macro.c` right now), that's a "do we want to build this yet" decision,
not a reconciliation task.

## 3. Bugs deliberately replicated on purpose -- CHECK THESE FIRST

cocotools's stated philosophy is faithful translation, bugs included --
*not* "improve on lwasm independently." That means some of cocotools's
current behavior is a bug, kept on purpose, because real lwasm has the
same bug. **If a new lwtools release fixes one of these upstream, cocotools's
faithful replica becomes wrong relative to new-upstream, even though it
was correct relative to old-upstream.** These need to be checked
explicitly, every reconciliation, because they will not show up as an
obvious "this looks broken" symptom -- they'll show up as "this now
disagrees with the newest lwasm," which only a deliberate check catches.

- **`passes.py`, `do_pass5`'s address-resolution recovery loop.**
  Real lwasm's `pass5.c` has an apparent copy-paste bug: it uses a fixed
  `sl` instead of the advancing `cl` in its inner loop, and checks
  `cl->addr` twice instead of `cl->addr` then `cl->daddr`. cocotools
  replicates the first half of this bug faithfully and (as of the
  2026-07-13 audit) *unintentionally* fixes the second half -- an honest
  divergence, not a deliberate one, but worth knowing either way. A
  formal bug report for this was written and is intended for submission
  to William Astle (see `lwtools_upstream_bug_report_pass5.txt` in this
  directory). **If a new lwtools release includes a pass5.c fix,
  re-derive `do_pass5` from the new C rather than assuming the old
  replication is still correct.**

Keep this list updated as new deliberate-replication decisions are made.
Right now there is exactly one entry; there may be more by the time you
read this.

## 4. Two categories of C/Python divergence to watch for in any diff

When reading a changed C file during reconciliation, these are the
specific shapes of bug that a surface-level "translate the syntax" pass
will miss. All three were found the hard way during the 2026-07-13 audit.
**`cocotools/c_compat.py`** now exists specifically to hold the fixes for
these -- use it, and extend it, rather than re-deriving the fix inline at
each call site (see that file's own docstrings for what's implemented vs.
stubbed).

- **Truncating vs. floor division/modulo.** Any C `/` or `%` on a value
  that could ever be negative needs `c_compat.c_trunc_div` /
  `c_trunc_mod`, not Python's native `//` / `%`. This was the actual
  MOD/INTDIV bug found in `lw_expr.py`. Native Python operators will run
  without error and be silently wrong only on mixed-sign inputs -- easy
  to miss in casual testing.
- **Fixed-width integer wraparound.** Not yet hit in this codebase (6809/
  6309 values stay in ranges that avoid it), but if a new C file does
  arithmetic relying on e.g. an 8-bit value wrapping from 255 to 0,
  Python's arbitrary-precision `int` will NOT do that automatically.
  Stub for this exists in `c_compat.py` (`c_int_wrap`), unimplemented,
  waiting for the first real need.
- **Null-termination doing double duty as an implicit length.** Also not
  yet hit, but worth knowing the shape of: a C `while (*p) { ...; p++; }`
  loop is often using the trailing `\0` as both "keep going" and "this is
  how long the string is." A direct translation needs to notice both
  roles, not just the looping one. Stub exists (`c_strlen_walk`),
  unimplemented.
- **The `char **p` mutable-cursor idiom.** Already fully solved --
  `c_compat.Ptr` (same class already in use as `lw_expr.py`'s `Ptr`)
  reproduces a C function's ability to advance the *caller's* read
  position by writing through a pointer, which Python's immutable
  strings can't do directly.

## 5. Known gaps that are NOT bugs -- disclosed, not hidden

These are open work, not divergences to fix reactively:

- **`macro.c` has no Python implementation at all.** MACRO/ENDM cannot
  be used in cocotools right now. A full implementation roadmap already
  exists (audit session 9) -- the scaffolding in `pass1.py` for
  receiving macro-expansion control lines is already in place and
  verified correct; the actual `expand_macro`/`add_macro_line` functions
  themselves were never written.
- **`output.c`'s 10 other output formats are unimplemented.** Only DECB
  and RAW exist. Confirm whether a given SuperComm-adjacent project
  actually needs OS9 format specifically before building anything here.
- **`instab.py` is missing 10 mnemonics** (6309-conv: asrq/clrq/comq/
  lsle/lslf/lslq/lsrq/nege/negf/negw) **and has 7 more with a dropped
  dual-dispatch entry** (asrd/clrd/comd/lsld/lsrd/negd/tstd -- the
  6809-legal convenience-macro form is silently shadowed by the
  6309-only hardware-opcode form, because `INSTAB_BY_NAME` is a flat
  dict and can't represent C's pragma-disambiguated duplicate entries).
  Confirmed, not yet fixed as of this writing.
- **Two intentional cocotools-only additions exist beyond lwasm's real
  feature set:** `PHASE`/`DEPHASE` (a pseudo-op with no lwasm
  equivalent) and `PRAGMA_NOLISTCODE` (listing-only). Both are additive,
  not divergent -- just make sure a future diff doesn't mistake "this
  exists in cocotools but not in the new C" for a regression. It never
  existed in C at all.

## 6. The two-assembler-implementations trap (already fixed, but know it exists)

`cocotools/lwasm.py` is a self-contained, earlier prototype assembler --
its own inline register tables, its own addressing-mode logic, no use of
the `instab.py`-driven dispatch system the rest of this codebase runs on.
**It is not used by the real `cocotools.py` CLI**, which imports directly
from `pass1`, `passes`, `lwasm_core`, and `input_system`. Until
2026-07-13, `cocotools/__init__.py` exported `assemble` from this old
prototype, meaning `from cocotools import assemble` (the "normal" way to
use the package) silently returned different, unaudited behavior than
what the actual CLI ran. This has been fixed -- `__init__.py` now exports
from `.passes`, matching the CLI. **If you ever see two things in this
codebase that both look like "the assembler," check which one the CLI
actually imports before assuming either is dead code or live code.**

## 7. A regression corpus would make all of this checkable, not just careful

None of the following are built yet as checked-in test files, but every
one of them was a real ad-hoc test written during the 2026-07-13 fixes,
and would take one sitting to formalize:

- Mixed-sign MOD/INTDIV (`-7 % 2`, `7 % -2`, etc.) -- catches the
  truncating-vs-floor divergence.
- A multi-line program with a leading RMB before the first ORG, and a
  mid-program RMB gap -- catches the RAW-output line-order-vs-address-
  order divergence.
- `TFM D,X+`, `AIM #$0F,$50`, `BAND CC,0,1,$50` -- catch regressions in
  the 6309 instruction families fixed this session (real 6309 opcode
  bytes to check against: TFM r0,r1+ = `$11 $3B`; AIM direct = `$02`;
  BAND = `$11 $30`).
- `PSHS D,X` / `PULS D,X,PC` -- catches regression on the very first bug
  this whole audit traces back to (D has no dedicated postbyte bit; must
  assemble identically to `PSHS A,B,X`).

Running the current cocotools against this corpus and diffing byte output
before and after a reconciliation pass would catch anything the C-diff
step alone might miss.

---

**In short: pin, diff, check the deliberate-bug list, watch for the three
category-error shapes in section 4, and don't assume `lwasm.py` is
relevant to anything.** That's the whole procedure. Everything else is
ordinary code review of whatever specific lines the diff actually flags.
