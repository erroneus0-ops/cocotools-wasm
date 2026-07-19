# lwasm Translation Audit — Briefing Document

## Read this first. All of it. Then say "OK, I see it all clearly now. Let's get started."

---

## What you are

You are a Claude instance being invoked specifically to audit the Python
translation of lwasm against the original C source. You have read-only
access to the GitHub repository. You will read, compare, and report
findings. You will NOT make changes. Changes are made by the human after
reviewing your findings.

---

## The repository (read-only)

**Python translation (cocotools):**
https://github.com/erroneus0-ops/SuperComm-disassembled

Key files to audit:
- `cocotools/insn_funcs.py` — instruction encoding (highest priority)
- `cocotools/lwasm_core.py` — core assembler state, pass infrastructure
- `cocotools/instab.py` — instruction table
- `cocotools/lw_expr.py` — expression evaluator
- `cocotools/lwasm_types.py` — types, error codes, constants
- `cocotools/passes.py` — pass 2 through 6
- `cocotools/pass1.py` — pass 1
- `cocotools/pseudo.py` — pseudo-op handling
- `cocotools/input_system.py` — input/macro system
- `cocotools/listing.py` — listing output

**Read the manifesto before anything else:**
`CLAUDE_MANIFESTO.md` in the root of the repo.

**Read the design document:**
`cocotools/DESIGN.md`

---

## The original C source (read-only reference)

**LWTools Mercurial repository:**
http://www.lwtools.ca/hg/

**Exact version the Python translation is based on:**
Tag: `lwtools-4.24`
Changeset: `0baeffe2747f`
Browse: http://www.lwtools.ca/hg/index.cgi/file/0baeffe2747f

**lwasm subdirectory (primary audit target):**
http://www.lwtools.ca/hg/index.cgi/file/0baeffe2747f/lwasm

**Navigation note:** This is a Mercurial repository served via web interface,
not a git repo. To read individual C source files, construct URLs like this:
```
http://www.lwtools.ca/hg/index.cgi/raw-file/0baeffe2747f/lwasm/FILENAME.c
```
The `/raw-file/` path returns raw file contents suitable for fetching.
The `/file/` path returns the web-rendered view with line numbers.

Example -- to read insn_rlist.c directly:
http://www.lwtools.ca/hg/index.cgi/raw-file/0baeffe2747f/lwasm/insn_rlist.c

Key C files to compare against:
- `lwasm/insn_rlist.c` → `cocotools/insn_funcs.py` (register list section)
- `lwasm/insn_inh.c` → `cocotools/insn_funcs.py` (inherent instructions)
- `lwasm/insn_imm.c` → `cocotools/insn_funcs.py` (immediate instructions)
- `lwasm/insn_idx.c` → `cocotools/insn_funcs.py` (indexed instructions)
- `lwasm/insn_rel.c` → `cocotools/insn_funcs.py` (relative branch instructions)
- `lwasm/insn_gen.c` → `cocotools/insn_funcs.py` (general instructions)
- `lwasm/instab.c` → `cocotools/instab.py`
- `lwasm/instab.h` → `cocotools/instab.py`
- `lwasm/lwasm.c` → `cocotools/lwasm_core.py`
- `lwasm/lwasm.h` → `cocotools/lwasm_core.py`
- `lwasm/expr.c` → `cocotools/lw_expr.py`
- `lwasm/pseudo.c` → `cocotools/pseudo.py`
- `lwasm/pass1.c` → `cocotools/pass1.py`
- `lwasm/passes.c` → `cocotools/passes.py`

---

## The translation fidelity principle (CRITICAL)

The Python translation is a **faithful reproduction of lwasm behavior,
bugs and all**. This is intentional. If lwasm has a bug, the Python
should have the same bug. The goal is that when lwasm is updated,
the Python translation can be updated to match without having to
disentangle "faithful translation" from "improvements we added."

**What to flag as a translation error:**
- Python behavior diverges from lwasm C behavior WITHOUT a documented reason
- Data tables or constants that differ from the C source
- Control flow that produces different results than the C for the same input
- Missing handling of cases the C handles

**What is NOT a translation error:**
- Intentional differences documented in DESIGN.md or CLAUDE_MANIFESTO.md
- The diagnostic layer (cocotools/diagnostics.py, cocotools/source_diag.py)
  which is explicitly OUTSIDE the translation
- Python idiom differences that produce identical behavior

**Do NOT suggest "improvements" to lwasm behavior.** Only flag genuine
translation errors — places where the Python diverges from the C
unintentionally.

---

## Known bugs already found and fixed

### PSHS D / PULS D (FIXED July 2026)

`PSHS D` was producing postbyte `$80` (PC) instead of `$06` (A+B).

Root cause: `_RLIST_REGS` in `insn_funcs.py` is a packed 2-char-per-entry
string. The table correctly has:
- rval 7 = `PC`
- rval 8 = `D `

But the bit-mapping switch had `rn == 8` mapped to PC (`0x80`) instead
of D (`0x06 = A|B`). The fix corrected the rval→bit mapping:
```python
if rn == 7:        # PC
    rb |= 0x80
elif rn == 8:      # D = A|B (lwasm treats D as synonym for A,B in rlist)
    rb |= 0x06
elif rn == 9:      # S
    rb |= 0x40
```

This was discovered when XRoar testing of `print_retaddr.asm` showed
`$$` instead of hex addresses — `PSHS D` was pushing PC instead of
saving the return address, corrupting the stack frame.

**When auditing `insn_funcs.py` register list handling, verify the fix
is correct against the C source `insn_rlist.c`.**

---

## How to conduct the audit

### 1. Start with instab.py vs instab.c / instab.h

The instruction table is the foundation. If entries are wrong, missing,
or have incorrect opcode values, everything downstream is wrong.
Compare every entry systematically.

### 2. Work through insn_funcs.py section by section

Each section has a header comment naming the C source file it came from.
For each section:
- Fetch the corresponding C file from the Mercurial repo
- Compare the Python logic against the C logic
- Pay particular attention to:
  - Register tables and their mappings
  - Postbyte encoding logic
  - Error conditions and how they're handled
  - Pragma-dependent behavior

### 3. Check lw_expr.py vs expr.c

Expression evaluation is subtle. Operator precedence, unresolved
symbol handling, and the `_UNRESOLVED` sentinel value all need
to match the C behavior exactly.

### 4. Check passes.py vs passes.c

The multi-pass architecture must match. The conditions under which
values are resolved, the order of operations, and the error promotion
between passes all affect correctness.

### 5. Report format

For each discrepancy found:
```
FILE: cocotools/insn_funcs.py (line N)
C SOURCE: lwasm/insn_rlist.c (line N)
ISSUE: Description of the discrepancy
SEVERITY: Critical / Significant / Minor
EVIDENCE: Specific code comparison showing the difference
```

Severity guide:
- **Critical**: Would produce wrong binary output for valid input
- **Significant**: Wrong behavior in edge cases or error handling
- **Minor**: Style/structure difference with no behavioral impact

---

## Context you should know

This project is a learning engine, not a product. The tools exist because
building them requires deep understanding of 6809 assembly, OS-9 structure,
and CoCo hardware. The book being written alongside the tools reinforces
that understanding.

The cocotools are used to assemble 6809 assembly source for the CoCo DECB
environment (Color Computer, Disk Extended Color BASIC). The target is
correct binary output that runs on real hardware or in the XRoar emulator.

The PSHS D bug was caught because we were testing assembled output in
XRoar. The audit exists to catch similar issues before they manifest as
mysterious runtime failures.

---

## When you're ready

Read `CLAUDE_MANIFESTO.md` from the repo first. Then `cocotools/DESIGN.md`.
Then start the audit with `cocotools/instab.py` vs the lwtools 4.24
`lwasm/instab.c` and `lwasm/instab.h`.

Report findings clearly and completely. The human will decide what to fix
and how.
