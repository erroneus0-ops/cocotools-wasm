# Tools Handoff

This file holds everything specific to **the tools** -- the standalone
6809/6309 Python toolchain (`cocotools`: disassembler, assembler,
markup processor) built as an independent reimplementation and
validation reference alongside the WASM-compiled `lwasm`/`toolshed`,
plus the various small standalone utility scripts built along the way
(`zip_backup.py`, and the newer `fix_keyboard_pointer_events.py` /
`fix_keyboard_label_naming.py`, which live in the Environment handoff
instead since they're specifically keyboard/SVG tools, not part of the
6809 toolchain proper).

Extracted out of CLAUDE_MANIFESTO.md (2026-07-31) as part of splitting
project-specific content into its own dedicated handoff, separate from
the manifesto's general, project-agnostic behavior/style guidance and
the Book and Environment handoffs.

Real, concrete status milestone as of the most recent entry here:
confirmed July 16 2026, `cocotools`' assembler produces byte-for-byte
identical output to Ciaran's own `asm6809` (2.12) on a 6309-mode test
file -- genuine cross-validation, not just "seems to work."

Still open: the wrapper-consistency work flagged in earlier sessions
(widening `lwasm_wrapper.c` / `cocotools_wasm/lwasm.py` to accept a
real flag string passed straight to `lwasm_main`, instead of exposing
only the `format` parameter) -- not started.

---

## Toolchain & NPP Workflow

```
# Disasm pass (NPP Run command):
cmd /c cd /d $(CURRENT_DIRECTORY) && python dis6x09.py --proj $(NAME_PART).json -n --markup

# Markup pass (NPP Run command):
cmd /c cd /d $(CURRENT_DIRECTORY) && python markup.py $(NAME_PART).dasm $(NAME_PART).json
```

File extensions:
- `.dasm` -- disassembler output, annotated, NOT directly assembleable
- `.asm`  -- prepasm.py output, assembleable by lwasm

BSS format in JSON (unified):
```json
"bss": {
  "88": {"name": "BSS.DEName", "comment": "29-byte filename field"}
}
```
Auto-migrates old plain-string format on load.

---

## cocotools -- Python Toolkit (IN PROGRESS)

**Goal:** Fully self-contained Python replacement for lwasm + toolshed + decb.
Python is everywhere. No platform binaries. Works in browser via XRoar WASM.

**Workflow vision:**
```
python cocotools.py assemble GUESS.ASM -o GUESS.BIN
python cocotools.py makedsk GUESS.DSK GUESS.BIN GUESS.BAS
# Mount GUESS.DSK in XRoar WASM -- done
```

### Source References for Translation

**lwasm (assembler):**
- Source: http://www.lwtools.ca/hg/index.cgi/file/tip/lwasm/
- Language: C (GPL v3), author: William Astle <lost@l-w.ca>
- Also mirrored: https://github.com/stahta01/LWTools
- Also mirrored: https://github.com/jmatzen/LWTools
- Key files to translate:
  - lwasm/instab.c (47KB) -- instruction table (DONE in instab.py)
  - lwasm/instab.h -- structure definitions
  - lwasm/insn_gen.c -- general addressing mode handling
  - lwasm/insn_indexed.c (13KB) -- indexed postbyte encoding (COMPLEX)
  - lwasm/insn_rel.c -- branch instruction encoding
  - lwasm/insn_inh.c -- inherent instructions
  - lwasm/insn_rlist.c -- register list (PSHS/PULS)
  - lwasm/insn_rtor.c -- register-to-register (TFR/EXG)
  - lwasm/pass1.c -- first pass (parse, symbol collection)
  - lwasm/pass2.c through pass6.c -- resolution and emission passes
  - lwasm/output.c -- DECB and raw output format
  - lwasm/os9.c -- OS-9 module output
  - lwasm/lwasm.c -- main assembler logic
  - lwasm/main.c -- CLI entry point

**toolshed/decb (disk image tools):**
- Source: https://github.com/hathaway3/toolshed
- Also: https://github.com/n6il/toolshed
- Language: C (GPL), key tool: decb (Disk Extended Color BASIC utility)
- Key operations needed: dskini, copy, dir, dump

**BASIC tokenizer:**
- No single authoritative source
- CoCo BASIC token table documented in "Color BASIC Unravelled" series
- Scanned copies at: https://techheap.packetizer.com/computers/coco/unravelled_series/

**XRoar WASM:**
- https://www.6809.org.uk/xroar/
- Browser-based CoCo emulator -- no installation needed

### cocotools Status

| File | Status | Notes |
|------|--------|-------|
| cocotools/DESIGN.md | DONE | Full architecture document |
| cocotools/instab.py | DONE | 139 instructions, 15 spot checks pass |
| cocotools/lw_expr.py | DONE | Faithful translation of lw_expr.c — expression trees, simplify, parser |
| cocotools/lwasm.py | STUB | Phase 1 reimplementation (not a translation) — to be replaced |
| cocotools/decb.py | DONE | DSK builder + BIN formatter, Dsk class |
| cocotools/basic.py | NOT STARTED | BASIC tokenizer |
| cocotools.py | DONE | CLI: assemble, makedsk, binin, dskls |

### instab.py Design (for lwasm.py author)

INSTAB dict structure:
```python
INSTAB['LDA'] = {
  'imm': 0x86,   # immediate opcode
  'dir': 0x96,   # direct page opcode
  'idx': 0xA6,   # indexed opcode
  'ext': 0xB6,   # extended opcode
  'parse': 'gen8'  # parser class
}
# Prefixed opcodes: P10 = 0x1000, P11 = 0x1100
# None = mode not supported for this instruction
```

Parser classes: inh, gen8, gen16, gen0, rel8, rel16, relgen,
                rtor, rlist, imm8, leax, mem

Indexed register postbyte bits [6:5]: X=00, Y=01, U=10, S=11
PCR addressing uses postbyte 0x8C (8-bit) or 0x8D (16-bit)

### Verification Strategy

For each program:
1. Assemble with lwasm -> reference binary
2. Assemble with Python cocotools -> test binary
3. Compare byte-for-byte -> must match exactly

Start with GUESS.ASM (30 bytes, simple)
Then HELLO.ASM (80 bytes)
Then dir/supercomm22 (real-world)

---

## Engine Features (dis6x09.py)

- `target`: "os9" emits mod/emod/rmb/size idioms; "raw" keeps EQU output
- `hex_offsets`: ["U"] shows hex offsets on unnamed U-relative addressing
- `--source` optional when `binary` field set in JSON
- BSS: unified dict format, auto-migrates old plain-string format
- `prev_ret = is_ret` -- separator fires after labeled RTS too
- `/bss/ $XX Name "comment"` -- quoted comment replaces size annotation

## prepasm.py Features

- Converts BSS EQU -> RMB with gap-based size calculation
- Preserves analyst comments on RMB lines
- Handles "raw" (.dasm EQU style) input

## markup.py Directives (quick reference)

Key ones: /label/, /bss/, /comment/.../end-comment/, /; line comment/,
/region/, /routine/, /rename-label/, /remove-comment/
Full reference in any .dasm file at bottom as MARKUP QUICK REFERENCE

---

## zip_backup.py Rewrite (July 3 2026)

Complete rewrite with config file, module system, explicit flags.

### Location
- Office: `C:\Users\dhauck\AppData\Local\scripts\zip_backup.py`
- Home: `C:\Users\Daniel\AppData\Local\scripts\zip_backup.py`
- Config: `zip_backup.json` next to script (not tracked in git, machine-specific)
- Modules: `zip_backup_modules\` folder next to script

### Flags
- No flags → shows help (no accidental runs)
- `--run` → incremental backup
- `--full` → full backup
- `--dry-run` → preview, no zip created
- `--config` → interactive reconfiguration only, no backup
- `--help` / `-h` → help

### Config: zip_backup.json
```json
{
    "source_dir":       "D:\\git",
    "backup_dir":       "D:\\git_backups",
    "log_file":         "D:\\git_backups\\zip_backup_log.log",
    "max_backups":      20,
    "prefix":           "git_",
    "excluded_folders": ["screenshots"],
    "modules":          ["git_bundle"]
}
```
Optional keys: `suffix_incremental` (default `_daily`), `suffix_full` (default `_full`)

### Key behaviors
- Dot-folders (.git, .svn, etc.) always excluded from incremental at runtime
- Not stored in JSON -- handled by code
- Log: weekly rotating (TimedRotatingFileHandler, W0, 4 weeks)
- Config prompts: short labels when value exists, descriptive with platform
  hints when empty. Windows hints `C:\DATA\...`, Unix hints `/home/user/...`
- `X to clear` for folder exclusions
- Scheduled task: exits with error code 2 if no config and no terminal
- `--config` requires interactive terminal, exits with error if not

### Module System
Modules in `zip_backup_modules\` folder. Each is a `.py` file exposing:
- `NAME` -- string, matches config "modules" list entry
- `DESCRIPTION` -- string
- `run(cfg, backup_dir, dry_run)` -- returns list of Path objects to include

Bundled module: `git_bundle.py` -- creates `git bundle --all` snapshot of
each repo found directly under source_dir. Bundle written to backup_dir,
included in zip. Self-contained restore: `git clone repo.bundle restored_repo`

Optional git_bundle config in zip_backup.json:
```json
"git_bundle": { "git_exe": "C:\\Program Files\\Git\\cmd\\git.exe" }
```
If omitted, assumes `git` is in PATH.

README in `zip_backup_modules\README.md` documents module contract.

---

## Disassembly Workflow: dis6x09.py + markup.py

The disassembler is a multi-tool workflow, not a one-shot script.
Read analyst_json_tutorial.md and analyst_markup_reference.md before
working on any disassembly project.

### Tools in the chain

- **dis6x09.py** — disassembler engine. Produces annotated .dasm output.
  Use --help to see all options. Two formats supported:
  - OS-9 module: requires --proj JSON file (created on first run if absent)
  - DECB/Color BASIC BIN: use --decb flag, no JSON required for first pass
- **markup.py** — reads analyst directives from the .dasm file, updates
  the project JSON. The analyst never edits JSON directly.
- **strip_listing.py** — removes directives and address/byte columns,
  producing a clean .asm file for reassembly
- **compare_bins.py** — verifies reassembled binary matches original

### Workflow

```
First run:
  python3 dis6x09.py --source binary --proj project.json
  → prompts for JSON name if not found (has timeout -- use -n for default)
  → writes project.json and binary_proj.dasm

Work cycle (repeat):
  1. Review binary_proj.dasm
  2. Add /directives/ to .dasm (labels, data regions, comments)
  3. python3 markup.py binary_proj.dasm → updates project.json
  4. Re-run dis6x09.py → cleaner output reflecting analyst knowledge

DECB one-shot:
  python3 dis6x09.py --source file.bin --decb
  → no JSON needed, CoCo hardware equates at top, outputs file_proj.dasm

Product stage:
  strip_listing.py → clean .asm
  assembler → .bin
  compare_bins.py ← must match original
```

### Key docs
- analyst_json_tutorial.md -- full workflow with directive examples
- analyst_markup_reference.md -- complete directive reference

### Notes
- The prompt for JSON name will hang in piped/automated contexts.
  Use -n flag to skip prompts and accept defaults.
- DECB project JSON workflow (--decb --proj) not yet implemented --
  currently DECB is one-shot only. Full DECB workflow is a pending item.

---

## dis6x09.py / markup.py -- Discoverability Design Notes

The tool was redesigned after identifying that the original workflow
punished natural first-contact behavior:

**Problems identified:**
- No args → hung indefinitely waiting for JSON name prompt
- --help showed -h in usage line (unclear)
- No path to useful output without knowing the full JSON workflow
- MARKUP_QUICK_REF embedded in dis6x09.py (duplicate, drift risk)

**Solutions applied:**
- No args → clean usage line + "run with --help" hint, exits cleanly
- --help shown explicitly in usage line
- --quick / -q → first-contact mode: auto-detect format, no JSON,
  no prompts, write .dasm and exit. Natural entry point for new binary.
- Auto-detection: OS-9 ($87CD), DECB (block structure), raw (fallback)
- --os9 / --decb / --raw override detection when needed
- MARKUP_QUICK_REF moved to markup.py as single source of truth
- markup.py --ref → terminal reference; --ref --asm → comment lines
- dis6x09.py --ref calls markup.py --ref --asm via subprocess

**Intended first contact with an unknown binary:**
```bash
python3 dis6x09.py --source unknown.bin --quick
```
Get output, get oriented, then start a full --proj workflow if warranted.

---

## FIXED: PSHS D / PULS D bug in cocotools

`PSHS D` and `PULS D` were assembling incorrectly -- producing postbyte
$80 (PC) instead of $06 (A+B).

**Root cause:** _RLIST_REGS table has D at rval 8, but the mapping code
checked `rn == 8` for PC (should be rval 7). PC and D indices were swapped
in the bit-mapping logic.

**Fix:** insn_funcs.py -- corrected rval→bit mapping:
  rn==7 → PC ($80), rn==8 → D ($06 = A|B), rn==9 → S ($40)

**Status:** Fixed July 2026. `PSHS D` and `PULS D` now produce correct
output identical to `PSHS A,B` and `PULS A,B`.

Discovered: via XRoar test output -- print_retaddr.asm printed `$$`
instead of hex addresses. The bug caused `PSHS D` to push PC instead
of saving the return address, corrupting the stack frame.

---

## cocotools Validation Against asm6809

July 16 2026 -- cocotools and Ciaran's asm6809 2.12 produced byte-for-byte
identical output assembling print_retaddr.asm with 6309 mode enabled.

asm6809 also warns on [,-S] as "illegal indirect indexed mode" --
independently confirming W2000 diagnostic is correct.

TFR 0,D in 6309 mode = $1F $C0 confirmed by both assemblers.
