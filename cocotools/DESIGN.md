# cocotools — Design Document

## Project Goal

A faithful Python translation of lwasm (LWTools 4.24, William Astle, GPL v3).

**Faithful translation** means the same data structures, the same six-pass
algorithm, the same resolution logic.  The output is correct by construction
because the logic is the same, not because it was tuned to match test cases.

This mirrors the philosophy of the disassembler project: byte-perfect
reassembly is the baseline, not the end goal.  For lwasm, the baseline is
that every valid lwasm source file produces identical output from the Python
translation.  Edge cases are handled correctly because the code follows the
same path, not because they were anticipated.

A reimplementation that passes known test cases is not a translation.  The
disassembler learned this lesson when it encountered opcodes not yet handled
— the right answer is completeness by architecture, not by test coverage.

Source references:
  lwasm C source:  http://lwtools.projects.l-w.ca/hg/index.cgi/file/tip/lwasm/
  LWTools mirrors: https://github.com/stahta01/LWTools
                   https://github.com/jmatzen/LWTools


---

## Scope

cocotools provides:

  lwasm.py    Python translation of lwasm — 6809/6309 assembler
  lw_expr.py  Python translation of lwlib/lw_expr.c — expression trees
  decb.py     DSK and BIN format handler (not part of lwasm; replaces toolshed)
  basic.py    BASIC tokenizer (not started)
  crc.py      CRC-24 for OS-9 modules (not started)
  cocotools.py  CLI entry point

The scope of the lwasm translation is the DECB and OS-9 output targets.
Object file linking (lwlink) is out of scope for now.


---

## Layer Order (dependency stack)

Each layer depends on the one below it.

    instab.py         Instruction table (translation of instab.c / instab.h)
    lw_expr.py        Expression trees   (translation of lwlib/lw_expr.c)
    lwasm.py          Assembler          (translation of pass1..6, insn_*.c,
                                          pseudo.c, output.c, symbol.c)

instab.py is complete.  lw_expr.py is complete.  lwasm.py is the next layer.


---

## lw_expr.py — Expression Tree System (DONE)

Translation of lwlib/lw_expr.c (1442 lines C → 844 lines Python).

Expr nodes have four types (matching lw_expr_type_* enum):
  TYPE_INT      resolved integer value
  TYPE_VAR      symbol name, resolved by evaluate_var callback
  TYPE_OPER     operator node with operand list
  TYPE_SPECIAL  assembler-defined reference (line address, symbol entry, etc.)

ExprContext holds the callbacks that were static globals in the C code:
  evaluate_special(type_code, ptr) → Expr | None
  evaluate_var(name) → Expr | None
  parse_term(Ptr, ctx) → Expr | None   (set by lwasm to lwasm_parse_term)
  divzero()
  expr_width (0=16-bit, 8=8-bit, affects complement operations)

Key behaviours preserved from C:
  In-place simplification: Expr._become(other) mirrors *E = *te
  goto again pattern: recursive _simplify_go call after SPECIAL/VAR resolves
  Level/bailing anti-recursion (depth limit 500, matching C)
  Pratt-style parser matching lw_expr_parse / lw_expr_parse_compact
  Like-term collection in PLUS nodes
  Distribution: int * (a + b) → int*a + int*b

Ptr class simulates C char** for parser input advancement.


---

## lwasm.py — Six-Pass Assembler (IN PROGRESS)

Translation of the following C files, in dependency order:

  lwasm.h          Data structures: line_t, asmstate_t, symtabe
  symbol.c         Symbol table (binary tree, context-scoped)
  input.c          Source file reading and include handling
  lwasm.c          Core helpers: lwasm_emit, lwasm_emitexpr,
                   lwasm_evaluate_var, lwasm_evaluate_special,
                   lwasm_parse_term, lwasm_reduce_expr
  pass1.c          First pass: tokenise, parse, build line list
  pass2.c          Simplify all expressions; flag undefined symbols
  pass3.c          Resolve1: iterate resolve callbacks until stable
  pass4.c          Resolve2: force resolution of remaining unknowns
  pass5.c          AssignAddresses: resolve all line addresses
  pass6.c          Finalise: final expression reduction before emit
  insn_gen.c       General addressing mode parse/resolve/emit
  insn_indexed.c   Indexed postbyte encoding
  insn_rel.c       Relative branch instructions
  insn_inh.c       Inherent instructions
  insn_rlist.c     Register list (PSHS/PULS/PSHU/PULU)
  insn_rtor.c      Register-to-register (TFR/EXG)
  insn_logicmem.c  Logic-memory instructions (AIM/OIM/EIM/TIM, 6309)
  insn_bitbit.c    Bit manipulation (6309)
  insn_tfm.c       Transfer-memory (6309)
  pseudo.c         All directives (ORG, EQU, FCB, FDB, FCC, MACRO, IF, ...)
  output.c         Output formatters (DECB, OS-9, raw, SREC, ihex)
  macro.c          Macro expansion
  section.c        Section management (for object file output)
  list.c           Listing file generation


### Key Data Structures

**Line (line_t)**
  addr     Expr   assembly address — expression tree, not integer
  daddr    Expr   data address (OS-9 only)
  phase    Expr   PHASE override
  len      int    instruction size in bytes; -1 = unknown
  dlen     int    data size; -1 = unknown
  minlen   int    minimum possible size
  maxlen   int    maximum possible size
  insn     int    index into instab; -1 = not an instruction
  sym      str    label on this line (or None)
  output   bytes  emitted bytes (filled in pass 6 emit callback)
  exprs    dict   {id: Expr} — named expressions saved during parse
  dpval    int    direct page value at this line
  genmode  int    generation mode (8 or 16 bit immediate)
  prev/next        linked list pointers

**AsmState (asmstate_t)**
  output_format   OUTPUT_DECB | OUTPUT_OS9 | OUTPUT_RAW | ...
  pragmas         bitmask of active pragmas (PRAGMA_6809, PRAGMA_AUTOBRANCHLENGTH, ...)
  passno          current pass number (0=pass1, 1=pass2, ..., 5=pass6)
  pretendmax      bool: use maxlen instead of len for address calc
  badsymerr       bool: error on undefined symbol (set in pass2)
  line_head       first Line in linked list
  line_tail       last Line
  cl              current Line being processed
  symtab          symbol table root
  execaddr        integer exec address from END directive
  execaddr_expr   Expr form of same
  endseen         bool: END directive has been seen
  inmod           bool: inside OS-9 MOD/EMOD block
  crc             3-byte CRC accumulator (OS-9)

**SymTabEntry (symtabe)**
  symbol    str     symbol name
  context   int     local context (-1 = global)
  version   int     for SET (allows redefinition)
  flags     int     symbol_flag_set | symbol_flag_nocase | ...
  value     Expr    the symbol's value — an expression tree

Note: symbol values are Expr trees, not integers.  A label's value is the
address expression of its line, which starts as an Expr tree and simplifies
to an integer once all preceding line sizes are known.


### Six-Pass Structure

**Pass 1 (pass1.c) — do_pass1(as)**
  Read source line by line.  For each line:
    Allocate a Line node and append to the linked list
    Set line.addr = prev.addr + Expr.special(LINELEN, prev)
      (This is an expression tree: addr is unknown until prev.len is known)
    Call lwasm_parse_term to identify mnemonic
    Look up mnemonic in instab -> set line.insn
    Call instab[insn].parse(as, line, operand_ptr)
      parse() stores the parsed operand as saved expressions on the line
      parse() sets line.len = -1 (unknown) or a fixed value if immediately known
    Register line.sym in the symbol table with value = line.addr expression
    Call lwasm_reduce_line_exprs() to attempt early simplification

**Pass 2 (pass2.c) — do_pass2(as)**
  Set as.badsymerr = 1 (now errors on undefined symbols)
  For each line: call lwasm_reduce_expr() on addr, daddr, all saved exprs
  Verify export list (OBJ target only)

**Pass 3 (pass3.c) — do_pass3(as)**
  Repeat until no sizes change:
    For each line: reduce all expressions
    If line.len == -1 and has resolve callback:
      call instab[insn].resolve(as, line, force=0)
      If resolve() set line.len: increment resolved count
  Stop when resolved count reaches zero (nothing new to resolve)

**Pass 4 (pass4.c) — do_pass4(as)**
  For each still-unresolved line:
    call instab[insn].resolve(as, line, force=1)
    resolve() MUST produce a size (use worst-case if uncertain)
    Error if still len == -1 after force

**Pass 5 (pass5.c) — do_pass5(as)**
  Force resolution of all line address expressions
  All sizes now known, so all addr Exprs should collapse to integers

**Pass 6 (pass6.c) — do_pass6(as)**
  Final expression reduction on all saved exprs
  Call instab[insn].emit(as, line) for each line to produce output bytes


### Instruction Callback Pattern

Each instab entry has three callbacks (function pointers in C, callables in Python):

  parse(as, line, p)       Called in Pass 1.
                           Reads operand from Ptr p.
                           Saves parsed Exprs to line with lwasm_save_expr().
                           Sets line.len = -1 (deferred) or known size.
                           Sets line.minlen and line.maxlen.

  resolve(as, line, force) Called in Passes 3 and 4.
                           With force=0: try to determine line.len; ok to skip.
                           With force=1: must set line.len (use maxlen if needed).
                           Uses lwasm_fetch_expr() to retrieve parsed Exprs.

  emit(as, line)           Called in Pass 6.
                           Uses lwasm_fetch_expr() to retrieve final Exprs.
                           Calls lwasm_emit(line, byte) for each output byte.

The separation of parse/resolve/emit (rather than a single function) is what
makes the multi-pass architecture work correctly.  An instruction only knows
its size in resolve(), not in parse().


### pretendmax and Address Calculation

Line addresses are expression trees:

  line[n].addr = line[n-1].addr + Expr.special(LINELEN, line[n-1])

LINELEN is a special node that evaluates via evaluate_special():
  if line.len >= 0:   return Expr.int(line.len)
  if pretendmax:      return Expr.int(line.maxlen)  [worst-case estimate]
  otherwise:          return None                    [still unknown]

When pretendmax=True, all addresses can be calculated conservatively, allowing
pass 4 to force-resolve instructions even when some preceding sizes are still
being determined.


### Pragma Notes

Key pragmas affecting 6809 book programs:

  PRAGMA_6809              6809 mode (default); disables 6309 instructions
  PRAGMA_AUTOBRANCHLENGTH  auto-promote short branches to long if needed
  PRAGMA_FORWARDREFMAX     force worst-case size for all forward refs in pass 1
  PRAGMA_PCASPCR           treat ,PC as ,PCR (not fixed offset)


---

## instab.py — Instruction Table (DONE)

Translation of instab.c (836 lines C).

Python dict INSTAB: mnemonic → {mode: opcode, 'parse': class_string}

Mode keys: 'imm', 'dir', 'idx', 'ext', 'inh', 'rel'
  None = mode not supported
  int  = opcode (>= 0x1000 means prefixed: 0x10__ or 0x11__)

Parse classes: inh, gen8, gen16, gen0, rel8, rel16, relgen,
               rtor, rlist, imm8, leax, mem

139 instructions verified against the C table.


---

## Indexed Addressing (insn_indexed.c)

The most complex part of the assembler — 834 lines of C.

Postbyte encoding:
  ,R           → 0x84|(R<<5)           zero offset
  n,R (5-bit)  → (n&0x1F)|(R<<5)      5-bit signed, no indirect
  n,R (8-bit)  → 0x88|(R<<5), n       8-bit signed
  n,R (16-bit) → 0x89|(R<<5), hi, lo  16-bit
  ,R+          → 0x80|(R<<5)          post-inc by 1
  ,R++         → 0x81|(R<<5)          post-inc by 2
  ,-R          → 0x82|(R<<5)          pre-dec by 1
  ,--R         → 0x83|(R<<5)          pre-dec by 2
  A,R          → 0x86|(R<<5)          accumulator A offset
  B,R          → 0x85|(R<<5)          accumulator B offset
  D,R          → 0x8B|(R<<5)          accumulator D offset
  n,PC (8)     → 0x8C, n             PC-relative 8-bit
  n,PC (16)    → 0x8D, hi, lo        PC-relative 16-bit
  n,PCR        → same as n,PC (lwasm treats PCR == PC for 6809)
  [addr]       → 0x9F, hi, lo        extended indirect

Indirect bit: OR postbyte with 0x10 (except 5-bit which has no indirect form)

Register bits in postbyte [6:5]: X=00, Y=01, U=10, S=11


---

## Output Formats

DECB (Color BASIC LOADM format):
  Per segment: 0x00, len_hi, len_lo, load_hi, load_lo, <bytes>
  Postamble:   0xFF, 0x00, 0x00, exec_hi, exec_lo

OS-9 module format:
  Module header from MOD directive
  CRC-24 appended by EMOD

Raw: bytes only, no headers
SREC / IHEX: Motorola S-record / Intel hex (output.c)


---

## Verification Strategy

The baseline test for any correct assembler is byte-for-byte agreement with
the reference tool on every valid input it can process.

For the lwasm translation, verification is:
  1. Assemble with real lwasm (compiled from source) → reference binary
  2. Assemble with Python translation → test binary
  3. Diff byte-for-byte → must match exactly

Current verified programs:
  GUESS.ASM (30 bytes)    PASS — byte-perfect vs lwasm 4.24
  HELLO.ASM (78 bytes)    PASS — byte-perfect vs lwasm 4.24

These were verified against the stub lwasm.py (a reimplementation, not a
translation).  As the proper translation is built, each program will be
reverified against it.  The stub will be retired once the translation covers
the same feature set.


---

## Implementation Status

  lw_expr.py      DONE   841 lines — full translation of lwlib/lw_expr.c
  instab.py       DONE   259 lines — instruction table, 139 instructions
  lwasm.py        STUB   Current file is a reimplementation, not a translation.
                         Produces correct output for GUESS.ASM and HELLO.ASM.
                         Does NOT implement the six-pass architecture.
                         Will be replaced by the proper translation.
  decb.py         DONE   Not part of lwasm; replaces toolshed decb/dskini.
  basic.py        TODO
  crc.py          TODO

**Next step: lwasm.py — start with lwasm.h data structures (Line, AsmState,
SymTabEntry), then symbol.c, then lwasm.c helpers, then pass1.c.**
