# cocotools/lwasm.py — Design Document
# Python faithful translation of lwasm (LWTools assembler)
# Source: http://lwtools.projects.l-w.ca/ (GPL v3, William Astle)
# Target: byte-perfect output compatible with lwasm for 6809/6309 programs
#
# ================================================================
# ARCHITECTURE OVERVIEW
# ================================================================
#
# lwasm is a multi-pass assembler. The C source uses 6 passes:
#
#   Pass 1 (pass1.c): Read and tokenize all source lines.
#                     Parse operands. Build initial symbol table.
#                     Calculate instruction lengths where possible.
#
#   Pass 2 (pass2.c): Resolve forward references where possible.
#
#   Pass 3 (pass3.c): Force resolution of remaining symbols.
#
#   Pass 4 (pass4.c): Re-resolve after forcing.
#
#   Pass 5 (pass5.c): Final length calculation.
#
#   Pass 6 (pass6.c): Emit bytes to output.
#
# For simple programs (no complex forward references, no macros,
# no object file linking), a 2-pass approach suffices:
#
#   Pass 1: Build symbol table, calculate instruction sizes.
#   Pass 2: Emit bytes with resolved symbols.
#
# The Python translation will implement the full 6-pass model
# to ensure compatibility with all valid lwasm source files.
#
# ================================================================
# INSTRUCTION TABLE STRUCTURE (from instab.c/instab.h)
# ================================================================
#
# Each instruction entry has:
#   name    -- mnemonic string (e.g. "LDA", "JSR")
#   ops[4]  -- opcode for each addressing mode:
#              ops[0] = direct page (or only opcode for inherent)
#              ops[1] = indexed
#              ops[2] = extended
#              ops[3] = immediate (for instructions that support it)
#   parse   -- function to parse the operand
#   resolve -- function to resolve forward references
#   emit    -- function to emit bytes
#
# ops[] values use a special encoding:
#   -1      = mode not supported
#   0xXX    = 1-byte opcode (e.g. 0x96 for LDA direct)
#   0x10XX  = 2-byte opcode with 0x10 prefix (e.g. LDS)
#   0x11XX  = 2-byte opcode with 0x11 prefix (e.g. CMPU)
#
# In Python we represent ops as:
#   None    = mode not supported
#   int     = opcode value (may be 16-bit for prefixed opcodes)
#
# ================================================================
# ADDRESSING MODE DETECTION (from insn_gen.c)
# ================================================================
#
# For general instructions (LDA, STA, etc.):
#
#   '<' prefix  -> forced direct page (lint2 = 0)
#   '>' prefix  -> forced extended    (lint2 = 2)
#   '[' prefix  -> indexed indirect   (lint2 = 1)
#   ',' in operand -> indexed         (lint2 = 1)
#   '#' prefix  -> immediate          (lint2 = 3)
#   otherwise   -> auto: direct if addr high byte == DP reg,
#                        extended otherwise
#
# lint2 values: 0=direct, 1=indexed, 2=extended, 3=immediate
#
# ================================================================
# INDEXED ADDRESSING (from insn_indexed.c)
# ================================================================
#
# The most complex part. The indexed postbyte encodes:
#   - Base register (X, Y, U, S, PC)
#   - Offset type (none, 5-bit, 8-bit, 16-bit, PCR)
#   - Indirect flag (bit 4)
#   - Auto-increment/decrement
#
# Postbyte encoding (key cases for the book):
#
#   ,R          -> 0x84 | (R<<5)              no offset
#   n,R (5-bit) -> (n&0x1F) | (R<<5)         5-bit signed offset
#   n,R (8-bit) -> 0x88 | (R<<5), n          8-bit signed offset
#   n,R (16-bit)-> 0x89 | (R<<5), n_hi, n_lo 16-bit offset
#   ,R+         -> 0x80 | (R<<5)              post-increment by 1
#   ,R++        -> 0x81 | (R<<5)              post-increment by 2
#   ,-R         -> 0x82 | (R<<5)              pre-decrement by 1
#   ,--R        -> 0x83 | (R<<5)              pre-decrement by 2
#   n,PC (8-bit)-> 0x8C, n                   PC-relative 8-bit
#   n,PC (16-bit)-> 0x8D, n_hi, n_lo         PC-relative 16-bit
#   n,PCR       -> same as n,PC (lwasm treats PCR == PC)
#
#   Indirect variants: OR postbyte with 0x10
#   [,R]        -> 0x94 | (R<<5)
#   [n,R]       -> 0x98|0x99 | (R<<5) etc.
#
# Register encoding for indexed base:
#   X=0, Y=1, U=2, S=3, PC=4 (but encoding differs -- see below)
#
# Actual register bits in postbyte bits [6:5]:
#   X: 00 (0)
#   Y: 01 (1)  -- note: NOT the register number
#   U: 10 (2)
#   S: 11 (3)
#   PC: special cases (0x8C/0x8D)
#
# ================================================================
# OPCODE TABLE STRUCTURE (Python representation)
# ================================================================
#
# We represent the instruction table as a dict:
#
#   INSTAB = {
#     'LDA': {
#       'imm':  0x86,   # immediate
#       'dir':  0x96,   # direct page
#       'idx':  0xA6,   # indexed
#       'ext':  0xB6,   # extended
#       'parse': 'gen8',  # parser class
#     },
#     'JSR': {
#       'imm':  None,
#       'dir':  0x9D,
#       'idx':  0xAD,
#       'ext':  0xBD,
#       'parse': 'gen0',
#     },
#     ...
#   }
#
# Parser classes:
#   'inh'    -- inherent (no operand)
#   'gen8'   -- general, 8-bit immediate
#   'gen16'  -- general, 16-bit immediate
#   'gen0'   -- general, no immediate mode
#   'rel8'   -- 8-bit relative branch
#   'rel16'  -- 16-bit relative branch (LBRA etc)
#   'relgen' -- auto-size relative branch
#   'rtor'   -- register-to-register (TFR, EXG)
#   'rlist'  -- register list (PSHS, PULS, PSHU, PULU)
#   'imm8'   -- immediate-only (ANDCC, ORCC, CWAI)
#
# ================================================================
# TWO-PASS ALGORITHM (Python implementation)
# ================================================================
#
# Pass 1:
#   for each source line:
#     parse label -> add to symbol table with value = current_addr
#     parse mnemonic -> look up in INSTAB
#     parse operand -> determine addressing mode
#     estimate instruction size -> advance current_addr
#     if size unknown (forward reference in branch) -> mark for pass 2
#
# Pass 2:
#   for each source line:
#     with symbol table complete, resolve all expressions
#     determine final addressing mode (direct vs extended for ambiguous)
#     emit bytes to output buffer
#
# ================================================================
# OUTPUT FORMATS
# ================================================================
#
# DECB (--format=decb):
#   Preamble per segment: 0x00, len_hi, len_lo, addr_hi, addr_lo
#   Code bytes follow
#   Postamble: 0xFF, 0x00, 0x00, exec_hi, exec_lo
#
# OS-9 module (--format=os9):
#   Module header generated from MOD/EMOD directives
#   CRC-24 calculated and appended by EMOD
#
# Raw (--format=raw):
#   Just the bytes, no headers
#
# ================================================================
# DIRECTIVES (pseudo-ops)
# ================================================================
#
# ORG expr      -- set current address
# EQU expr      -- define symbol = expr (no code generated)
# SET expr      -- like EQU but can be redefined
# FCB expr,...  -- form constant byte(s)
# FDB expr,...  -- form constant word(s) (16-bit big-endian)
# FCC "string"  -- form constant characters (no null terminator)
# FCS "string"  -- form constant characters with high bit set on last
# FCN "string"  -- form constant characters with null terminator
# RMB expr      -- reserve memory bytes (no initialization)
# END expr      -- end of source, optional exec address
# INCLUDE file  -- include another source file
# MACRO/ENDM    -- macro definition (implement later)
# IF/ELSE/ENDIF -- conditional assembly (implement later)
# MOD/EMOD      -- OS-9 module header/footer
# OS9 syscall   -- OS-9 system call (SWI2 + syscall byte)
#
# ================================================================
# IMPLEMENTATION PLAN
# ================================================================
#
# Phase 1 -- Core assembler for book programs:
#   [ ] Instruction table (all 6809 instructions, no 6309)
#   [ ] Tokenizer/parser
#   [ ] Symbol table
#   [ ] Pass 1 and Pass 2
#   [ ] Addressing mode detection
#   [ ] Indexed postbyte encoding (including PCR)
#   [ ] Branch instruction encoding (rel8/rel16)
#   [ ] Directives: ORG, EQU, FCB, FDB, FCC, FCS, RMB, END
#   [ ] Output: DECB format
#   [ ] Output: raw binary
#   [ ] Verification: byte-for-byte match against lwasm output
#
# Phase 2 -- OS-9 support:
#   [ ] MOD/EMOD directives
#   [ ] CRC-24 calculation
#   [ ] OS9 syscall directive
#   [ ] Output: OS-9 module format
#   [ ] RMB in data section (separate from code section)
#
# Phase 3 -- Extended features:
#   [ ] MACRO/ENDM
#   [ ] IF/ELSE/ENDIF
#   [ ] INCLUDE
#   [ ] 6309 instructions
#   [ ] Object file format + lwlink equivalent
#
# ================================================================
# VERIFICATION STRATEGY
# ================================================================
#
# For each book program:
#   1. Assemble with lwasm -> reference binary
#   2. Assemble with Python lwasm -> test binary
#   3. Compare byte-for-byte -> must match exactly
#
# Start with GUESS.ASM (30 bytes, simple program)
# Then HELLO.ASM (80 bytes, more complex)
# Then SuperComm/dir (real-world programs)
#
# ================================================================
# FILES IN cocotools PACKAGE
# ================================================================
#
#   cocotools/
#     __init__.py
#     lwasm.py        -- assembler (this design)
#     decb.py         -- DSK builder (already written, needs cleanup)
#     basic.py        -- BASIC tokenizer
#     crc.py          -- CRC-24 for OS-9 modules
#   cocotools.py      -- CLI entry point
#     usage: python cocotools.py assemble GUESS.ASM -o GUESS.BIN
#            python cocotools.py makedsk GUESS.DSK GUESS.BIN GUESS.BAS
#            python cocotools.py tokenize GUESS.BAS
