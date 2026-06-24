"""
cocotools/lwasm_core.py — Line, AsmState, and core assembler helpers
Faithful Python translation of lwasm/symbol.c and lwasm/lwasm.c
(William Astle, LWTools, GPL v3)
Source: http://lwtools.projects.l-w.ca/

Corresponds to:
    lwasm/lwasm.h      — struct line_s, struct asmstate_s
    lwasm/symbol.c     — register_symbol(), lookup_symbol()
    lwasm/lwasm.c      — evaluate_var/special, emit, parse_term, reduce, etc.

C → Python mapping notes:
    char **p             → Ptr object (from lw_expr.py); advance() = (*p)++
    lw_alloc / lw_free   → garbage collection; no-op in Python
    void *priv           → self (AsmState is always the priv pointer)
    unsigned char[]      → bytearray
    strcasecmp(a, b)     → a.casefold() vs b.casefold()
    strcmp(a, b)         → a == b  (exact match)
    strchr(set, c)       → c in set
    toupper(c)           → c.upper()
    isalpha/isdigit      → str.isalpha() / str.isdigit()
    CURPRAGMA(l, p)      → curpragma(cl, p)   [module-level helper]
    OPLEN(op)            → 2 if op > 0xFF else 1
"""

import sys

from .lw_expr  import (Expr, ExprContext, Ptr,
                       TYPE_INT, TYPE_VAR, TYPE_OPER, TYPE_SPECIAL,
                       OPER_PLUS, OPER_MINUS, OPER_TIMES, OPER_DIVIDE,
                       OPER_BWAND, OPER_BWOR,
                       parse_expr as lw_parse_expr,
                       parse_expr_compact as lw_parse_expr_compact)

from .lwasm_types import (
    # special node types
    lwasm_expr_linelen, lwasm_expr_lineaddr, lwasm_expr_nextbp,
    lwasm_expr_prevbp,  lwasm_expr_syment,   lwasm_expr_import,
    lwasm_expr_secbase, lwasm_expr_linedaddr, lwasm_expr_linedlen,
    lwasm_expr_lineaddrraw,
    # output formats
    OUTPUT_OBJ, OUTPUT_LWMOD,
    # pragma bits
    PRAGMA_NONE, PRAGMA_6809,
    PRAGMA_NOOUTPUT, PRAGMA_NEWSOURCE, PRAGMA_SYMBOLNOCASE,
    PRAGMA_DOLLARNOTLOCAL, PRAGMA_UNDEFEXTERN, PRAGMA_NOLIST,
    PRAGMA_EXPORT, PRAGMA_CONDUNDEFZERO, PRAGMA_M80EXT,
    PRAGMA_TESTMODE,
    # error codes
    E_DIV0, E_SYMBOL_BAD, E_SYMBOL_DUPE, E_SYMBOL_UNDEFINED,
    E_INSTRUCTION_SECTION, E_CONDITION_P1, E_EXPRESSION_BAD,
    E_COMPLEX_INCOMPLETE, E_OPERAND_BAD, E_EXPRESSION_NOT_RESOLVED,
    W_OPERAND_SIZE,
    # symbol flags
    symbol_flag_set, symbol_flag_nocheck, symbol_flag_nolist,
    symbol_flag_nocase, symbol_flag_none,
    # section flags
    section_flag_constant,
    # character sets
    SSYMCHARS, SYMCHARS,
    # data classes
    LwasmError, LineExpr, SymTabEntry, SymTab, SectionTab, RelocTab,
    ExportListEntry, ImportListEntry,
    # lookup
    lwasm_lookup_error,
    # test flags
    TF_EMIT, TF_ERROR,
)


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────

def curpragma(cl, pragma):
    """
    CURPRAGMA(l, p) macro: True if line exists and has pragma bit set.
    C: (((l) && ((l)->pragmas & (p))) ? 1 : 0)
    """
    return bool(cl and (cl.pragmas & pragma))


def oplen(opc):
    """OPLEN(op): 2 if prefixed opcode (> 0xFF), else 1."""
    return 2 if opc > 0xFF else 1


# ─────────────────────────────────────────────────────────────────────────────
# Line  (struct line_s from lwasm.h)
# ─────────────────────────────────────────────────────────────────────────────

class Line:
    """
    struct line_s — one parsed source line.

    Key fields:
        addr     Expr   assembly address (expression tree, not integer)
        len      int    size in bytes; -1 = unknown
        insn     int    index into instab; -1 = not an instruction
        sym      str    label on this line (or None)
        output   bytearray  emitted bytes (filled by emit())
        exprs    LineExpr   linked list of saved expressions
        pb       int    pass-forward post byte
        lint     int    pass-forward integer
        lint2    int    pass-forward integer 2
        prev/next       doubly-linked list of all lines
    """

    __slots__ = (
        'addr',    'daddr',   'phase',
        'len',     'dlen',    'minlen',  'maxlen',
        'insn',    'symset',  'sym',
        'output',  'outputl', 'outputbl',
        'dpval',
        'cycle_base', 'cycle_adj', 'cycle_flags',
        'genmode', 'fcc_extras',
        'err',     'warn',    'err_testmode',
        'prev',    'next',
        'inmod',   'csect',
        'exprs',
        'lstr',
        'pb',      'lint',    'lint2',
        'conditional_return',
        'as_',                      # pointer back to AsmState (C: as)
        'pragmas', 'context',
        'ltext',   'linespec', 'lineno',
        'soff',    'dshow',   'dsize',
        'isbrpt',  'dptr',
        'noexpand_start', 'noexpand_end',
        'hideline', 'hidecond',
    )

    def __init__(self, as_):
        # Expression-tree addresses
        self.addr   = None      # lw_expr_t — set by pass1
        self.daddr  = None      # lw_expr_t — OS-9 data address
        self.phase  = None      # lw_expr_t — PHASE override

        # Sizes (-1 = unknown)
        self.len    = -1
        self.dlen   = -1
        self.minlen = 0
        self.maxlen = 0

        # Instruction
        self.insn   = -1        # index in instab; -1 = not an instruction
        self.symset = 0         # set if label was consumed by instruction
        self.sym    = None      # label string or None

        # Output bytes
        self.output  = bytearray()
        self.outputl = -1       # -1 until first emit(); then 0+
        self.outputbl = 0       # allocated size (not needed in Python)

        # Assembler context
        self.dpval  = 0         # direct page value at this line

        # Cycle counting
        self.cycle_base  = 0
        self.cycle_adj   = 0
        self.cycle_flags = 0

        # Pass-forward state (parse → resolve → emit)
        self.genmode          = 0
        self.fcc_extras       = 0
        self.pb               = 0   # post byte
        self.lint             = 0   # pass-forward integer
        self.lint2            = 0   # pass-forward integer 2
        self.lstr             = None
        self.conditional_return = 0

        # Error lists (linked)
        self.err           = None
        self.warn          = None
        self.err_testmode  = 0

        # Linked list
        self.prev = None
        self.next = None

        # Module/section
        self.inmod = 0
        self.csect = None

        # Saved expressions (linked list of LineExpr)
        self.exprs = None

        # Back pointer to assembler state
        self.as_ = as_

        # Pragmas and context in effect at this line
        self.pragmas = as_.pragmas if as_ else 0
        self.context = as_.context if as_ else 0

        # Source info
        self.ltext    = ''      # source text of the line
        self.linespec = ''      # file:line spec
        self.lineno   = 0

        # Listing
        self.soff    = 0
        self.dshow   = 0
        self.dsize   = 0
        self.dptr    = None
        self.isbrpt  = 0
        self.noexpand_start = 0
        self.noexpand_end   = 0
        self.hideline = 0
        self.hidecond = 0

    # ── lwasm_emit(line_t *cl, int byte) ─────────────────────────────────────

    def emit(self, byte):
        """
        lwasm_emit(cl, byte):
        Append one byte to the output buffer.
        If inside an OS-9 module, also update the CRC-24 accumulator.
        """
        as_ = self.as_

        if curpragma(self, PRAGMA_NOOUTPUT):
            return
        if as_.output_format == OUTPUT_OBJ and self.csect is None:
            as_.register_error(self, E_INSTRUCTION_SECTION)
            return

        if self.outputl < 0:
            self.outputl = 0

        self.output.append(byte & 0xFF)
        self.outputl += 1

        if self.inmod:
            # OS-9 CRC-24 update
            # Direct transliteration from the nitros9 asm source via C
            b = byte & 0xFF
            crc = as_.crc

            b       ^= crc[0]
            crc[0]   = crc[1]
            crc[1]   = crc[2]
            crc[1]   = (crc[1] ^ (b >> 7)) & 0xFF
            crc[2]   = (b << 1) & 0xFF
            crc[1]   = (crc[1] ^ (b >> 2)) & 0xFF
            crc[2]   = (crc[2] ^ (b << 6)) & 0xFF
            b        = (b ^ (b << 1)) & 0xFF
            b        = (b ^ (b << 2)) & 0xFF
            b        = (b ^ (b << 4)) & 0xFF
            if b & 0x80:
                crc[0] = (crc[0] ^ 0x80) & 0xFF
                crc[2] = (crc[2] ^ 0x21) & 0xFF

    # ── lwasm_emitop(line_t *cl, int opc) ────────────────────────────────────

    def emitop(self, opc):
        """
        lwasm_emitop(cl, opc):
        Emit 1 or 2 bytes for an opcode; update cycle count on first call.
        """
        if self.cycle_base == 0:
            self.as_.cycle_update_count(self, opc)
        if opc > 0x100:
            self.emit(opc >> 8)
        self.emit(opc)

    # ── lwasm_save_expr(line_t *cl, int id, lw_expr_t expr) ──────────────────

    def save_expr(self, id_, expr):
        """
        lwasm_save_expr(cl, id, expr):
        Save (or replace) a named expression on this line.
        """
        e = self.exprs
        while e:
            if e.id == id_:
                e.expr = expr
                return
            e = e.next
        # Not found — prepend new entry
        ne       = LineExpr(id_, expr)
        ne.next  = self.exprs
        self.exprs = ne

    # ── lwasm_fetch_expr(line_t *cl, int id) → lw_expr_t ─────────────────────

    def fetch_expr(self, id_):
        """
        lwasm_fetch_expr(cl, id):
        Retrieve a saved expression by id, or None if not found.
        """
        e = self.exprs
        while e:
            if e.id == id_:
                return e.expr
            e = e.next
        return None

    # ── lwasm_emitexpr(line_t *l, lw_expr_t expr, int size) → int ────────────

    def emitexpr(self, expr, size):
        """
        lwasm_emitexpr(l, expr, size):
        Emit 1, 2, or 4 bytes from a (hopefully resolved) expression.
        For OBJ and LWMOD targets, creates relocation entries for
        unresolved expressions.  Returns 0 on success, -1 on error.
        """
        as_ = self.as_
        ol   = max(0, self.outputl)

        if expr.istype(TYPE_INT):
            v = expr.intval()
        else:
            # Unresolved expression: handle OBJ / LWMOD targets
            if as_.output_format == OUTPUT_LWMOD:
                return self._emitexpr_lwmod(expr, size, ol)
            elif as_.output_format == OUTPUT_OBJ:
                return self._emitexpr_obj(expr, size, ol)
            else:
                as_.register_error(self, E_EXPRESSION_NOT_RESOLVED)
                return -1

        # Emit bytes big-endian
        if size >= 4:
            self.emit(v >> 24)
            self.emit(v >> 16)
        if size >= 2:
            self.emit(v >> 8)
        self.emit(v)
        return 0

    def _emitexpr_lwmod(self, expr, size, ol):
        """Helper: emitexpr for OUTPUT_LWMOD target."""
        as_ = self.as_
        if self.csect is None:
            as_.register_error(self, E_INSTRUCTION_SECTION)
            return -1
        if size != 2:
            as_.register_error(self, E_OPERAND_BAD)
            return -1

        ad = {'v': 0, 'oc': 0, 'ms': 0}

        def _aux(e):
            if e.istype(TYPE_INT):
                ad['v'] = e.intval(); return 0
            if e.istype(TYPE_SPECIAL):
                if e.specint() == lwasm_expr_secbase:
                    s = e.specptr()
                    if s.name == 'main':
                        ad['ms'] = 1; return 0
                    if s.name == 'bss':
                        return 0
                    return -1
                return -1
            if e.whichop() == OPER_PLUS:
                if ad['oc']: return -1
                ad['oc'] = 1; return 0
            return -1

        v = expr.whichop()
        if v == -1:
            ad['v'] = 0
            if expr.testterms(_aux):
                as_.register_error(self, E_COMPLEX_INCOMPLETE); return -1
            v = ad['v']
        elif v == OPER_PLUS:
            ad['v'] = 0
            if expr.operand_count() > 2:
                as_.register_error(self, E_COMPLEX_INCOMPLETE); return -1
            if expr.testterms(_aux):
                as_.register_error(self, E_COMPLEX_INCOMPLETE); return -1
            v = ad['v']
        else:
            as_.register_error(self, E_COMPLEX_INCOMPLETE); return -1

        # Build relocation entry
        re         = RelocTab(None, size, None)
        re.next    = self.csect.reloctab
        self.csect.reloctab = re
        te = Expr.int(ol)
        re.offset  = Expr.oper(OPER_PLUS, self.addr, te)
        as_.reduce_expr(re.offset)
        re.expr    = Expr.copy(expr) if ad['ms'] == 1 else None

        self.emit(v >> 8); self.emit(v & 0xFF)
        return 0

    def _emitexpr_obj(self, expr, size, ol):
        """Helper: emitexpr for OUTPUT_OBJ target."""
        as_ = self.as_
        if self.csect is None:
            as_.register_error(self, E_INSTRUCTION_SECTION); return -1

        if size == 4:
            # Split into two 16-bit references
            te  = Expr.int(0x10000)
            te2 = Expr.oper(OPER_DIVIDE, expr, te)
            re  = RelocTab(None, 2, te2)
            re.next = self.csect.reloctab
            self.csect.reloctab = re
            te  = Expr.int(ol)
            re.offset = Expr.oper(OPER_PLUS, self.addr, te)
            as_.reduce_expr(re.offset)

            te  = Expr.int(0xFFFF)
            te2 = Expr.oper(OPER_BWAND, expr, te)
            re  = RelocTab(None, 2, te2)
            re.next = self.csect.reloctab
            self.csect.reloctab = re
            te  = Expr.int(ol + 2)
            re.offset = Expr.oper(OPER_PLUS, self.addr, te)
            as_.reduce_expr(re.offset)
        else:
            re  = RelocTab(None, size, Expr.copy(expr))
            re.next = self.csect.reloctab
            self.csect.reloctab = re
            te  = Expr.int(ol)
            re.offset = Expr.oper(OPER_PLUS, self.addr, te)
            as_.reduce_expr(re.offset)

        for _ in range(size):
            self.emit(0)
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# AsmState  (struct asmstate_s from lwasm.h)
# ─────────────────────────────────────────────────────────────────────────────

class AsmState:
    """
    struct asmstate_s — global assembler state.

    Also implements:
        symbol.c    — register_symbol(), lookup_symbol()
        lwasm.c     — evaluate_var(), evaluate_special(), parse_term(),
                      emit helpers, reduce_expr(), etc.
    """

    def __init__(self, output_format=0):
        # Output
        self.output_format = output_format
        self.output_file   = None
        self.list_file     = None
        self.symbol_dump_file = None
        self.map_file      = None

        # Flags and pragmas
        self.flags         = 0
        self.pragmas       = PRAGMA_6809  # default to 6809 mode
        self.nowarn_flags  = 0

        # Error tracking
        self.errorcount          = 0
        self.warningcount        = 0
        self.testmode_errorcount = 0

        # Macro / struct state
        self.inmacro   = 0
        self.instruct  = 0

        # Conditional assembly
        self.skipcond  = 0
        self.skipcount = 0
        self.skipmacro = 0

        # END directive
        self.endseen       = 0
        self.execaddr      = 0
        self.execaddr_expr = None

        # OS-9 module
        self.inmod     = 0
        self.crc       = bytearray(3)

        # Cycle counting
        self.cycle_total = 0

        # Error on undefined symbol (set in pass 2+)
        self.badsymerr = 0

        # Pretend max size for addresses during forced resolution
        self.pretendmax = 0

        # Undefined → zero for conditionals
        self.undefzero = 0

        # Expression width (0 = 16-bit default)
        self.exprwidth = 0

        # Line list (doubly linked)
        self.line_head = None
        self.line_tail = None
        self.cl        = None   # current line pointer

        # Section table
        self.csect    = None
        self.sections = None

        # Symbol table
        self.symtab  = SymTab()
        self.context = 0
        self.nextcontext = 0

        # Macro table
        self.macros = None

        # Export / import lists
        self.exportlist = None
        self.importlist = None
        self.exportcheck = 0

        # Struct table
        self.structs   = None
        self.cstruct   = None
        self.savedaddr = None

        # Input / include
        self.input_files  = []   # list of str (replaces lw_stringlist_t)
        self.input_data   = None
        self.include_list = []
        self.file_dir     = []   # stack of str
        self.includelist  = []
        self.stringvars   = {}   # dict str→str (replaces lw_dict_t)
        self.fileerr      = 0
        self.listnofile   = 0
        self.tabwidth     = 0
        self.debug_level  = 0
        self.debug_file   = sys.stderr

        # Pass number
        self.passno    = 0
        self.preprocess = 0

        # Set up the expression context pointing back to this state
        self._setup_expr_context()

    # ── Expression context ────────────────────────────────────────────────────

    def _setup_expr_context(self):
        """
        Wire up the lw_expr callback hooks.
        In C these are global function pointers set once in main.c:
            lw_expr_set_special_handler(lwasm_evaluate_special)
            lw_expr_set_var_handler(lwasm_evaluate_var)
            lw_expr_set_term_parser(lwasm_parse_term)
        In Python they are methods on the AsmState instance.
        """
        ctx = ExprContext()
        ctx.evaluate_special = self._evaluate_special
        ctx.evaluate_var     = self._evaluate_var
        ctx.parse_term       = self._parse_term
        ctx.divzero          = self._dividezero
        self.expr_ctx        = ctx

    # ── lwasm_dividezero ──────────────────────────────────────────────────────

    def _dividezero(self):
        """lwasm_dividezero: register a division-by-zero error on current line."""
        self.register_error(self.cl, E_DIV0)

    # ── lwasm_evaluate_var(char *var, void *priv) → lw_expr_t ────────────────

    def _evaluate_var(self, var):
        """
        lwasm_evaluate_var(var, priv):
        Called by lw_expr_simplify when a TYPE_VAR node needs resolution.
        Returns an Expr or None.
        """
        s = self.lookup_symbol(self.cl, var)
        if s:
            return Expr.special(lwasm_expr_syment, s)

        if self.undefzero:
            return Expr.int(0)

        # For non-OBJ targets, undefined is undefined
        if self.output_format != OUTPUT_OBJ:
            if self.badsymerr:
                self.register_error2(self.cl, E_SYMBOL_UNDEFINED, '%s', var)
            return None

        # OBJ target: check import list
        im = self.importlist
        while im:
            if im.symbol == var:
                break
            im = im.next

        # PRAGMA_UNDEFEXTERN: auto-import undefined symbols
        if (self.passno != 0) and (im is None) and curpragma(self.cl, PRAGMA_UNDEFEXTERN):
            im       = ImportListEntry(var)
            im.next  = self.importlist
            self.importlist = im

        if im is None:
            if self.badsymerr:
                self.register_error2(self.cl, E_SYMBOL_UNDEFINED, '%s', var)
            return None

        return Expr.special(lwasm_expr_import, im)

    # ── lwasm_evaluate_special(int t, void *ptr, void *priv) → lw_expr_t ─────

    def _evaluate_special(self, t, ptr):
        """
        lwasm_evaluate_special(t, ptr, priv):
        Called by lw_expr_simplify when a TYPE_SPECIAL node needs resolution.
        Returns an Expr or None.
        """
        if t == lwasm_expr_secbase:
            s = ptr   # SectionTab
            if s.tbase != -1:
                return Expr.int(s.tbase)
            if self.exportcheck and ptr is self.csect:
                return Expr.int(0)
            if s.flags & section_flag_constant:
                return Expr.int(0)
            return None

        if t == lwasm_expr_linedlen:
            cl = ptr
            if cl.dlen == -1:
                return None
            return Expr.int(cl.dlen)

        if t == lwasm_expr_linelen:
            cl = ptr
            if cl.len != -1:
                return Expr.int(cl.len)
            if cl.as_.pretendmax:
                if cl.maxlen != 0:
                    return Expr.int(cl.maxlen)
            return None

        if t == lwasm_expr_linedaddr:
            cl = ptr
            return Expr.copy(cl.daddr) if cl.daddr else None

        if t == lwasm_expr_lineaddrraw:
            cl = ptr
            return Expr.copy(cl.addr) if cl.addr else None

        if t == lwasm_expr_lineaddr:
            cl = ptr
            if cl.phase:
                return Expr.copy(cl.phase)
            if cl.addr:
                return Expr.copy(cl.addr)
            return None

        if t == lwasm_expr_syment:
            sym = ptr   # SymTabEntry
            return Expr.copy(sym.value)

        if t == lwasm_expr_import:
            return None   # imports remain unresolved in Python too

        if t == lwasm_expr_nextbp:
            cl = ptr
            cl = cl.next
            while cl:
                if cl.isbrpt:
                    break
                cl = cl.next
            if cl:
                return Expr.copy(cl.addr)
            return None

        if t == lwasm_expr_prevbp:
            cl = ptr
            cl = cl.prev
            while cl:
                if cl.isbrpt:
                    break
                cl = cl.prev
            if cl:
                return Expr.copy(cl.addr)
            return None

        return None

    # ── lwasm_parse_term(char **p, void *priv) → lw_expr_t ───────────────────

    def _parse_term(self, p, ctx):
        """
        lwasm_parse_term(p, priv):
        Parse one atomic term from source input at Ptr p.
        Returns an Expr or None; advances p past the consumed input.

        Handles: . * < > "AB" 'A &dec %bin 0bbin $hex 0xhex @oct
                 symbols, numeric constants with suffix notation
        """
        cl = self.cl
        c  = p.peek()

        if not c or c == '\0':
            return None

        # '.' — current data address (unless followed by alpha/digit)
        if c == '.':
            nxt = p.s[p.pos+1] if p.pos+1 < len(p.s) else ''
            if not (nxt.isalpha() or nxt.isdigit()):
                p.advance()
                return Expr.special(lwasm_expr_linedaddr, cl)

        # '*' — current line address
        if c == '*':
            p.advance()
            return Expr.special(lwasm_expr_lineaddr, cl)

        # '<' — previous branch point
        if c == '<':
            p.advance()
            return Expr.special(lwasm_expr_prevbp, cl)

        # '>' — next branch point
        if c == '>':
            p.advance()
            return Expr.special(lwasm_expr_nextbp, cl)

        # '"AB" — 16-bit double-ASCII constant (or M80EXT single-quote variant)
        if c == '"':
            p.advance()
            if p.at_end() or p.pos + 1 >= len(p.s):
                return None
            v = (ord(p.s[p.pos]) << 8) | ord(p.s[p.pos+1])
            p.advance(2)
            if p.peek() == '"':
                p.advance()
            return Expr.int(v)

        # PRAGMA_M80EXT: double-char constant in 16-bit context
        if curpragma(cl, PRAGMA_M80EXT):
            if c in ('"', "'") and cl.genmode == 16:
                p.advance()
                if p.at_end() or p.pos + 1 >= len(p.s):
                    return None
                v = (ord(p.s[p.pos]) << 8) | ord(p.s[p.pos+1])
                p.advance(2)
                if p.peek() in ('"', "'"):
                    p.advance()
                return Expr.int(v)

        # "'" — single-ASCII constant
        if c == "'":
            p.advance()
            if p.at_end():
                return None
            v = ord(p.peek())
            p.advance()
            if p.peek() == "'":
                p.advance()
            return Expr.int(v)

        # '&' — decimal constant (with optional minus)
        if c == '&':
            p.advance()
            neg = 1
            if p.peek() == '-':
                p.advance(); neg = -1
            if not p.peek() or p.peek() not in '0123456789':
                p.advance(-1)
                if neg < 0: p.advance(-1)
                return None
            val = 0
            while p.peek() and p.peek() in '0123456789':
                val = val * 10 + int(p.peek()); p.advance()
            return Expr.int(val * neg)

        # '%' — binary constant
        if c == '%':
            p.advance()
            neg = 1
            if p.peek() == '-':
                p.advance(); neg = -1
            if p.peek() not in '01':
                p.advance(-1)
                if neg < 0: p.advance(-1)
                return None
            val = 0
            while p.peek() in '01':
                val = val * 2 + int(p.peek()); p.advance()
            return Expr.int(val * neg)

        # '0b' / '0B' — C-style binary
        if c == '0' and p.pos+1 < len(p.s) and p.s[p.pos+1].lower() == 'b':
            p.advance(2)
            if p.peek() not in '01':
                return Expr.int(0)
            val = 0
            while p.peek() in '01':
                val = val * 2 + int(p.peek()); p.advance()
            return Expr.int(val)

        # '$' — hexadecimal
        if c == '$':
            p.advance()
            neg = 1
            if p.peek() == '-':
                p.advance(); neg = -1
            HEXDIGITS = '0123456789abcdefABCDEF'
            if not p.peek() or p.peek() not in HEXDIGITS:
                p.advance(-1)
                if neg < 0: p.advance(-1)
                return None
            val = 0
            while p.peek() and p.peek() in HEXDIGITS:
                d = ord(p.peek().upper()) - ord('0')
                if d > 9: d -= 7
                val = val * 16 + d
                p.advance()
            return Expr.int(val * neg)

        # '0x' / '0X' — C-style hex
        if c == '0' and p.pos+1 < len(p.s) and p.s[p.pos+1].lower() == 'x':
            p.advance(2)
            HEXDIGITS = '0123456789abcdefABCDEF'
            if not p.peek() or p.peek() not in HEXDIGITS:
                p.advance(-2); return None
            val = 0
            while p.peek() and p.peek() in HEXDIGITS:
                d = ord(p.peek().upper()) - ord('0')
                if d > 9: d -= 7
                val = val * 16 + d
                p.advance()
            return Expr.int(val)

        # '@' + octal digit — octal constant
        if c == '@' and p.pos+1 < len(p.s) and p.s[p.pos+1] in '01234567':
            p.advance()
            neg = 1
            if p.peek() == '-':
                p.advance(); neg = -1
            if not p.peek() or p.peek() not in '01234567':
                p.advance(-1)
                if neg < 0: p.advance(-1)
                return None
            val = 0
            while p.peek() and p.peek() in '01234567':
                val = val * 8 + (ord(p.peek()) - ord('0'))
                p.advance()
            return Expr.int(val * neg)

        # Symbol or numeric (including suffix notation: 1234H, 1010B, etc.)
        # First, check for a symbol
        SYMCH = SYMCHARS
        havedol = False
        l = 0
        while p.pos + l < len(p.s) and p.s[p.pos+l] in SYMCH:
            if p.s[p.pos+l] == '$':
                havedol = True
            l += 1
        if l == 0:
            return None

        # Struct field extension: {...}
        ep = p.pos + l
        if ep < len(p.s) and p.s[ep] == '{':
            while ep < len(p.s) and p.s[ep] != '}':
                ep += 1
            if ep < len(p.s):
                ep += 1
            l = ep - p.pos

        first_ch = p.s[p.pos]
        if havedol or not first_ch.isdigit():
            # It's a symbol
            sym = p.s[p.pos:p.pos+l]
            p.advance(l)
            return Expr.var(sym)

        # Numeric with possible suffix (hex H, octal Q/O, binary B, decimal default)
        decval = 0; binval = 0; hexval = 0; octval = 0
        valtype = 15   # bitmask: 1=bin 2=oct 4=dec 8=hex
        bindone = False

        while True:
            ALLDIGITS = '0123456789ABCDEFabcdefqhoQHO'
            c2 = p.peek()
            if not c2 or c2 not in ALLDIGITS:
                if bindone:
                    val = binval; break
                elif valtype & 4:
                    val = decval; break
                else:
                    return None

            dval = c2.upper()
            p.advance()

            if bindone:
                bindone = False
                valtype &= 14   # can no longer be binary

            if dval in ('Q', 'O'):
                if valtype & 2:
                    val = octval; valtype = -1; break
                else:
                    return None
            elif dval == 'H':
                if valtype & 8:
                    val = hexval; valtype = -1; break
                else:
                    return None
            elif dval == 'B':
                if valtype & 1:
                    bindone = True
                    valtype = 9   # could still be binary (suffix) or hex
                # fall through to digit processing
                dval = 'B'

            # Digit
            dv = ord(dval) - ord('0')
            if dv > 9: dv -= 7
            if valtype & 8: hexval = hexval * 16 + dv
            if valtype & 4:
                if dv > 9: valtype &= 11
                else:       decval = decval * 10 + dv
            if valtype & 2:
                if dv > 7: valtype &= 13
                else:       octval = octval * 8 + dv
            if valtype & 1:
                if dv > 1: valtype &= 14
                else:       binval = binval * 2 + dv

            if valtype == -1:
                break
            if valtype == 0:
                return None

            val = decval   # default if we fall out of the loop

        return Expr.int(val)

    # ── lwasm_parse_expr(asmstate_t *as, char **p) → lw_expr_t ───────────────

    def parse_expr(self, p):
        """
        lwasm_parse_expr(as, p):
        Parse a full expression from Ptr p using the compact or normal parser.
        """
        ctx = self.expr_ctx
        if self.exprwidth != 16:
            ctx.expr_width = self.exprwidth
        else:
            ctx.expr_width = 0

        if curpragma(self.cl, PRAGMA_NEWSOURCE):
            e = lw_parse_expr(p, ctx)
        else:
            e = lw_parse_expr_compact(p, ctx)

        ctx.expr_width = 0
        # lwasm_skip_to_next_token: only active under NEWSOURCE
        if curpragma(self.cl, PRAGMA_NEWSOURCE):
            while p.peek() and p.peek().isspace():
                p.advance()
        return e

    # ── lwasm_reduce_expr(asmstate_t *as, lw_expr_t expr) → int ──────────────

    def reduce_expr(self, expr):
        """
        lwasm_reduce_expr(as, expr):
        Simplify expr in place using this state's callbacks.  Returns 0.
        """
        if expr:
            expr.simplify(self.expr_ctx)
        return 0

    # ── lwasm_reduce_line_exprs(line_t *cl) ───────────────────────────────────

    def reduce_line_exprs(self, cl):
        """
        lwasm_reduce_line_exprs(cl):
        Reduce all expressions on a line: addr, daddr, phase, and each
        saved expression.  Then try to resolve instruction length (force=0).
        """
        from .instab import INSTAB   # deferred import to avoid circularity
        self.cl = cl

        self.reduce_expr(cl.addr)
        self.reduce_expr(cl.daddr)
        if cl.phase:
            self.reduce_expr(cl.phase)

        le = cl.exprs
        while le:
            self.reduce_expr(le.expr)
            le = le.next

        if cl.len == -1 or cl.dlen == -1:
            if cl.insn >= 0:
                # Look up the instruction entry and call resolve(force=0)
                # instab entries are dicts with optional 'resolve' callable
                entry = list(INSTAB.values())[cl.insn] if cl.insn < len(INSTAB) else None
                # This will be called properly once instab.py is extended
                # with resolve callbacks.  For now, the hook is in place.

    # ── lwasm_register_error ─────────────────────────────────────────────────

    def register_error(self, cl, code):
        """lwasm_register_error(as, cl, code)"""
        self._register_error_real(cl, code, lwasm_lookup_error(code))

    def register_error2(self, cl, code, fmt, *args):
        """lwasm_register_error2(as, cl, code, fmt, ...)"""
        base = lwasm_lookup_error(code)
        try:
            extra = (fmt % args) if args else fmt
        except Exception:
            extra = fmt
        self._register_error_real(cl, code, f'{base} {extra}')

    def _register_error_real(self, cl, code, msg):
        """lwasm_register_error_real: attach error/warning to line."""
        if not cl:
            return
        # Testmode: suppress expected errors
        if curpragma(cl, PRAGMA_TESTMODE):
            # Full testmode handling deferred to when pseudo.c is translated
            pass
        e         = LwasmError(code, msg)
        if code >= 1000:
            e.next    = cl.warn
            cl.warn   = e
            self.warningcount += 1
        else:
            e.next    = cl.err
            cl.err    = e
            self.errorcount += 1

    # ── lwasm_next_context(asmstate_t *as) → int ─────────────────────────────

    def next_context(self):
        """lwasm_next_context: allocate and return next context number."""
        r = self.nextcontext
        self.nextcontext += 1
        return r

    # ── cycle_update_count ────────────────────────────────────────────────────

    def cycle_update_count(self, cl, opc):
        """
        lwasm_cycle_update_count(cl, opc):
        Placeholder — cycle counting is a minor feature; full translation
        deferred until pass1/insn handlers are in place.
        """
        pass   # cycle count update goes here

    # ── register_symbol (symbol.c: register_symbol) ──────────────────────────

    def register_symbol(self, cl, sym, val, flags=symbol_flag_none):
        """
        register_symbol(as, cl, sym, val, flags) → SymTabEntry | None

        Faithful translation of symbol.c register_symbol().

        Inserts sym into the binary-tree symbol table.  For SET symbols,
        increments the version number and chains the old entry via nextver.
        Returns the new SymTabEntry, or None on error.
        """
        islocal = False
        context = -1
        version = -1

        # Validate symbol name (unless nocheck)
        if not (flags & symbol_flag_nocheck):
            if not sym:
                self.register_error2(cl, E_SYMBOL_BAD, '(%s)', sym or '')
                return None

            first = sym[0]
            if ord(first) < 0x80 and first not in SSYMCHARS:
                # Check if $ or @ appears later (makes it valid start)
                if '$' not in sym[1:] and '@' not in sym[1:] and '?' not in sym[1:]:
                    self.register_error2(cl, E_SYMBOL_BAD, '(%s)', sym)
                    return None

            if (first in ('$', '@')) and len(sym) > 1 and sym[1].isdigit():
                self.register_error2(cl, E_SYMBOL_BAD, '(%s)', sym)
                return None

        # Scan for local marker characters
        for ch in sym:
            if ch in ('@', '?'):
                islocal = True
            if ch == '$' and not curpragma(cl, PRAGMA_DOLLARNOTLOCAL):
                islocal = True
            if not (flags & symbol_flag_nocheck):
                if ord(ch) < 0x80 and ch not in SYMCHARS:
                    self.register_error2(cl, E_SYMBOL_BAD, '(%s)', sym)
                    return None

        if islocal:
            context = cl.context if cl else -1

        # Binary-tree search for existing entry
        se    = self.symtab.head
        sprev = None
        cdir  = 0

        while se:
            ndir = _strcasecmp(sym, se.symbol)
            # For non-SET symbols, enforce exact case unless nocase pragma
            if ndir == 0 and not (se.flags & symbol_flag_set):
                if sym != se.symbol:
                    if not curpragma(cl, PRAGMA_SYMBOLNOCASE) and not (se.flags & symbol_flag_nocase):
                        ndir = 1
            if ndir == 0 and se.context != context:
                ndir = -1 if context < se.context else 1
            if ndir == 0:
                if (flags & symbol_flag_set) and (se.flags & symbol_flag_set):
                    version = se.version
                break
            cdir  = ndir
            sprev = se
            se    = se.left if cdir < 0 else se.right

        if se and version == -1:
            # Multiply defined
            self.register_error2(cl, E_SYMBOL_DUPE, '(%s)', sym)
            return None

        if flags & symbol_flag_set:
            version += 1

        # Simplify the value expression before storing
        self.reduce_expr(val)

        # Build new entry
        nse         = SymTabEntry(sym, Expr.copy(val), context, version, flags,
                                  cl.csect if cl else None)
        nse.symbol  = sym

        if curpragma(cl, PRAGMA_NOLIST):
            nse.flags |= symbol_flag_nolist
        if curpragma(cl, PRAGMA_SYMBOLNOCASE):
            nse.flags |= symbol_flag_nocase
        if not cl and (self.pragmas & PRAGMA_SYMBOLNOCASE):
            nse.flags |= symbol_flag_nocase

        # If replacing a SET symbol: chain old entry and inherit subtree
        if se:
            nse.nextver = se
            nse.left    = se.left
            nse.right   = se.right
            se.left     = None
            se.right    = None

        # Insert into tree
        if not sprev:
            self.symtab.head = nse
        else:
            if cdir < 0:
                sprev.left  = nse
            else:
                sprev.right = nse

        # Auto-export if PRAGMA_EXPORT is set
        if curpragma(cl, PRAGMA_EXPORT) and cl and cl.csect and not islocal:
            e       = ExportListEntry(sym, nse, cl)
            e.next  = self.exportlist
            self.exportlist = e

        return nse

    # ── lookup_symbol (symbol.c: lookup_symbol) ───────────────────────────────

    def lookup_symbol(self, cl, sym):
        """
        lookup_symbol(as, cl, sym) → SymTabEntry | None

        Faithful translation of symbol.c lookup_symbol().

        For SET symbols always returns the last (most recent) version,
        because register_symbol() calls reduce_expr() which converts lingering
        VAR references to direct values.
        """
        local = False

        if '@' in sym or '?' in sym:
            local = True
        if cl and not curpragma(cl, PRAGMA_DOLLARNOTLOCAL) and '$' in sym:
            local = True
        if not cl and not (self.pragmas & PRAGMA_DOLLARNOTLOCAL) and '$' in sym:
            local = True

        # Cannot look up a local symbol without a line context
        if not cl and local:
            return None

        s = self.symtab.head
        while s:
            cdir = _strcasecmp(sym, s.symbol)
            if cdir == 0 and not (s.flags & symbol_flag_nocase):
                if sym != s.symbol:
                    cdir = 1
            if cdir == 0:
                if local and cl and s.context != cl.context:
                    cdir = -1 if cl.context < s.context else 1
            if cdir == 0:
                return s
            s = s.left if cdir < 0 else s.right

        return None

    # ── lookupreg2 / lookupreg3 ───────────────────────────────────────────────

    @staticmethod
    def lookupreg2(regs, p):
        """
        lwasm_lookupreg2(regs, p):
        Match a 2-character register name from the string regs (each entry
        is 2 chars, space = match 1 char).  Returns index, or -1 if not found.
        Advances p past the matched register.
        """
        rval = 0
        i = 0
        while i < len(regs):
            r0 = regs[i]; r1 = regs[i+1]
            c0 = p.peek()
            if c0.upper() == r0.upper():
                c1 = p.s[p.pos+1] if p.pos+1 < len(p.s) else ''
                if r1 == ' ' and not c1.isalpha():
                    p.advance(); return rval
                if c1.upper() == r1.upper():
                    p.advance(2); return rval
            i    += 2
            rval += 1
        return -1

    @staticmethod
    def lookupreg3(regs, p):
        """
        lwasm_lookupreg3(regs, p):
        Match a 3-character register name.  Returns index, or -1.
        """
        rval = 0
        i = 0
        while i < len(regs):
            r0 = regs[i]; r1 = regs[i+1]; r2 = regs[i+2]
            c0 = p.peek()
            c1 = p.s[p.pos+1] if p.pos+1 < len(p.s) else ''
            c2 = p.s[p.pos+2] if p.pos+2 < len(p.s) else ''
            if c0.upper() == r0.upper():
                if r1 == ' ' and not c1.isalpha():
                    p.advance(); return rval
                if c1.upper() == r1.upper():
                    if r2 == ' ' and not c2.isalpha():
                        p.advance(2); return rval
                    if c2.upper() == r2.upper():
                        p.advance(3); return rval
            i    += 3
            rval += 1
        return -1

    # ── show_errors ───────────────────────────────────────────────────────────

    def show_errors(self, file=None):
        """lwasm_show_errors(as): print all errors and warnings to stderr."""
        if file is None:
            file = sys.stderr
        cl = self.line_head
        while cl:
            if cl.err or cl.warn:
                spec = cl.linespec or ''
                # trim 'include:' prefix if present
                if len(spec) > 8 and spec[7] == ':':
                    spec = spec[8:].lstrip()
                e = cl.err
                while e:
                    print(f'{spec}({cl.lineno}) : ERROR : {e.mess}', file=file)
                    e = e.next
                e = cl.warn
                while e:
                    print(f'{spec}({cl.lineno}) : WARNING : {e.mess}', file=file)
                    e = e.next
                print(f'{cl.linespec}:{cl.lineno:05d} {cl.ltext}', file=file)
                print(file=file)
            cl = cl.next


# ─────────────────────────────────────────────────────────────────────────────
# String comparison helpers (C library equivalents)
# ─────────────────────────────────────────────────────────────────────────────

def _strcasecmp(a, b):
    """
    strcasecmp(a, b): case-insensitive comparison.
    Returns negative / 0 / positive like C strcmp.
    """
    al = a.casefold()
    bl = b.casefold()
    if al < bl: return -1
    if al > bl: return  1
    return 0
