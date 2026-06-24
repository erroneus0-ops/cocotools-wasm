"""
cocotools/lw_expr.py -- Expression Tree System
Faithful Python translation of lwlib/lw_expr.c (William Astle, LWTools, GPL v3)
Source: http://lwtools.projects.l-w.ca/

This module is the foundation for the assembler.  Everything that can be
unknown at parse time -- symbol values, line addresses, instruction sizes,
operands -- is represented as an expression tree (Expr) rather than a bare
integer.  Trees are simplified in place across multiple passes as information
becomes available; when a tree reduces to a single integer node, the value
is fully resolved.

Key design notes (C -> Python mapping):

  lw_expr_t / struct lw_expr_priv  ->  Expr class
  lw_expr_build(type, ...)         ->  Expr.int(), Expr.var(), Expr.oper(), Expr.special()
  lw_expr_copy()                   ->  Expr.copy()
  lw_expr_destroy()                ->  (garbage collected)
  lw_expr_compare()                ->  Expr.__eq__()
  lw_expr_simplify()               ->  Expr.simplify(ctx)
  lw_expr_parse / _compact         ->  parse_expr() / parse_expr_compact()
  *E = *te  (in-place overwrite)   ->  Expr._become(other)
  char **p  (mutable pointer)      ->  Ptr class

  static globals (evaluate_special, evaluate_var, parse_term, level, bailing,
  parse_compact, divzero, expr_width) -> ExprContext instance fields
"""

# ---------------------------------------------------------------------------
# Expression node type constants
# (matches enum in lw_expr.h)
# ---------------------------------------------------------------------------

TYPE_INT     = 0    # lw_expr_type_int     -- resolved integer
TYPE_VAR     = 1    # lw_expr_type_var     -- symbol name (string)
TYPE_OPER    = 2    # lw_expr_type_oper    -- operator node
TYPE_SPECIAL = 3    # lw_expr_type_special -- assembler special reference

# ---------------------------------------------------------------------------
# Operator constants
# (matches enum in lw_expr.h, operator values 1..20)
# ---------------------------------------------------------------------------

OPER_PLUS   = 1     # lw_expr_oper_plus
OPER_MINUS  = 2     # lw_expr_oper_minus
OPER_TIMES  = 3     # lw_expr_oper_times
OPER_DIVIDE = 4     # lw_expr_oper_divide
OPER_MOD    = 5     # lw_expr_oper_mod
OPER_INTDIV = 6     # lw_expr_oper_intdiv   (\\ operator)
OPER_BWAND  = 7     # lw_expr_oper_bwand
OPER_BWOR   = 8     # lw_expr_oper_bwor
OPER_BWXOR  = 9     # lw_expr_oper_bwxor
OPER_AND    = 10    # lw_expr_oper_and       (boolean &&)
OPER_OR     = 11    # lw_expr_oper_or        (boolean ||)
OPER_NEG    = 12    # lw_expr_oper_neg       (unary negation)
OPER_COM    = 13    # lw_expr_oper_com       (16-bit complement ~)
OPER_COM8   = 14    # lw_expr_oper_com8      (8-bit complement)
OPER_EQ     = 15    # lw_expr_oper_eq
OPER_NE     = 16    # lw_expr_oper_ne
OPER_LT     = 17    # lw_expr_oper_lt
OPER_LE     = 18    # lw_expr_oper_le
OPER_GT     = 19    # lw_expr_oper_gt
OPER_GE     = 20    # lw_expr_oper_ge
OPER_NONE   = 0     # lw_expr_oper_none

# Unary operators (one operand)
_UNARY_OPERS = (OPER_NEG, OPER_COM, OPER_COM8)


# ---------------------------------------------------------------------------
# ExprContext
# Holds the callback functions and per-simplification state that were static
# globals in the C code.  Pass this as 'priv' (void *) to all simplify/parse.
# ---------------------------------------------------------------------------

class ExprContext:
    """
    Holds the callback hooks used by simplify() and the parser.

    Corresponds to the static globals in lw_expr.c:
        evaluate_special  -> ExprContext.evaluate_special
        evaluate_var      -> ExprContext.evaluate_var
        parse_term        -> ExprContext.parse_term
        divzero           -> ExprContext.divzero
        expr_width        -> ExprContext.expr_width
        level / bailing   -> ExprContext._level / _bailing
        parse_compact     -> passed as argument to parse functions

    Callbacks:
        evaluate_special(type_code: int, ptr: object) -> Expr | None
            Called when simplifying a TYPE_SPECIAL node.  Return an Expr to
            replace it, or None to leave it unresolved.

        evaluate_var(name: str) -> Expr | None
            Called when simplifying a TYPE_VAR node (symbol lookup).
            Return an Expr to replace it, or None if undefined.

        parse_term(p: Ptr, ctx: ExprContext) -> Expr | None
            Called by the expression parser for atomic terms (numbers,
            symbols, character literals, etc.).  Advance p.pos past the
            consumed input.  Return None if nothing matched.

        divzero() -> None
            Called on division by zero.  May register an error.
    """
    def __init__(self):
        self.evaluate_special = None  # (type_code, ptr) -> Expr | None
        self.evaluate_var     = None  # (name) -> Expr | None
        self.parse_term       = None  # (Ptr, ctx) -> Expr | None
        self.divzero          = None  # () -> None
        self.expr_width       = 0     # 0 = 16-bit (default), 8 = 8-bit
        # Anti-recursion (static in C; attached to context for thread-safety)
        self._level           = 0
        self._bailing         = False


# ---------------------------------------------------------------------------
# Ptr -- mutable string pointer (C: char **)
# The C code uses char **p to advance through input in place.  We simulate
# this with an object whose .pos field is incremented.
# ---------------------------------------------------------------------------

class Ptr:
    """Mutable pointer into a string.  Simulates C `char **p`."""

    __slots__ = ('s', 'pos')

    def __init__(self, s, pos=0):
        self.s   = s
        self.pos = pos

    def peek(self):
        """Return current character (empty string if past end — falsy like C '\0')."""
        return self.s[self.pos] if self.pos < len(self.s) else ''

    def advance(self, n=1):
        """(*p) += n"""
        self.pos += n

    def startswith(self, prefix):
        return self.s.startswith(prefix, self.pos)

    def at_end(self):
        return self.pos >= len(self.s)

    def remaining(self):
        return self.s[self.pos:]

    def __repr__(self):
        return f'Ptr({self.s!r}, pos={self.pos})'


# ---------------------------------------------------------------------------
# Expr -- expression tree node
# Corresponds to struct lw_expr_priv / lw_expr_t
# ---------------------------------------------------------------------------

class Expr:
    """
    Expression tree node.

    Fields (matching struct lw_expr_priv):
        type     -- TYPE_INT | TYPE_VAR | TYPE_OPER | TYPE_SPECIAL
        value    -- integer value (TYPE_INT), operator code (TYPE_OPER),
                    or special type code (TYPE_SPECIAL); 0 for TYPE_VAR
        value2   -- symbol name str (TYPE_VAR), or arbitrary object pointer
                    (TYPE_SPECIAL); None otherwise
        operands -- list[Expr] for TYPE_OPER; empty for all others
    """

    __slots__ = ('type', 'value', 'value2', 'operands')

    def __init__(self, type_=TYPE_INT, value=0, value2=None):
        self.type     = type_
        self.value    = value
        self.value2   = value2
        self.operands = []

    # ------------------------------------------------------------------
    # Factory methods (lw_expr_build)
    # ------------------------------------------------------------------

    @staticmethod
    def int(v):
        """lw_expr_build(lw_expr_type_int, v)"""
        return Expr(TYPE_INT, int(v))

    @staticmethod
    def int32(v):
        """lw_expr_build for unrestricted-width integer (section offsets etc.)"""
        e = Expr(TYPE_INT, int(v))
        return e

    @staticmethod
    def var(name):
        """lw_expr_build(lw_expr_type_var, name)"""
        e = Expr(TYPE_VAR)
        e.value2 = str(name)
        return e

    @staticmethod
    def oper(op, *args):
        """
        lw_expr_build(lw_expr_type_oper, op, term1[, term2])
        Operands are deep-copied (matching lw_expr_add_operand behaviour).
        """
        e = Expr(TYPE_OPER, op)
        for a in args:
            e.operands.append(a.copy())
        return e

    @staticmethod
    def special(type_code, ptr):
        """lw_expr_build(lw_expr_type_special, type_code, ptr)"""
        e = Expr(TYPE_SPECIAL, int(type_code))
        e.value2 = ptr   # raw pointer; no copy
        return e

    # ------------------------------------------------------------------
    # Copy (lw_expr_copy)
    # Note: value2 is pointer-copied for SPECIAL (same object),
    # string-copied for VAR.
    # ------------------------------------------------------------------

    def copy(self):
        """lw_expr_copy(E)"""
        e = Expr(self.type, self.value)
        if self.type == TYPE_VAR:
            e.value2 = str(self.value2)          # copy string
        else:
            e.value2 = self.value2               # pointer copy
        e.operands = [op.copy() for op in self.operands]
        return e

    # ------------------------------------------------------------------
    # In-place overwrite (_become)
    # C: *E = *te  (struct copy, then fixup value2 for VAR type)
    # Used by simplify_go() when a node resolves to a different expression.
    # ------------------------------------------------------------------

    def _become(self, other):
        """Overwrite this node's contents with other (in-place)."""
        self.type = other.type
        self.value = other.value
        if other.type == TYPE_VAR:
            self.value2 = str(other.value2)
        else:
            self.value2 = other.value2
        self.operands = [op.copy() for op in other.operands]

    # ------------------------------------------------------------------
    # Accessors (lw_expr_istype, lw_expr_intval, etc.)
    # ------------------------------------------------------------------

    def istype(self, t):
        """lw_expr_istype(E, t)"""
        return self.type == t

    def intval(self):
        """lw_expr_intval(E): -1 if not TYPE_INT"""
        return self.value if self.type == TYPE_INT else -1

    def whichop(self):
        """
        lw_expr_whichop(E): returns operator code, or -1 if not TYPE_OPER.
        Note: COM8 is reported as COM (matching C behaviour).
        """
        if self.type == TYPE_OPER:
            return OPER_COM if self.value == OPER_COM8 else self.value
        return -1

    def specint(self):
        """lw_expr_specint(E): special type code, or -1"""
        return self.value if self.type == TYPE_SPECIAL else -1

    def specptr(self):
        """lw_expr_specptr(E): special pointer value"""
        return self.value2

    def operand_count(self):
        """lw_expr_operandcount(E)"""
        return len(self.operands) if self.type == TYPE_OPER else 0

    # ------------------------------------------------------------------
    # Equality (lw_expr_compare)
    # Returns True if structurally identical.  For SPECIAL, pointer
    # identity (not equality) is used for value2.
    # ------------------------------------------------------------------

    def __eq__(self, other):
        """lw_expr_compare(E1, E2): structural equality."""
        if other is None:
            return False
        if self is other:
            return True
        if not isinstance(other, Expr):
            return False
        if self.type != other.type or self.value != other.value:
            return False
        if self.type == TYPE_VAR:
            return self.value2 == other.value2
        if self.type == TYPE_SPECIAL:
            return self.value2 is other.value2    # pointer identity
        # TYPE_OPER or TYPE_INT: compare operand lists
        if len(self.operands) != len(other.operands):
            return False
        return all(a == b for a, b in zip(self.operands, other.operands))

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        # Required because we define __eq__
        return id(self)

    # ------------------------------------------------------------------
    # Contains check (lw_expr_contains)
    # Used to break infinite recursion in simplification.
    # ------------------------------------------------------------------

    def contains(self, other):
        """
        lw_expr_contains(E, E1):
        True if 'other' (a VAR or SPECIAL node) appears anywhere in this tree.
        """
        if other.type not in (TYPE_VAR, TYPE_SPECIAL):
            return False
        if self == other:
            return True
        return any(op.contains(other) for op in self.operands)

    # ------------------------------------------------------------------
    # Testterms (lw_expr_testterms)
    # Walk every node; return True if fn(node) is truthy for any node.
    # ------------------------------------------------------------------

    def testterms(self, fn):
        """lw_expr_testterms(E, fn, priv): walk all nodes, return True on first match."""
        for op in self.operands:
            if op.testterms(fn):
                return True
        return bool(fn(self))

    # ------------------------------------------------------------------
    # Simplification (lw_expr_simplify / lw_expr_simplify_l / _go)
    # ------------------------------------------------------------------

    def simplify(self, ctx):
        """
        lw_expr_simplify(E, priv):
        Simplify this expression tree in place using the callbacks in ctx.
        No-op if already TYPE_INT.
        """
        if self.type == TYPE_INT:
            return
        # Reset anti-recursion counters at top-level entry
        ctx._level   = 0
        ctx._bailing = False
        self._simplify_l(ctx)

    def _simplify_l(self, ctx):
        """
        lw_expr_simplify_l(E, priv):
        Iterates _simplify_go until the expression stops changing.
        Bails out at recursion depth >= 500.
        """
        ctx._level += 1
        if ctx._level >= 500 or ctx._bailing:
            ctx._bailing = True
            ctx._level  -= 1
            if ctx._level == 0:
                ctx._bailing = False
            return
        # Iterate until stable (copy -> simplify -> compare)
        while True:
            before = self.copy()
            self._simplify_go(ctx)
            if self == before:
                break
        ctx._level -= 1

    def _simplify_go(self, ctx):
        """
        lw_expr_simplify_go(E, priv):
        One simplification step.  May modify self in place.
        """
        # ---- Normalise subtraction: A - B  =>  A + (-1 * B) --------
        # (needed for like-term collection later)
        if self.type == TYPE_OPER and self.value == OPER_MINUS:
            new_ops = [self.operands[0].copy()]
            for op in self.operands[1:]:
                m1 = Expr.int(-1)
                new_ops.append(Expr.oper(OPER_TIMES, m1, op))
            self.operands = new_ops
            self.value    = OPER_PLUS

        # ---- Normalise NEG: -X  =>  (-1 * X) -----------------------
        if self.type == TYPE_OPER and self.value == OPER_NEG:
            self.value = OPER_TIMES
            self.operands.append(Expr.int(-1))

        # ---- Resolve SPECIAL nodes ----------------------------------
        # C: if (E->type == special && evaluate_special) { ... goto again; }
        if self.type == TYPE_SPECIAL and ctx.evaluate_special:
            te = ctx.evaluate_special(self.value, self.value2)
            if te is not None and not te.contains(self):
                self._become(te)
                self._simplify_go(ctx)   # C: goto again
            return

        # ---- Resolve VAR nodes (symbol lookup) ----------------------
        # C: if (E->type == var && evaluate_var) { ... goto again; }
        if self.type == TYPE_VAR and ctx.evaluate_var:
            te = ctx.evaluate_var(self.value2)
            if te is None:
                return
            if te.contains(self):
                return
            self._become(te)
            self._simplify_go(ctx)       # C: goto again
            return

        # Non-operators have no further simplification
        if self.type != TYPE_OPER:
            return

        # ---- Flatten nested PLUS: (A + B) + C  => A + B + C --------
        if self.value == OPER_PLUS:
            changed = True
            while changed:
                changed = False
                new_ops = []
                for op in self.operands:
                    if op.type == TYPE_OPER and op.value == OPER_PLUS:
                        new_ops.extend(o.copy() for o in op.operands)
                        changed = True
                    else:
                        new_ops.append(op)
                self.operands = new_ops

        # ---- Flatten nested TIMES ------------------------------------
        if self.value == OPER_TIMES:
            changed = True
            while changed:
                changed = False
                new_ops = []
                for op in self.operands:
                    if op.type == TYPE_OPER and op.value == OPER_TIMES:
                        new_ops.extend(o.copy() for o in op.operands)
                        changed = True
                    else:
                        new_ops.append(op)
                self.operands = new_ops

        # ---- Simplify each non-integer sub-expression ---------------
        for op in self.operands:
            if op.type != TYPE_INT:
                op._simplify_l(ctx)

        # ---- If all operands are integers, compute the result -------
        if all(op.type == TYPE_INT for op in self.operands):
            result = self._compute([op.value for op in self.operands], ctx)
            if result is not None:
                self.operands = []
                self.type     = TYPE_INT
                self.value    = result
                return

        # ---- Partial evaluation for PLUS: collect integer terms -----
        if self.value == OPER_PLUS:
            cval    = 0
            non_int = []
            for op in self.operands:
                if op.type == TYPE_INT:
                    cval += op.value
                else:
                    non_int.append(op)
            self.operands = non_int
            if cval != 0:
                self.operands.append(Expr.int(cval))
            # Eliminate zero terms
            self.operands = [op for op in self.operands
                             if not (op.type == TYPE_INT and op.value == 0)]
            # Collapse to single term
            if len(self.operands) == 1:
                self._become(self.operands[0])
                return
            if len(self.operands) == 0:
                self.type  = TYPE_INT
                self.value = 0
                return

        # ---- Partial evaluation for TIMES: collect integer terms ----
        if self.value == OPER_TIMES:
            cval    = 1
            non_int = []
            for op in self.operands:
                if op.type == TYPE_INT:
                    cval *= op.value
                else:
                    non_int.append(op)
            # Any factor is zero -> whole product is zero
            if cval == 0:
                self.type     = TYPE_INT
                self.value    = 0
                self.operands = []
                return
            self.operands = non_int
            if cval != 1:
                self.operands.append(Expr.int(cval))

        # ---- Distribute: int * (a + b) -> int*a + int*b -------------
        if self.value == OPER_TIMES and len(self.operands) == 2:
            a, b = self.operands
            if a.type == TYPE_INT and b.type == TYPE_OPER and b.value == OPER_PLUS:
                self.value    = OPER_PLUS
                self.operands = [Expr.oper(OPER_TIMES, a, t) for t in b.operands]
            elif b.type == TYPE_INT and a.type == TYPE_OPER and a.value == OPER_PLUS:
                self.value    = OPER_PLUS
                self.operands = [Expr.oper(OPER_TIMES, b, t) for t in a.operands]

        # ---- Like-term collection in PLUS ---------------------------
        # (lw_expr_simplify_isliketerm / like-term loop in C)
        # Collects  2x + 3x  =>  5x  etc.
        if self.value == OPER_PLUS:
            i = 0
            while i < len(self.operands):
                t1 = self.operands[i]
                if t1.type == TYPE_INT:
                    i += 1
                    continue
                j = i + 1
                while j < len(self.operands):
                    t2 = self.operands[j]
                    if t2.type == TYPE_INT:
                        j += 1
                        continue
                    if _is_like_term(t1, t2):
                        coef1 = _coef_of(t1)
                        coef2 = _coef_of(t2)
                        base  = _base_of(t1)
                        total = coef1 + coef2
                        if total == 0:
                            # terms cancel
                            self.operands[i] = Expr.int(0)
                            self.operands[j] = Expr.int(0)
                        else:
                            combined = Expr.oper(OPER_TIMES, Expr.int(total), base)
                            self.operands[i] = combined
                            self.operands[j] = Expr.int(0)
                        t1 = self.operands[i]
                        i  = 0   # restart outer loop (matching C goto again)
                        break
                    j += 1
                i += 1
            # Remove zero terms after collection
            self.operands = [op for op in self.operands
                             if not (op.type == TYPE_INT and op.value == 0)]
            if len(self.operands) == 1:
                self._become(self.operands[0])
            elif len(self.operands) == 0:
                self.type = TYPE_INT; self.value = 0

    # ------------------------------------------------------------------
    # Compute fully-resolved operator result
    # ------------------------------------------------------------------

    def _compute(self, vals, ctx):
        """
        Evaluate operator when all operands are integers.
        Returns integer result or None if operator unrecognised.
        """
        op = self.value
        if op == OPER_NEG:    return -vals[0]
        if op == OPER_COM:    return ~vals[0] & 0xFFFF
        if op == OPER_COM8:   return ~vals[0] & 0xFF
        if op == OPER_PLUS:
            r = vals[0]
            for v in vals[1:]: r += v
            return r
        if op == OPER_MINUS:
            r = vals[0]
            for v in vals[1:]: r -= v
            return r
        if op == OPER_TIMES:
            r = vals[0]
            for v in vals[1:]: r *= v
            return r
        if op == OPER_DIVIDE:
            if vals[1] == 0:
                if ctx.divzero: ctx.divzero()
                return 0
            return int(vals[0] / vals[1])
        if op == OPER_MOD:
            if vals[1] == 0:
                if ctx.divzero: ctx.divzero()
                return 0
            return vals[0] % vals[1]
        if op == OPER_INTDIV:
            if vals[1] == 0:
                if ctx.divzero: ctx.divzero()
                return 0
            return vals[0] // vals[1]
        if op == OPER_BWAND:  return vals[0] & vals[1]
        if op == OPER_BWOR:   return vals[0] | vals[1]
        if op == OPER_BWXOR:  return vals[0] ^ vals[1]
        if op == OPER_AND:    return int(bool(vals[0]) and bool(vals[1]))
        if op == OPER_OR:     return int(bool(vals[0]) or  bool(vals[1]))
        if op == OPER_EQ:     return int(vals[0] == vals[1])
        if op == OPER_NE:     return int(vals[0] != vals[1])
        if op == OPER_LT:     return int(vals[0] <  vals[1])
        if op == OPER_LE:     return int(vals[0] <= vals[1])
        if op == OPER_GT:     return int(vals[0] >  vals[1])
        if op == OPER_GE:     return int(vals[0] >= vals[1])
        return None

    # ------------------------------------------------------------------
    # Debug representation (lw_expr_print)
    # Postfix notation matching the C output format.
    # ------------------------------------------------------------------

    def __repr__(self):
        if self.type == TYPE_INT:
            v = self.value
            return f'-0x{-v:x}' if v < 0 else f'0x{v:x}'
        if self.type == TYPE_VAR:
            return f'V({self.value2})'
        if self.type == TYPE_SPECIAL:
            return f'S({self.value},{id(self.value2):x})'
        _op_names = {
            OPER_PLUS: '+', OPER_MINUS: '-', OPER_TIMES: '*',
            OPER_DIVIDE: '/', OPER_MOD: '%', OPER_INTDIV: '\\',
            OPER_BWAND: 'BWAND', OPER_BWOR: 'BWOR', OPER_BWXOR: 'BWXOR',
            OPER_AND: 'AND', OPER_OR: 'OR',
            OPER_NEG: 'NEG', OPER_COM: 'COM', OPER_COM8: 'COM8',
            OPER_EQ: 'EQ', OPER_NE: 'NE',
            OPER_LT: 'LT', OPER_LE: 'LE', OPER_GT: 'GT', OPER_GE: 'GE',
        }
        ops  = ' '.join(repr(o) for o in self.operands)
        name = _op_names.get(self.value, f'[{self.value}]')
        return f'[{len(self.operands)}]{name} {ops}'


# ---------------------------------------------------------------------------
# Like-term helpers (used by _simplify_go)
# Corresponds to lw_expr_simplify_isliketerm and related code in C.
# ---------------------------------------------------------------------------

def _coef_of(e):
    """
    Return the integer coefficient of a term in a PLUS expression.
    If e is (int * stuff), return int; otherwise return 1.
    """
    if e.type == TYPE_OPER and e.value == OPER_TIMES:
        for op in e.operands:
            if op.type == TYPE_INT:
                return op.value
    return 1


def _base_of(e):
    """
    Return the non-integer base of a term.
    If e is (int * base), return base; otherwise return e itself.
    """
    if e.type == TYPE_OPER and e.value == OPER_TIMES:
        for op in e.operands:
            if op.type != TYPE_INT:
                return op
    return e


def _is_like_term(e1, e2):
    """
    lw_expr_simplify_isliketerm:
    True if e1 and e2 have the same non-constant factors.
    """
    b1 = _base_of(e1)
    b2 = _base_of(e2)
    if b1 is e1 and b2 is e2:
        return e1 == e2
    if b1 is e1:
        # e2 is a TIMES with a constant; check if its non-int part matches e1
        non_int = [op for op in e2.operands if op.type != TYPE_INT]
        if len(non_int) == 1:
            return e1 == non_int[0]
        return False
    if b2 is e2:
        non_int = [op for op in e1.operands if op.type != TYPE_INT]
        if len(non_int) == 1:
            return e2 == non_int[0]
        return False
    return b1 == b2


# ---------------------------------------------------------------------------
# Expression parser
# Corresponds to lw_expr_parse_expr and lw_expr_parse_term in lw_expr.c.
# The C uses a Pratt (precedence climbing) parser.
# ---------------------------------------------------------------------------

# Operator table: (oper_code, symbol, precedence)
# Order matters for disambiguation (longer matches checked first by sort).
_PARSE_OPERATORS = sorted([
    (OPER_PLUS,   '+',   100),
    (OPER_MINUS,  '-',   100),
    (OPER_TIMES,  '*',   150),
    (OPER_DIVIDE, '/',   150),
    (OPER_MOD,    '%',   150),
    (OPER_INTDIV, '\\',  150),
    (OPER_AND,    '&&',   25),
    (OPER_OR,     '||',   25),
    (OPER_BWAND,  '&',    50),
    (OPER_BWOR,   '|',    50),
    (OPER_BWOR,   '!',    50),   # '!' is alias for '|' per C source
    (OPER_BWXOR,  '^',    50),
    (OPER_EQ,     '==',   55),
    (OPER_NE,     '!=',   55),
    (OPER_NE,     '<>',   55),
    (OPER_LT,     '<',    60),
    (OPER_LE,     '<=',   60),
    (OPER_GT,     '>',    60),
    (OPER_GE,     '>=',   60),
], key=lambda x: -len(x[1]))   # longest match first


def _skip_ws(p, compact):
    """lw_expr_parse_next_tok: skip whitespace unless compact mode."""
    if not compact:
        while p.peek() not in ('\0',) and p.peek() in ' \t\r\n':
            p.advance()


def _parse_term(p, ctx, compact):
    """
    lw_expr_parse_term: handle prefix operators and parentheses,
    then delegate to ctx.parse_term for atomic terms.
    """
    _skip_ws(p, compact)
    c = p.peek()

    if c == '\0' or c.isspace() or c in (')', ']'):
        return None

    # Parentheses
    if c == '(':
        p.advance()
        term = _parse_expr(p, ctx, 0, compact)
        _skip_ws(p, compact)
        if p.peek() != ')':
            return None       # syntax error; C returns NULL
        p.advance()
        return term

    # Unary +  (no-op, just consume and re-enter)
    if c == '+':
        p.advance()
        return _parse_term(p, ctx, compact)   # goto eval_next in C

    # Unary -  (prec 200)
    if c == '-':
        p.advance()
        term = _parse_expr(p, ctx, 200, compact)
        if term is None:
            return None
        return Expr.oper(OPER_NEG, term)

    # Unary ^ or ~  (complement; prec 200)
    if c in ('^', '~'):
        p.advance()
        term = _parse_expr(p, ctx, 200, compact)
        if term is None:
            return None
        if ctx.expr_width == 8:
            return Expr.oper(OPER_COM8, term)
        return Expr.oper(OPER_COM, term)

    # Delegate to assembler-supplied atom parser (lwasm_parse_term)
    if ctx.parse_term:
        return ctx.parse_term(p, ctx)

    return None


def _parse_expr(p, ctx, prec, compact):
    """
    lw_expr_parse_expr: Pratt-style precedence climbing.
    Returns Expr or None.
    """
    _skip_ws(p, compact)
    c = p.peek()
    if c == '\0' or c.isspace() or c in (')', ',', ']', ';'):
        return None

    term1 = _parse_term(p, ctx, compact)
    if term1 is None:
        return None

    while True:
        _skip_ws(p, compact)
        c = p.peek()
        if c == '\0' or c.isspace() or c in (')', ',', ']', ';'):
            return term1

        # Find the longest matching operator whose precedence > prec
        matched = None
        for op_code, op_str, op_prec in _PARSE_OPERATORS:
            if op_prec <= prec:
                continue
            if p.startswith(op_str):
                matched = (op_code, op_str, op_prec)
                break   # already sorted by length desc; take first match

        if matched is None:
            return term1   # unrecognised -> return what we have

        op_code, op_str, op_prec = matched
        p.advance(len(op_str))

        term2 = _parse_expr(p, ctx, op_prec, compact)
        if term2 is None:
            return term1   # C returns NULL here; we keep term1 to be safe

        term1 = Expr.oper(op_code, term1, term2)
        # Loop continues: eval_next in C


def parse_expr(p, ctx):
    """
    lw_expr_parse(p, priv): parse a full-whitespace expression from Ptr p.
    Returns Expr or None.
    """
    return _parse_expr(p, ctx, 0, False)


def parse_expr_compact(p, ctx):
    """
    lw_expr_parse_compact(p, priv): parse a compact (no internal whitespace) expression.
    Returns Expr or None.
    """
    return _parse_expr(p, ctx, 0, True)
