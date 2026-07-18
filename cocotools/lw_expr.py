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
# C-style truncating integer division (DIVIDE/MOD/INTDIV all need this --
# see cocotools/c_compat.py for why native Python // and % disagree with
# C's / and % on mixed-sign operands, and why this needs to be a single
# shared implementation rather than redefined per-file).
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Shared C-semantics primitives (see cocotools/c_compat.py): truncating
# division for DIVIDE/MOD/INTDIV, and Ptr (the mutable char** stand-in)
# used throughout this file's parser. Single implementation, imported
# here rather than redefined, so every file that needs either one stays
# in sync automatically.
# ---------------------------------------------------------------------------
from .c_compat import c_trunc_div, c_isspace, Ptr

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

# ---------------------------------------------------------------------------
# Ptr -- mutable string pointer (C: char **) -- now a single shared
# implementation in c_compat.py (imported above alongside c_trunc_div),
# rather than a separate copy maintained here. Re-exported under this
# name so `from .lw_expr import Ptr` (used by insn_funcs.py, lwasm_core.py,
# and pseudo.py) continues to work unchanged.
# ---------------------------------------------------------------------------


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
        # source.c lines 297-320. Merge every literal-int operand into a
        # single running total; re-add it (once, at the end) only if
        # nonzero. NOTE: unlike a prior version of this function, there is
        # no early "collapse to single term / zero" here -- that collapse
        # doesn't happen in the C until the dedicated block near the end
        # (source.c lines 449-522), which runs *after* sort-const-first
        # and like-term collection below. Returning early here would skip
        # those steps for cases they still need to run on (e.g. "x + 0 + y"
        # reduces to two operands here, but still needs like-term
        # collection to check whether x and y are like terms).
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

        # ---- Partial evaluation for TIMES: collect integer terms ----
        # source.c lines 322-345.
        if self.value == OPER_TIMES:
            cval    = 1
            non_int = []
            for op in self.operands:
                if op.type == TYPE_INT:
                    cval *= op.value
                else:
                    non_int.append(op)
            self.operands = non_int
            if cval != 1:
                self.operands.append(Expr.int(cval))

        # ---- TIMES: any literal-0 operand makes the whole product 0 ----
        # source.c lines 347-366 -- a separate, later check from the cval
        # collection above (by the time we get here, at most one literal
        # int remains -- the merged cval -- so this fires only when that
        # cval collapsed to 0).
        if self.value == OPER_TIMES:
            for op in self.operands:
                if op.type == TYPE_INT and op.value == 0:
                    self.type     = TYPE_INT
                    self.value    = 0
                    self.operands = []
                    return

        # ---- Sort constants to the front of + and * operand lists ------
        # source.c line 369-370: lw_expr_simplify_sortconstfirst(E).
        # Needed so the like-term coefficient extraction below (which,
        # like the C, only inspects the *first* operand of a TIMES node)
        # finds the right value.
        if self.value == OPER_PLUS or self.value == OPER_TIMES:
            _sort_const_first(self)

        # ---- Like-term collection in PLUS ---------------------------
        # source.c lines 372-446 (lw_expr_simplify_isliketerm + merge).
        # Collects  2x + 3x  =>  5x,  x + x*y ... etc. Unlike a prior
        # version of this function, this operates on full operand lists
        # (a term can be a product of several non-constant factors, e.g.
        # "2*x*y") rather than assuming a single "base" expression, and
        # reads the coefficient only from the first operand of a TIMES
        # node -- matching the C exactly now that sort-const-first (above)
        # guarantees the constant is first when one is present.
        if self.value == OPER_PLUS:
            restart = True
            while restart:
                restart = False
                ops = self.operands
                n = len(ops)
                for i in range(n):
                    if ops[i].type == TYPE_INT:
                        continue
                    for j in range(i + 1, n):
                        if ops[j].type == TYPE_INT:
                            continue
                        if _is_like_term(ops[i], ops[j]):
                            t1, t2 = ops[i], ops[j]
                            if t1.type == TYPE_OPER and t1.value == OPER_TIMES:
                                coef = (t1.operands[0].value
                                        if t1.operands[0].type == TYPE_INT else 1)
                            else:
                                coef = 1
                            if t2.type == TYPE_OPER and t2.value == OPER_TIMES:
                                coef2 = (t2.operands[0].value
                                         if t2.operands[0].type == TYPE_INT else 1)
                            else:
                                coef2 = 1
                            coef += coef2
                            new_times = Expr(TYPE_OPER, OPER_TIMES)
                            if coef != 1:
                                new_times.operands.append(Expr.int(coef))
                            if t2.type == TYPE_OPER:
                                for sub in t2.operands:
                                    if sub.type == TYPE_INT:
                                        continue
                                    new_times.operands.append(sub.copy())
                            else:
                                new_times.operands.append(t2.copy())
                            ops[i] = new_times
                            ops[j] = Expr.int(0)
                            restart = True
                            break
                    if restart:
                        break

        # ---- PLUS: collapse to single term / zero, or prune zeros -----
        # source.c lines 449-522. This is the ONLY place a PLUS node
        # collapses to a bare operand or to a literal 0 -- deliberately
        # placed after like-term collection above, since a like-term
        # cancellation (e.g. x + -x) leaves behind exactly the kind of
        # literal-0 placeholder this block prunes.
        if self.value == OPER_PLUS:
            c = 0
            t = 0
            for op in self.operands:
                t += 1
                if not (op.type == TYPE_INT and op.value == 0):
                    c += 1
            if c == 1:
                r = None
                for op in self.operands:
                    if not (op.type == TYPE_INT and op.value == 0):
                        r = op
                self._become(r)
                return
            elif c == 0:
                self.type     = TYPE_INT
                self.value    = 0
                self.operands = []
                return
            elif c != t:
                self.operands = [op for op in self.operands
                                  if not (op.type == TYPE_INT and op.value == 0)]
            return

        # ---- Distribute: int * (a + b) -> int*a + int*b -------------
        # source.c lines 524-578 -- deliberately LAST, only for exactly
        # two operands where one is a literal int and the other a PLUS.
        if self.value == OPER_TIMES and len(self.operands) == 2:
            a, b = self.operands
            if a.type == TYPE_INT and b.type == TYPE_OPER and b.value == OPER_PLUS:
                self.value    = OPER_PLUS
                self.operands = [Expr.oper(OPER_TIMES, a, t) for t in b.operands]
            elif b.type == TYPE_INT and a.type == TYPE_OPER and a.value == OPER_PLUS:
                self.value    = OPER_PLUS
                self.operands = [Expr.oper(OPER_TIMES, b, t) for t in a.operands]

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
        # source.c: `tr = ~(E->operands->p->value);` -- NO mask here. Only
        # COM8 masks (`& 0xff`). Masking COM to 16 bits (as a prior version
        # of this function did) diverges from the true C internal state:
        # in C, ~5 stays -6 (plain int complement); it is not truncated
        # to an unsigned 16-bit value at this point in the computation.
        if op == OPER_COM:    return ~vals[0]
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
            return c_trunc_div(vals[0], vals[1])
        if op == OPER_MOD:
            # C's % has the sign of the DIVIDEND (truncating remainder),
            # not the sign of the divisor (Python's native % is floor-based
            # and would differ whenever operands have mixed signs).
            if vals[1] == 0:
                if ctx.divzero: ctx.divzero()
                return 0
            a, b = vals[0], vals[1]
            return a - c_trunc_div(a, b) * b
        if op == OPER_INTDIV:
            # lwasm's "\" operator is defined identically to "/" in the C
            # source (both use C's truncating integer division) -- NOT
            # Python's floor-based "//", which rounds toward negative
            # infinity and disagrees with C whenever operands have
            # different signs.
            if vals[1] == 0:
                if ctx.divzero: ctx.divzero()
                return 0
            return c_trunc_div(vals[0], vals[1])
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

def _sort_const_first(e):
    """
    lw_expr_simplify_sortconstfirst(E) (lw_expr.c lines 449-477):
    Recursively move every literal-int operand of a PLUS/TIMES node to the
    front of its operand list (non-PLUS/TIMES nodes, and their operands,
    are left alone). No-op if E isn't PLUS/TIMES.

    Needed so that later code (like-term coefficient extraction) which,
    matching the C, only inspects the *first* operand of a TIMES node to
    find its coefficient, actually finds it there.
    """
    if e.type != TYPE_OPER or e.value not in (OPER_PLUS, OPER_TIMES):
        return
    for op in e.operands:
        if op.type == TYPE_OPER and op.value in (OPER_PLUS, OPER_TIMES):
            _sort_const_first(op)
    ops = e.operands
    i = 0
    while i < len(ops):
        if ops[i].type == TYPE_INT and i != 0:
            ops.insert(0, ops.pop(i))
            continue   # re-examine position i (now holds the next element)
        i += 1


def _compare_operand_list(list1, list2):
    """
    lw_expr_simplify_compareoperandlist: ordered, element-wise comparison.
    lw_expr_sortoperandlist -- which this C function calls on both lists
    first -- is an unimplemented no-op stub in the real lw_expr.c ("not yet
    implemented"), so no actual sorting occurs here either; this is a
    strictly order-sensitive comparison, matching that reality.
    """
    if len(list1) != len(list2):
        return False
    return all(a == b for a, b in zip(list1, list2))


def _is_like_term(e1, e2):
    """
    lw_expr_simplify_isliketerm(e1, e2) (lw_expr.c lines 503-554).

    True if e1 and e2 differ only in an integer-literal coefficient --
    i.e. they're "like terms" that can be added together (2x and 3x; x and
    5*x*y is NOT a like term of plain x, etc.)
    """
    if e1.type == TYPE_OPER and e1.value == OPER_TIMES:
        if e2.type == TYPE_OPER and e2.value == OPER_TIMES:
            # Both TIMES: skip each one's leading run of int operands
            # (there should be at most one, at the front, courtesy of
            # sort-const-first), then compare what's left, in order.
            i1 = 0
            while i1 < len(e1.operands) and e1.operands[i1].type == TYPE_INT:
                i1 += 1
            i2 = 0
            while i2 < len(e2.operands) and e2.operands[i2].type == TYPE_INT:
                i2 += 1
            return _compare_operand_list(e1.operands[i1:], e2.operands[i2:])

        # e2 is not a TIMES -- e1 must be exactly (coefficient * single
        # term) for this to count as a like term at all.
        if len(e1.operands) != 2:
            return False
        return e1.operands[1] == e2

    if e2.type == TYPE_OPER and e2.value == OPER_TIMES:
        if len(e2.operands) != 2:
            return False
        return e1 == e2.operands[1]

    # Neither is a TIMES -- only a like term if structurally identical.
    return e1 == e2


# ---------------------------------------------------------------------------
# Expression parser
# Corresponds to lw_expr_parse_expr and lw_expr_parse_term in lw_expr.c.
# The C uses a Pratt (precedence climbing) parser.
# ---------------------------------------------------------------------------

# Operator table: (oper_code, symbol, precedence)
#
# CRITICAL: this order must match the C `operators[]` array EXACTLY --
# declaration order, NOT sorted by string length. The C matching loop
# (source.c) walks the table in this order and stops at the FIRST entry
# whose string is a complete prefix of the remaining input; it is not a
# longest-match search.
#
# Because "<" is declared before "<=" (same for ">" / ">=", and the
# single-char "!" -- the bwor alias -- before "!="), the shorter operator
# always wins the prefix test first and the loop breaks there without
# ever reaching the longer one. A single-character operator that is a
# prefix of a later, longer operator therefore permanently shadows it.
#
# Concretely: lwasm 4.24 can NEVER parse "<=", ">=", or "!=" as their own
# distinct operator -- confirmed against the real lwasm 4.24 binary,
# which reports "Bad operand" for all three (the shorter operator matches,
# consumes 1 char, and the dangling "=" then fails to parse as a term).
# A prior version of this translation sorted the table by descending
# string length specifically to get "longest match wins" -- which is
# exactly backwards from the real (buggy-but-authoritative) C behavior,
# and also silently changes which operator wins in mixed-precedence
# interactions (e.g. "1&2!=3", which real lwasm rejects outright but a
# longest-match-first search parses as "1 & (2!=3)").
_PARSE_OPERATORS = [
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
    (OPER_NE,     '!=',   55),   # unreachable in practice -- see above
    (OPER_NE,     '<>',   55),
    (OPER_LT,     '<',    60),
    (OPER_LE,     '<=',   60),   # unreachable in practice -- see above
    (OPER_GT,     '>',    60),
    (OPER_GE,     '>=',   60),   # unreachable in practice -- see above
]


def _match_operator(p):
    """
    lw_expr_parse_expr's operator-recognition loop: walk _PARSE_OPERATORS
    IN TABLE ORDER and return the first entry whose string is a complete
    prefix of the remaining input at p. Precedence is NOT considered here
    -- the C source always finds a match first (irrespective of prec) and
    only checks precedence afterward, once the operator is already fixed.
    Returns (op_code, op_str, op_prec), or None if nothing matches (C's
    `operators[opern].opernum == lw_expr_oper_none` case).
    """
    for op_code, op_str, op_prec in _PARSE_OPERATORS:
        if p.startswith(op_str):
            return (op_code, op_str, op_prec)
    return None


def _skip_ws(p, compact):
    """lw_expr_parse_next_tok: skip whitespace unless compact mode."""
    if not compact:
        while p.peek() not in ('\0',) and p.peek() in ' \t\r\n':
            p.advance()


def _parse_term(p, ctx, compact):
    """
    lw_expr_parse_term: handle prefix operators and parentheses,
    then delegate to ctx.parse_term for atomic terms.

    ---------------------------------------------------------------------
    Pre-translation checklist results (see checklist.md for full detail):
      Integer width: none (no fixed-width assignments)
      Division/modulo: none (no / or % in this function)
      char **p: FOUND -- p is a Ptr, shared with _parse_expr and (via the
        unary-'+' goto) with itself; never rebuilt from p.remaining().
      goto: FOUND -- `goto eval_next;` is a self re-entry after consuming
        a unary '+' with no other state to preserve; translated as a
        direct recursive call to this same function.
      char signedness: safe -- only ASCII punctuation is compared to *p.
      Argument order: safe -- no (*p)++ in argument position.
      Promotion: safe -- no fixed-width destination anywhere here.
      Complement: N/A at this level -- OPER_COM/OPER_COM8 are only built
        as tree nodes here; the actual ~ computation (and its 8-bit
        mask) happens later in Expr._compute, not in the parser.
      lookupreg: N/A.

    Interaction risks identified (found comparing against existing.py):
      1. Ptr.peek() returns '' (empty string) at end of input, never the
         C NUL character '\\0' -- the same sentinel mistake already
         identified and fixed in _parse_expr's docstring (risk #3
         there). existing.py's check here was `c == '\\0'`, which can
         never be true, so the C's `if (!**p) return NULL;` case was
         never reached directly -- true end-of-input instead fell
         through every other branch and reached
         `ctx.parse_term(p, ctx)`, asking the atom parser to parse a
         term out of nothing.
      2. checklist.md flags `isspace(**p)` with the mitigation
         `c_isspace(c)`. existing.py used Python's `c.isspace()`
         directly. Python's str.isspace() agrees with C's isspace()
         (C locale) for the whitespace characters lwasm's own source
         actually emits (space/tab/CR/LF/FF/VT), but ALSO returns True
         for characters C's isspace() does not treat as whitespace --
         concretely, the ASCII control characters U+001C-U+001F
         (file/group/record/unit separator) and non-ASCII Unicode space
         separators such as U+00A0 (NBSP). Confirmed directly:
         '\\x1c'.isspace() is True in Python but isspace(0x1C) is false
         in C's "C" locale. Any of these characters appearing where a
         term is expected would be (incorrectly) treated as an
         immediate end-of-term by existing.py, when the C source would
         instead fall through to attempt `parse_term(p, priv)` on it.

    Mitigations applied:
      1. End-of-input check changed from `c == '\\0'` to `c == ''`,
         matching Ptr's actual sentinel value (mirrors the identical
         fix already applied in _parse_expr).
      2. `c.isspace()` replaced with `c_isspace(c)` (imported from
         c_compat), matching the checklist's explicit instruction and
         removing the divergence documented in risk #2 above.

    Both fixes are provably observable at the direct-unit-test level
    (see UNIT_TESTS_PARSE_TERM in test_fidelity.py): a stub parse_term
    callback shows existing.py either wrongly invoking it (case 1, via
    fallthrough) or wrongly skipping it (case 2, via the FS-control-char
    false positive) relative to the fixed version.
    ---------------------------------------------------------------------
    """
    _skip_ws(p, compact)
    c = p.peek()

    if c == '' or c_isspace(c) or c in (')', ']'):
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

    ---------------------------------------------------------------------
    Pre-translation checklist results (see checklist.md for full detail):
      Integer width: none (no fixed-width assignments)
      Division/modulo: N/A (no / or % in this function)
      char **p: FOUND -- p is a Ptr, shared across every recursive call
        and with _parse_term; never rebuilt from p.remaining().
      goto: FOUND -- `goto eval_next;` is Pattern B (shared code the
        function jumps back to repeatedly); translated as a `while True`
        loop, since eval_next is re-entered from the bottom with the same
        local variables (term1, prec) still in scope.
      char signedness: safe -- Ptr.peek() returns Python str comparisons
        only against ASCII terminator/operator characters, never > 127.
      Argument order: safe -- no (*p)++-in-argument-position pattern here.
      Promotion: safe -- no fixed-width destination anywhere in this fn.
      Complement: none.
      lookupreg: N/A.

    Interaction risks identified:
      1. The C operator table matches by FIRST full-prefix hit in
         declaration order, not by longest match. Because "<", ">", and
         the bwor alias "!" are declared before "<=", ">=", and "!="
         respectively, and are themselves complete prefixes of those
         longer operators, the longer two-char operators can never be
         reached -- lwasm 4.24 cannot parse "<=", ">=", or "!=" as their
         own operators (confirmed against the real binary: all three
         produce "Bad operand", not the operator lwasm's own table
         suggests they should be).
      2. Operator matching and precedence-checking are two SEPARATE
         steps in the C source: a match is found unconditionally first
         (regardless of prec), and only afterward is its precedence
         compared against the current `prec` threshold. Pre-filtering
         candidates by precedence during the search (as a "skip low-prec
         entries" step) is NOT equivalent once shadowing (risk 1) is in
         play: at prec values between a shadowed short operator's
         precedence and its shadowing target's precedence (e.g. prec=50,
         between "!" at 50 and "!=" at 55), a precedence-filtered search
         would incorrectly "see" and accept "!=" as NE, while the real
         C code (and lwasm) permanently commits to "!" first and bails
         via the low-precedence return before "!=" is ever considered.
         Verified against real lwasm with "1&2!=3", which real lwasm
         rejects as "Bad operand" in its entirety.
      3. Ptr.peek() returns '' (empty string) at end of input, not the
         null character '\\0'. A prior version of this translation
         checked `c == '\\0'`, which can never be true for Ptr's actual
         end-of-string sentinel -- it happened to produce the right
         answer at true end-of-input only by accident, because it also
         (incorrectly) treated "no operator matched" as "return term1"
         (see mitigation 5 below). Fixing that return value without also
         fixing this check would break ordinary end-of-string parsing
         (e.g. a bare "5" operand) by having it fall through to operator
         matching, find nothing, and (correctly, per the *fixed* NULL
         propagation) discard term1 entirely.

    Mitigations applied:
      1/2. _PARSE_OPERATORS kept in exact C declaration order; matching
           done by _match_operator(), which returns the first full-prefix
           hit with no precedence filtering. Precedence is checked only
           after a match is already fixed, exactly mirroring the C
           source's two separate `if` statements.
      3. End-of-input checks use `c == ''` (Ptr's actual sentinel),
         not `c == '\\0'`.
      4. (Also verified, no fix needed) `if (operators[opern].operprec
         <= prec) return term1;` was already correctly translated as an
         unconditional early return with no destroy -- kept as-is.
      5. `lw_expr_destroy(term1); return NULL;` -- both the "unrecognized
         operator" branch and the "term2 came back NULL" branch destroy
         term1 and return NULL in C. A prior version of this translation
         returned term1 in both cases ("to be safe"); this is wrong and
         has an observable effect: real lwasm rejects a term followed by
         unrecognized trailing input (e.g. "5`", "5@", "5.1") and a
         dangling operator with no right operand (e.g. "5+") as complete
         syntax errors ("Bad operand"), not as a successfully parsed
         partial expression. Both branches now return None.
    ---------------------------------------------------------------------
    """
    _skip_ws(p, compact)
    c = p.peek()
    if c == '' or c.isspace() or c in (')', ',', ']', ';'):
        return None

    term1 = _parse_term(p, ctx, compact)
    if term1 is None:
        return None

    while True:
        _skip_ws(p, compact)
        c = p.peek()
        if c == '' or c.isspace() or c in (')', ',', ']', ';'):
            return term1

        # Expecting an operator here. Match unconditionally, in table
        # (declaration) order, BEFORE looking at precedence at all --
        # see "Interaction risks" #1/#2 above for why this order matters.
        matched = _match_operator(p)

        if matched is None:
            # C: lw_expr_destroy(term1); return NULL;  (unrecognized
            # operator with input still remaining -- a real syntax error,
            # not "stop and hand back what we have").
            return None

        op_code, op_str, op_prec = matched

        # logic (from source.c): if the precedence of this operation is
        # <= to the "prec" flag, simply return without advancing the
        # input pointer; the operator will be evaluated again in the
        # enclosing function call.
        if op_prec <= prec:
            return term1

        # logic (from source.c): higher precedence operator -- advance
        # past it and let the expression evaluator loose on what
        # follows, of at least this operator's own precedence, before
        # building the operator node and continuing.
        p.advance(len(op_str))

        term2 = _parse_expr(p, ctx, op_prec, compact)
        if term2 is None:
            # C: lw_expr_destroy(term1); return NULL;
            return None

        term1 = Expr.oper(op_code, term1, term2)
        # continue evaluating: goto eval_next in C


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
