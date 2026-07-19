"""
cocotools/lwasm_types.py — Constants, enumerations, and data structures
Faithful Python translation of lwasm/lwasm.h (William Astle, LWTools, GPL v3)
Source: http://lwtools.projects.l-w.ca/

Every constant, enum value, and data structure from lwasm.h is represented
here.  Naming is preserved exactly so that the translation can be verified
line-by-line against the C original.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Symbol character sets  (lwasm.h SSYMCHARS / SYMCHARS)
# ─────────────────────────────────────────────────────────────────────────────

SSYMCHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_@$.')
SYMCHARS  = SSYMCHARS | set('.?0123456789')


# ─────────────────────────────────────────────────────────────────────────────
# Special expression type codes  (enum in lwasm.h)
# ─────────────────────────────────────────────────────────────────────────────

lwasm_expr_linelen    = 1   # length of referenced line
lwasm_expr_lineaddr   = 2   # address of referenced line
lwasm_expr_nextbp     = 3   # next branch point
lwasm_expr_prevbp     = 4   # previous branch point
lwasm_expr_syment     = 5   # symbol table entry
lwasm_expr_import     = 6   # import entry
lwasm_expr_secbase    = 7   # section base address
lwasm_expr_linedaddr  = 8   # data address of the line
lwasm_expr_linedlen   = 9   # data length of the line
lwasm_expr_lineaddrraw = 10  # address of referenced line without phase


# ─────────────────────────────────────────────────────────────────────────────
# Output format codes  (enum lwasm_output_e)
# ─────────────────────────────────────────────────────────────────────────────

OUTPUT_DECB   = 0   # DECB multirecord format
OUTPUT_BASIC  = 1   # Color BASIC program
OUTPUT_RAW    = 2   # raw sequence of bytes
OUTPUT_OBJ    = 3   # proprietary object file format
OUTPUT_RAWREL = 4   # raw bytes where ORG causes SEEK
OUTPUT_OS9    = 5   # OS-9 module target
OUTPUT_SREC   = 6   # Motorola SREC format
OUTPUT_IHEX   = 7   # Intel hex format
OUTPUT_HEX    = 8   # generic hexadecimal format
OUTPUT_LWMOD  = 9   # special module format for LW
OUTPUT_DRAGON = 10  # Dragon DOS binary
OUTPUT_ABS    = 11  # absolute binary block


# ─────────────────────────────────────────────────────────────────────────────
# Assembly flag bits  (enum lwasm_flags_e)
# ─────────────────────────────────────────────────────────────────────────────

FLAG_LIST           = 0x0001
FLAG_DEPEND         = 0x0002
FLAG_SYMBOLS        = 0x0004
FLAG_DEPENDNOERR    = 0x0008
FLAG_UNICORNS       = 0x0010
FLAG_MAP            = 0x0020
FLAG_SYMBOLS_NOLOCALS = 0x0040
FLAG_NOOUT          = 0x0080
FLAG_SYMDUMP        = 0x0100
FLAG_NONE           = 0

# instab flags (subset needed outside pass1.py)
lwasm_insn_setdata  = 1 << 5   # use daddr (not addr) for symbol


# ─────────────────────────────────────────────────────────────────────────────
# Pragma bits  (enum lwasm_pragmas_e)
# ─────────────────────────────────────────────────────────────────────────────

PRAGMA_NONE             = 0
PRAGMA_DOLLARNOTLOCAL   = 1 << 0
PRAGMA_NOINDEX0TONONE   = 1 << 1
PRAGMA_UNDEFEXTERN      = 1 << 2
PRAGMA_CESCAPES         = 1 << 3
PRAGMA_IMPORTUNDEFEXPORT= 1 << 4
PRAGMA_PCASPCR          = 1 << 5
PRAGMA_SHADOW           = 1 << 6
PRAGMA_NOLIST           = 1 << 7
PRAGMA_AUTOBRANCHLENGTH = 1 << 8
PRAGMA_EXPORT           = 1 << 9
PRAGMA_SYMBOLNOCASE     = 1 << 10
PRAGMA_CONDUNDEFZERO    = 1 << 11
PRAGMA_6800COMPAT       = 1 << 12
PRAGMA_FORWARDREFMAX    = 1 << 13
PRAGMA_6809             = 1 << 14
PRAGMA_TESTMODE         = 1 << 15
PRAGMA_C                = 1 << 16
PRAGMA_CD               = 1 << 17
PRAGMA_CT               = 1 << 18
PRAGMA_CC               = 1 << 19
PRAGMA_QRTS             = 1 << 20
PRAGMA_M80EXT           = 1 << 21
PRAGMA_6809CONV         = 1 << 22
PRAGMA_6309CONV         = 1 << 23
PRAGMA_NEWSOURCE        = 1 << 24
PRAGMA_OPERANDSIZE      = 1 << 25
PRAGMA_EMUEXT           = 1 << 26
PRAGMA_NOOUTPUT         = 1 << 27
PRAGMA_NOEXPANDCOND     = 1 << 28
PRAGMA_NOLISTCODE       = 1 << 29
PRAGMA_CLEARBIT         = 1 << 31   # reserved: indicates negated pragma


# ─────────────────────────────────────────────────────────────────────────────
# Section flag bits  (anonymous enum in lwasm.h)
# ─────────────────────────────────────────────────────────────────────────────

section_flag_bss      = 1   # BSS section
section_flag_constant = 2   # constants — no base offset
section_flag_none     = 0


# ─────────────────────────────────────────────────────────────────────────────
# Symbol flag bits  (anonymous enum in lwasm.h)
# ─────────────────────────────────────────────────────────────────────────────

symbol_flag_set     = 1   # symbol was used with SET
symbol_flag_nocheck = 2   # do not check symbol characters
symbol_flag_nolist  = 4   # do not show symbol in symbol table
symbol_flag_nocase  = 8   # do not match case of symbol
symbol_flag_none    = 0


# ─────────────────────────────────────────────────────────────────────────────
# Macro flags  (anonymous enum in lwasm.h)
# ─────────────────────────────────────────────────────────────────────────────

macro_noexpand = 1   # do not expand by default in listing


# ─────────────────────────────────────────────────────────────────────────────
# Cycle flags  (enum cycle_flags)
# ─────────────────────────────────────────────────────────────────────────────

CYCLE_ADJ       = 1
CYCLE_ESTIMATED = 2


# ─────────────────────────────────────────────────────────────────────────────
# Test mode flags  (enum lwasm_testflags_t)
# ─────────────────────────────────────────────────────────────────────────────

TF_EMIT  = 1
TF_ERROR = 2


# ─────────────────────────────────────────────────────────────────────────────
# NOWARN flags
# ─────────────────────────────────────────────────────────────────────────────

NOWARN_NONE = 0
NOWARN_IFP1 = 1


# ─────────────────────────────────────────────────────────────────────────────
# Error codes  (enum lwasm_errorcode_t)
# ─────────────────────────────────────────────────────────────────────────────

E_6309_INVALID            = 1
E_6809_INVALID            = 2
E_ALIGNMENT_INVALID       = 3
E_BITNUMBER_UNRESOLVED    = 4
E_BITNUMBER_INVALID       = 5
E_BYTE_OVERFLOW           = 6
E_CONDITION_P1            = 7
E_DIRECTIVE_OS9_ONLY      = 8
E_DIV0                    = 9
E_EXEC_ADDRESS            = 10
E_FILL_INVALID            = 11
E_IMMEDIATE_INVALID       = 12
E_IMMEDIATE_UNRESOLVED    = 13
E_EXPRESSION_BAD          = 14
E_EXPRESSION_NOT_CONST    = 15
E_EXPRESSION_NOT_RESOLVED = 16
E_FILE_OPEN               = 17
E_FILENAME_MISSING        = 18
E_INSTRUCTION_FAILED      = 19
E_INSTRUCTION_SECTION     = 20
E_LINE_ADDRESS            = 21
E_LINED_ADDRESS           = 22
E_MACRO_DUPE              = 23
E_MACRO_ENDM              = 24
E_MACRO_NONAME            = 25
E_MACRO_RECURSE           = 26
E_MODULE_IN               = 27
E_MODULE_NOTIN            = 28
E_NEGATIVE_BLOCKSIZE      = 29
E_NEGATIVE_RESERVATION    = 30
E_NW_8                    = 31
E_OPCODE_BAD              = 32
E_OPERAND_BAD             = 33
E_OBJTARGET_ONLY          = 34
E_PADDING_BAD             = 35
E_PRAGMA_UNRECOGNIZED     = 36
E_REGISTER_BAD            = 37
E_SECTION_END             = 38
E_SECTION_EXTDEP          = 39
E_SECTION_FLAG            = 40
E_SECTION_NAME            = 41
E_SECTION_TARGET          = 42
E_SETDP_INVALID           = 43
E_SETDP_NOT_CONST         = 44
E_STRING_BAD              = 45
E_STRUCT_DUPE             = 46
E_STRUCT_NONAME           = 47
E_STRUCT_NOSYMBOL         = 48
E_STRUCT_RECURSE          = 49
E_SYMBOL_BAD              = 50
E_SYMBOL_DUPE             = 51
E_SYMBOL_MISSING          = 52
E_SYMBOL_UNDEFINED        = 53
E_SYMBOL_UNDEFINED_EXPORT = 54
E_UNKNOWN_OPERATION       = 55
E_USER_SPECIFIED          = 56
E_ORG_NOT_FOUND           = 57
E_COMPLEX_INCOMPLETE      = 58
E_ILL5                    = 59
E_INCLUDEBIN_ILL_START    = 60
E_INCLUDEBIN_ILL_LENGTH   = 61
E_NESTED_PHASE            = 62
E_MISSING_PHASE           = 63

# Warnings (>= 1000)
W_DUPLICATE_SECTION       = 1000
W_ENDSTRUCT_WITHOUT       = 1001
W_NOT_SUPPORTED           = 1002
W_USER_SPECIFIED          = 1003
W_OPERAND_SIZE            = 1004


# ─────────────────────────────────────────────────────────────────────────────
# Error message lookup  (lwasm_lookup_error in lwasm.c)
# ─────────────────────────────────────────────────────────────────────────────

_ERROR_MESSAGES = {
    E_6309_INVALID:            "Illegal use of 6309 instruction in 6809 mode",
    E_6809_INVALID:            "Illegal use of 6809 instruction in 6309 mode",
    E_ALIGNMENT_INVALID:       "Invalid alignment",
    E_BITNUMBER_INVALID:       "Invalid bit number",
    E_BITNUMBER_UNRESOLVED:    "Bit number must be fully resolved",
    E_BYTE_OVERFLOW:           "Byte overflow",
    E_CONDITION_P1:            "Conditions must be constant on pass 1",
    E_DIRECTIVE_OS9_ONLY:      "Directive only valid for OS9 target",
    E_DIV0:                    "Division by zero",
    E_EXEC_ADDRESS:            "Exec address not constant!",
    E_EXPRESSION_BAD:          "Bad expression",
    E_EXPRESSION_NOT_CONST:    "Expression must be constant",
    E_EXPRESSION_NOT_RESOLVED: "Expression not fully resolved",
    E_FILE_OPEN:               "Cannot open file",
    E_FILENAME_MISSING:        "Missing filename",
    E_FILL_INVALID:            "Invalid fill length",
    E_IMMEDIATE_INVALID:       "Immediate mode not allowed",
    E_IMMEDIATE_UNRESOLVED:    "Immediate byte must be fully resolved",
    E_INSTRUCTION_FAILED:      "Instruction failed to resolve.",
    E_INSTRUCTION_SECTION:     "Instruction generating output outside of a section",
    E_LINE_ADDRESS:            "Cannot resolve line address",
    E_LINED_ADDRESS:           "Cannot resolve line data address",
    E_OBJTARGET_ONLY:          "Only supported for object target",
    E_OPCODE_BAD:              "Bad opcode",
    E_OPERAND_BAD:             "Bad operand",
    E_PADDING_BAD:             "Bad padding",
    E_PRAGMA_UNRECOGNIZED:     "Unrecognized pragma string",
    E_REGISTER_BAD:            "Bad register",
    E_SETDP_INVALID:           "SETDP not permitted for object target",
    E_SETDP_NOT_CONST:         "SETDP must be constant on pass 1",
    E_STRING_BAD:              "Bad string condition",
    E_SYMBOL_BAD:              "Bad symbol",
    E_SYMBOL_MISSING:          "Missing symbol",
    E_SYMBOL_UNDEFINED:        "Undefined symbol",
    E_SYMBOL_UNDEFINED_EXPORT: "Undefined exported symbol",
    E_MACRO_DUPE:              "Duplicate macro definition",
    E_MACRO_ENDM:              "ENDM without MACRO",
    E_MACRO_NONAME:            "Missing macro name",
    E_MACRO_RECURSE:           "Attempt to define a macro inside a macro",
    E_MODULE_IN:               "Already in a module!",
    E_MODULE_NOTIN:            "Not in a module!",
    E_NEGATIVE_BLOCKSIZE:      "Negative block sizes make no sense!",
    E_NEGATIVE_RESERVATION:    "Negative reservation sizes make no sense!",
    E_NW_8:                    "n,W cannot be 8 bit",
    E_SECTION_END:             "ENDSECTION without SECTION",
    E_SECTION_EXTDEP:          "EXTDEP must be within a section",
    E_SECTION_FLAG:            "Unrecognized section flag",
    E_SECTION_NAME:            "Need section name",
    E_SECTION_TARGET:          "Cannot use sections unless using the object target",
    E_STRUCT_DUPE:             "Duplicate structure definition",
    E_STRUCT_NONAME:           "Cannot declare a structure without a symbol name.",
    E_STRUCT_NOSYMBOL:         "Structure definition with no effect - no symbol",
    E_STRUCT_RECURSE:          "Attempt to define a structure inside a structure",
    E_SYMBOL_DUPE:             "Multiply defined symbol",
    E_UNKNOWN_OPERATION:       "Unknown operation",
    E_ORG_NOT_FOUND:           "Previous ORG not found",
    E_COMPLEX_INCOMPLETE:      "Incomplete expression too complex",
    E_USER_SPECIFIED:          "User Specified:",
    E_ILL5:                    "Illegal 5 bit offset",
    E_INCLUDEBIN_ILL_START:    "Start value out of range",
    E_INCLUDEBIN_ILL_LENGTH:   "Length value out of range",
    E_NESTED_PHASE:            "Nested PHASE not supported",
    E_MISSING_PHASE:           "DEPHASE without PHASE",
    W_ENDSTRUCT_WITHOUT:       "ENDSTRUCT without STRUCT",
    W_DUPLICATE_SECTION:       "Section flags can only be specified the first time; ignoring duplicate definition",
    W_NOT_SUPPORTED:           "Not supported",
    W_OPERAND_SIZE:            "Operand size larger than required",
}

def lwasm_lookup_error(code):
    """lwasm_lookup_error(lwasm_errorcode_t) — return error message string."""
    return _ERROR_MESSAGES.get(code, "Error")


# ─────────────────────────────────────────────────────────────────────────────
# LwasmError  (struct lwasm_error_s)
# ─────────────────────────────────────────────────────────────────────────────

class LwasmError:
    """
    struct lwasm_error_s {
        lwasm_errorcode_t code;
        char *mess;
        int   charpos;
        lwasm_error_t *next;
    };
    """
    __slots__ = ('code', 'mess', 'charpos', 'next')

    def __init__(self, code, mess, charpos=-1):
        self.code    = code
        self.mess    = mess
        self.charpos = charpos
        self.next    = None   # linked list; NULL in C


# ─────────────────────────────────────────────────────────────────────────────
# LineExpr  (struct line_expr_s)
# ─────────────────────────────────────────────────────────────────────────────

class LineExpr:
    """
    struct line_expr_s {
        lw_expr_t expr;
        int id;
        struct line_expr_s *next;
    };
    Expressions saved on a line during parse, retrieved during resolve/emit.
    """
    __slots__ = ('expr', 'id', 'next')

    def __init__(self, id_, expr):
        self.id   = id_
        self.expr = expr
        self.next = None


# ─────────────────────────────────────────────────────────────────────────────
# RelocTab  (struct reloctab_s)
# ─────────────────────────────────────────────────────────────────────────────

class RelocTab:
    """
    struct reloctab_s {
        lw_expr_t offset;
        int       size;
        lw_expr_t expr;
        reloctab_t *next;
    };
    """
    __slots__ = ('offset', 'size', 'expr', 'next')

    def __init__(self, offset, size, expr):
        self.offset = offset
        self.size   = size
        self.expr   = expr
        self.next   = None


# ─────────────────────────────────────────────────────────────────────────────
# SectionTab  (struct sectiontab_s)
# ─────────────────────────────────────────────────────────────────────────────

class SectionTab:
    """
    struct sectiontab_s {
        char           *name;
        int             flags;
        lw_expr_t       offset;
        int             oblen;
        int             obsize;
        int             tbase;
        unsigned char  *obytes;
        reloctab_t     *reloctab;
        sectiontab_t   *next;
    };
    obytes is bytearray in Python (replaces unsigned char*).
    """
    __slots__ = ('name', 'flags', 'offset', 'oblen', 'obsize',
                 'tbase', 'obytes', 'reloctab', 'next')

    def __init__(self, name, flags=section_flag_none):
        self.name     = name
        self.flags    = flags
        self.offset   = None    # lw_expr_t — set by assembler
        self.oblen    = 0
        self.obsize   = 0
        self.tbase    = -1      # -1 means "not set"; matches C init
        self.obytes   = bytearray()
        self.reloctab = None
        self.next     = None


# ─────────────────────────────────────────────────────────────────────────────
# SymTabEntry  (struct symtabe)
# ─────────────────────────────────────────────────────────────────────────────

class SymTabEntry:
    """
    struct symtabe {
        char          *symbol;
        int            context;
        int            version;
        int            flags;
        sectiontab_t  *section;
        lw_expr_t      value;
        struct symtabe *left;
        struct symtabe *right;
        struct symtabe *nextver;
    };
    Binary search tree node.  Multiple versions (SET) are linked via nextver.
    """
    __slots__ = ('symbol', 'context', 'version', 'flags', 'section',
                 'value', 'left', 'right', 'nextver')

    def __init__(self, symbol, value, context=-1, version=-1,
                 flags=symbol_flag_none, section=None):
        self.symbol  = symbol
        self.value   = value
        self.context = context
        self.version = version
        self.flags   = flags
        self.section = section
        self.left    = None
        self.right   = None
        self.nextver = None


# ─────────────────────────────────────────────────────────────────────────────
# SymTab  (typedef struct { struct symtabe *head; } symtab_t)
# ─────────────────────────────────────────────────────────────────────────────

class SymTab:
    """symtab_t — wrapper around the symbol tree root pointer."""
    __slots__ = ('head',)

    def __init__(self):
        self.head = None


# ─────────────────────────────────────────────────────────────────────────────
# ExportListEntry  (struct exportlist_s)
# ─────────────────────────────────────────────────────────────────────────────

class ExportListEntry:
    """
    struct exportlist_s {
        char           *symbol;
        struct symtabe *se;
        line_t         *line;
        exportlist_t   *next;
    };
    """
    __slots__ = ('symbol', 'se', 'line', 'next')

    def __init__(self, symbol, se, line):
        self.symbol = symbol
        self.se     = se
        self.line   = line
        self.next   = None


# ─────────────────────────────────────────────────────────────────────────────
# ImportListEntry  (struct importlist_s)
# ─────────────────────────────────────────────────────────────────────────────

class ImportListEntry:
    """
    struct importlist_s {
        char          *symbol;
        importlist_t  *next;
    };
    """
    __slots__ = ('symbol', 'next')

    def __init__(self, symbol):
        self.symbol = symbol
        self.next   = None


# ─────────────────────────────────────────────────────────────────────────────
# MacroTab  (struct macrotab_s)
# ─────────────────────────────────────────────────────────────────────────────

class MacroTab:
    """
    struct macrotab_s {
        char       *name;
        char      **lines;
        int         numlines;
        int         flags;
        macrotab_t *next;
        line_t     *definedat;
    };
    lines is a list of strings in Python.
    """
    __slots__ = ('name', 'lines', 'flags', 'next', 'definedat')

    def __init__(self, name, flags=0):
        self.name      = name
        self.lines     = []     # list of str (replaces char**)
        self.flags     = flags
        self.next      = None
        self.definedat = None


# ─────────────────────────────────────────────────────────────────────────────
# StructTabField  (struct structtab_field_s)
# ─────────────────────────────────────────────────────────────────────────────

class StructTabField:
    """
    struct structtab_field_s {
        char               *name;
        int                 size;
        structtab_t        *substruct;
        structtab_field_t  *next;
    };
    """
    __slots__ = ('name', 'size', 'substruct', 'next')

    def __init__(self, name, size, substruct=None):
        self.name      = name
        self.size      = size
        self.substruct = substruct
        self.next      = None


# ─────────────────────────────────────────────────────────────────────────────
# StructTab  (struct structtab_s)
# ─────────────────────────────────────────────────────────────────────────────

class StructTab:
    """
    struct structtab_s {
        char               *name;
        int                 size;
        structtab_field_t  *fields;
        structtab_t        *next;
        line_t             *definedat;
    };
    """
    __slots__ = ('name', 'size', 'fields', 'next', 'definedat')

    def __init__(self, name):
        self.name      = name
        self.size      = 0
        self.fields    = None
        self.next      = None
        self.definedat = None
