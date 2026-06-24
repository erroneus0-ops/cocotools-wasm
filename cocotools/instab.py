"""
cocotools/instab.py — Instruction table
Faithful Python translation of lwasm/instab.c (William Astle, LWTools, GPL v3)
Source: http://lwtools.projects.l-w.ca/

INSTAB is a list of InstaEntry objects in the same order as instab.c.
Each entry's index in the list is the opnum stored in Line.insn.

ops[4] layout (same as C):
    ops[0] = DIR  (direct page)
    ops[1] = IDX  (indexed)
    ops[2] = EXT  (extended)
    ops[3] = IMM  (immediate)
    -1 = not supported for that mode

For inh:    ops[0]=opcode, rest=-1
For relgen: ops[0]=base, ops[1]=natural_size(8/16), ops[2]=short, ops[3]=long
For lbxx:   ops[1]=16 (force long branch)
"""


class InstaEntry:
    """Mirrors instab_t { char *opcode; int ops[4]; parse; resolve; emit; flags }"""
    __slots__ = ('opcode', 'ops', 'flags', 'parse', 'resolve', 'emit', 'opnum')

    def __init__(self, opcode, ops, flags, parse, resolve, emit):
        self.opcode  = opcode
        self.ops     = ops
        self.flags   = flags
        self.parse   = parse
        self.resolve = resolve
        self.emit    = emit
        self.opnum   = 0   # set after list construction


# ── Import all parse/resolve/emit functions ───────────────────────────────────

from .insn_funcs import (
    insn_parse_inh,    insn_resolve_inh,    insn_emit_inh,
    insn_parse_inh6800,insn_resolve_inh6800,insn_emit_inh6800,
    insn_parse_gen8,   insn_resolve_gen8,   insn_emit_gen8,
    insn_parse_gen16,  insn_resolve_gen16,  insn_emit_gen16,
    insn_parse_gen32,  insn_resolve_gen32,  insn_emit_gen32,
    insn_parse_gen0,   insn_resolve_gen0,   insn_emit_gen0,
    insn_parse_imm8,   insn_resolve_imm8,   insn_emit_imm8,
    insn_parse_andcc,  insn_parse_orcc,
    insn_parse_rel8,   insn_resolve_rel8,   insn_emit_rel8,
    insn_parse_rel16,  insn_resolve_rel16,  insn_emit_rel16,
    insn_parse_relgen, insn_resolve_relgen, insn_emit_relgen,
    insn_parse_rtor,   insn_resolve_rtor,   insn_emit_rtor,
    insn_parse_rlist,  insn_resolve_rlist,  insn_emit_rlist,
    insn_parse_indexed,insn_resolve_indexed,insn_emit_indexed,
    insn_parse_logicmem,insn_resolve_logicmem,insn_emit_logicmem,
    insn_parse_conv,   insn_resolve_conv,   insn_emit_conv,
    insn_parse_tfm,    insn_resolve_tfm,    insn_emit_tfm,
    insn_parse_tfmrtor,insn_resolve_tfmrtor,insn_emit_tfmrtor,
    insn_parse_bitbit, insn_resolve_bitbit, insn_emit_bitbit,
)
from .pseudo import (
    pseudo_parse_org,   pseudo_resolve_org,   pseudo_emit_org,
    pseudo_parse_reorg, pseudo_resolve_reorg, pseudo_emit_reorg,
    pseudo_parse_phase, pseudo_resolve_phase, pseudo_emit_phase,
    pseudo_parse_dephase,pseudo_resolve_dephase,pseudo_emit_dephase,
    pseudo_parse_equ,   pseudo_resolve_equ,   pseudo_emit_equ,
    pseudo_parse_set,   pseudo_resolve_set,   pseudo_emit_set,
    pseudo_parse_end,   pseudo_resolve_end,   pseudo_emit_end,
    pseudo_parse_fcb,   pseudo_resolve_fcb,   pseudo_emit_fcb,
    pseudo_parse_fdb,   pseudo_resolve_fdb,   pseudo_emit_fdb,
    pseudo_parse_fdbs,  pseudo_resolve_fdbs,  pseudo_emit_fdbs,
    pseudo_parse_fqb,   pseudo_resolve_fqb,   pseudo_emit_fqb,
    pseudo_parse_fcc,   pseudo_resolve_fcc,   pseudo_emit_fcc,
    pseudo_parse_fcn,   pseudo_resolve_fcn,   pseudo_emit_fcn,
    pseudo_parse_fcs,   pseudo_resolve_fcs,   pseudo_emit_fcs,
    pseudo_parse_rmb,   pseudo_resolve_rmb,   pseudo_emit_rmb,
    pseudo_parse_rmd,   pseudo_resolve_rmd,   pseudo_emit_rmd,
    pseudo_parse_zmb,   pseudo_resolve_zmb,   pseudo_emit_zmb,
    pseudo_parse_setdp, pseudo_resolve_setdp, pseudo_emit_setdp,
    pseudo_parse_align, pseudo_resolve_align, pseudo_emit_align,
    pseudo_parse_fill,  pseudo_resolve_fill,  pseudo_emit_fill,
    pseudo_parse_include,pseudo_resolve_include,pseudo_emit_include,
    pseudo_parse_includebin,pseudo_resolve_includebin,pseudo_emit_includebin,
    pseudo_parse_includestr,pseudo_resolve_includestr,pseudo_emit_includestr,
    pseudo_parse_error, pseudo_resolve_error, pseudo_emit_error,
    pseudo_parse_warning,pseudo_resolve_warning,pseudo_emit_warning,
    pseudo_parse_noop,  pseudo_resolve_noop,  pseudo_emit_noop,
    pseudo_parse_macro, pseudo_resolve_macro, pseudo_emit_macro,
    pseudo_parse_endm,  pseudo_resolve_endm,  pseudo_emit_endm,
    pseudo_parse_ifeq,  pseudo_resolve_ifeq,  pseudo_emit_ifeq,
    pseudo_parse_ifne,  pseudo_resolve_ifne,  pseudo_emit_ifne,
    pseudo_parse_if,    pseudo_resolve_if,    pseudo_emit_if,
    pseudo_parse_ifgt,  pseudo_resolve_ifgt,  pseudo_emit_ifgt,
    pseudo_parse_ifge,  pseudo_resolve_ifge,  pseudo_emit_ifge,
    pseudo_parse_iflt,  pseudo_resolve_iflt,  pseudo_emit_iflt,
    pseudo_parse_ifle,  pseudo_resolve_ifle,  pseudo_emit_ifle,
    pseudo_parse_endc,  pseudo_resolve_endc,  pseudo_emit_endc,
    pseudo_parse_endif, pseudo_resolve_endif, pseudo_emit_endif,
    pseudo_parse_else,  pseudo_resolve_else,  pseudo_emit_else,
    pseudo_parse_ifdef, pseudo_resolve_ifdef, pseudo_emit_ifdef,
    pseudo_parse_ifndef,pseudo_resolve_ifndef,pseudo_emit_ifndef,
    pseudo_parse_ifpragma,pseudo_resolve_ifpragma,pseudo_emit_ifpragma,
    pseudo_parse_ifstr, pseudo_resolve_ifstr, pseudo_emit_ifstr,
    pseudo_parse_ifp1,  pseudo_resolve_ifp1,  pseudo_emit_ifp1,
    pseudo_parse_ifp2,  pseudo_resolve_ifp2,  pseudo_emit_ifp2,
    pseudo_parse_section,pseudo_resolve_section,pseudo_emit_section,
    pseudo_parse_endsection,pseudo_resolve_endsection,pseudo_emit_endsection,
    pseudo_parse_struct,pseudo_resolve_struct,pseudo_emit_struct,
    pseudo_parse_endstruct,pseudo_resolve_endstruct,pseudo_emit_endstruct,
    pseudo_parse_extern,pseudo_resolve_extern,pseudo_emit_extern,
    pseudo_parse_export,pseudo_resolve_export,pseudo_emit_export,
    pseudo_parse_extdep,pseudo_resolve_extdep,pseudo_emit_extdep,
    pseudo_parse_pragma,pseudo_resolve_pragma,pseudo_emit_pragma,
    pseudo_parse_starpragma,pseudo_resolve_starpragma,pseudo_emit_starpragma,
    pseudo_parse_starpragmapush,pseudo_resolve_starpragmapush,pseudo_emit_starpragmapush,
    pseudo_parse_starpragmapop, pseudo_resolve_starpragmapop, pseudo_emit_starpragmapop,
    pseudo_parse_setstr,pseudo_resolve_setstr,pseudo_emit_setstr,
    pseudo_parse_os9,   pseudo_resolve_os9,   pseudo_emit_os9,
    pseudo_parse_mod,   pseudo_resolve_mod,   pseudo_emit_mod,
    pseudo_parse_emod,  pseudo_resolve_emod,  pseudo_emit_emod,
    pseudo_parse_dts,   pseudo_resolve_dts,   pseudo_emit_dts,
    pseudo_parse_dtb,   pseudo_resolve_dtb,   pseudo_emit_dtb,
)

# instab flag constants (from instab.h)
N  = 0           # lwasm_insn_normal
C  = 1           # lwasm_insn_cond
EM = 1 << 1      # lwasm_insn_endm
SS = 1 << 2      # lwasm_insn_setsym
I9 = 1 << 3      # lwasm_insn_is6309
ST = 1 << 4      # lwasm_insn_struct
SD = 1 << 5      # lwasm_insn_setdata
I8 = 1 << 6      # lwasm_insn_is6800
I809 = 1 << 7    # lwasm_insn_is6809
C9  = 1 << 8     # lwasm_insn_is6809conv
C39 = 1 << 9     # lwasm_insn_is6309conv
EE  = 1 << 10    # lwasm_insn_isemuext
OR  = 1 << 11    # lwasm_insn_org

def _e(op, ops, flags, pf, rf, ef):
    return InstaEntry(op, ops, flags, pf, rf, ef)

# Shorthand aliases
inh   = (insn_parse_inh,    insn_resolve_inh,    insn_emit_inh)
i68   = (insn_parse_inh6800,insn_resolve_inh6800,insn_emit_inh6800)
g8    = (insn_parse_gen8,   insn_resolve_gen8,   insn_emit_gen8)
g16   = (insn_parse_gen16,  insn_resolve_gen16,  insn_emit_gen16)
g32   = (insn_parse_gen32,  insn_resolve_gen32,  insn_emit_gen32)
g0    = (insn_parse_gen0,   insn_resolve_gen0,   insn_emit_gen0)
i8    = (insn_parse_imm8,   insn_resolve_imm8,   insn_emit_imm8)
rr    = (insn_parse_rtor,   insn_resolve_rtor,   insn_emit_rtor)
rl    = (insn_parse_rlist,  insn_resolve_rlist,  insn_emit_rlist)
idx   = (insn_parse_indexed,insn_resolve_indexed,insn_emit_indexed)
rg    = (insn_parse_relgen, insn_resolve_relgen, insn_emit_relgen)
r8    = (insn_parse_rel8,   insn_resolve_rel8,   insn_emit_rel8)
r16   = (insn_parse_rel16,  insn_resolve_rel16,  insn_emit_rel16)
lm    = (insn_parse_logicmem,insn_resolve_logicmem,insn_emit_logicmem)
bb    = (insn_parse_bitbit, insn_resolve_bitbit, insn_emit_bitbit)
cv    = (insn_parse_conv,   insn_resolve_conv,   insn_emit_conv)
tfm_  = (insn_parse_tfm,    insn_resolve_tfm,    insn_emit_tfm)
tfmr  = (insn_parse_tfmrtor,insn_resolve_tfmrtor,insn_emit_tfmrtor)
ac    = (insn_parse_andcc,  insn_resolve_imm8,   insn_emit_imm8)
oc    = (insn_parse_orcc,   insn_resolve_imm8,   insn_emit_imm8)

# pseudo shorthands
def _ps(pf, rf, ef): return (pf, rf, ef)
org_  = _ps(pseudo_parse_org,    pseudo_resolve_org,    pseudo_emit_org)
reorg_= _ps(pseudo_parse_reorg,  pseudo_resolve_reorg,  pseudo_emit_reorg)
ph_   = _ps(pseudo_parse_phase,  pseudo_resolve_phase,  pseudo_emit_phase)
dp_   = _ps(pseudo_parse_dephase,pseudo_resolve_dephase,pseudo_emit_dephase)
eq_   = _ps(pseudo_parse_equ,    pseudo_resolve_equ,    pseudo_emit_equ)
st_   = _ps(pseudo_parse_set,    pseudo_resolve_set,    pseudo_emit_set)
end_  = _ps(pseudo_parse_end,    pseudo_resolve_end,    pseudo_emit_end)
fcb_  = _ps(pseudo_parse_fcb,    pseudo_resolve_fcb,    pseudo_emit_fcb)
fdb_  = _ps(pseudo_parse_fdb,    pseudo_resolve_fdb,    pseudo_emit_fdb)
fdbs_ = _ps(pseudo_parse_fdbs,   pseudo_resolve_fdbs,   pseudo_emit_fdbs)
fqb_  = _ps(pseudo_parse_fqb,    pseudo_resolve_fqb,    pseudo_emit_fqb)
fcc_  = _ps(pseudo_parse_fcc,    pseudo_resolve_fcc,    pseudo_emit_fcc)
fcn_  = _ps(pseudo_parse_fcn,    pseudo_resolve_fcn,    pseudo_emit_fcn)
fcs_  = _ps(pseudo_parse_fcs,    pseudo_resolve_fcs,    pseudo_emit_fcs)
rmb_  = _ps(pseudo_parse_rmb,    pseudo_resolve_rmb,    pseudo_emit_rmb)
rmd_  = _ps(pseudo_parse_rmd,    pseudo_resolve_rmd,    pseudo_emit_rmd)
zmb_  = _ps(pseudo_parse_zmb,    pseudo_resolve_zmb,    pseudo_emit_zmb)
sdp_  = _ps(pseudo_parse_setdp,  pseudo_resolve_setdp,  pseudo_emit_setdp)
al_   = _ps(pseudo_parse_align,  pseudo_resolve_align,  pseudo_emit_align)
fi_   = _ps(pseudo_parse_fill,   pseudo_resolve_fill,   pseudo_emit_fill)
inc_  = _ps(pseudo_parse_include,pseudo_resolve_include,pseudo_emit_include)
ibin_ = _ps(pseudo_parse_includebin,pseudo_resolve_includebin,pseudo_emit_includebin)
istr_ = _ps(pseudo_parse_includestr,pseudo_resolve_includestr,pseudo_emit_includestr)
err_  = _ps(pseudo_parse_error,  pseudo_resolve_error,  pseudo_emit_error)
wrn_  = _ps(pseudo_parse_warning,pseudo_resolve_warning,pseudo_emit_warning)
nop_  = _ps(pseudo_parse_noop,   pseudo_resolve_noop,   pseudo_emit_noop)
mac_  = _ps(pseudo_parse_macro,  pseudo_resolve_macro,  pseudo_emit_macro)
endm_ = _ps(pseudo_parse_endm,   pseudo_resolve_endm,   pseudo_emit_endm)
ifeq__= _ps(pseudo_parse_ifeq,   pseudo_resolve_ifeq,   pseudo_emit_ifeq)
ifne__= _ps(pseudo_parse_ifne,   pseudo_resolve_ifne,   pseudo_emit_ifne)
if__  = _ps(pseudo_parse_if,     pseudo_resolve_if,     pseudo_emit_if)
ifgt__= _ps(pseudo_parse_ifgt,   pseudo_resolve_ifgt,   pseudo_emit_ifgt)
ifge__= _ps(pseudo_parse_ifge,   pseudo_resolve_ifge,   pseudo_emit_ifge)
iflt__= _ps(pseudo_parse_iflt,   pseudo_resolve_iflt,   pseudo_emit_iflt)
ifle__= _ps(pseudo_parse_ifle,   pseudo_resolve_ifle,   pseudo_emit_ifle)
endc_ = _ps(pseudo_parse_endc,   pseudo_resolve_endc,   pseudo_emit_endc)
endif_= _ps(pseudo_parse_endif,  pseudo_resolve_endif,  pseudo_emit_endif)
else_ = _ps(pseudo_parse_else,   pseudo_resolve_else,   pseudo_emit_else)
ifdf_ = _ps(pseudo_parse_ifdef,  pseudo_resolve_ifdef,  pseudo_emit_ifdef)
ifnd_ = _ps(pseudo_parse_ifndef, pseudo_resolve_ifndef, pseudo_emit_ifndef)
ifpg_ = _ps(pseudo_parse_ifpragma,pseudo_resolve_ifpragma,pseudo_emit_ifpragma)
ifst_ = _ps(pseudo_parse_ifstr,  pseudo_resolve_ifstr,  pseudo_emit_ifstr)
ifp1_ = _ps(pseudo_parse_ifp1,   pseudo_resolve_ifp1,   pseudo_emit_ifp1)
ifp2_ = _ps(pseudo_parse_ifp2,   pseudo_resolve_ifp2,   pseudo_emit_ifp2)
sec_  = _ps(pseudo_parse_section,pseudo_resolve_section,pseudo_emit_section)
esec_ = _ps(pseudo_parse_endsection,pseudo_resolve_endsection,pseudo_emit_endsection)
str_  = _ps(pseudo_parse_struct, pseudo_resolve_struct, pseudo_emit_struct)
estr_ = _ps(pseudo_parse_endstruct,pseudo_resolve_endstruct,pseudo_emit_endstruct)
ext_  = _ps(pseudo_parse_extern, pseudo_resolve_extern, pseudo_emit_extern)
exp_  = _ps(pseudo_parse_export, pseudo_resolve_export, pseudo_emit_export)
exd_  = _ps(pseudo_parse_extdep, pseudo_resolve_extdep, pseudo_emit_extdep)
prg_  = _ps(pseudo_parse_pragma, pseudo_resolve_pragma, pseudo_emit_pragma)
sprg_ = _ps(pseudo_parse_starpragma,pseudo_resolve_starpragma,pseudo_emit_starpragma)
spp_  = _ps(pseudo_parse_starpragmapush,pseudo_resolve_starpragmapush,pseudo_emit_starpragmapush)
spop_ = _ps(pseudo_parse_starpragmapop, pseudo_resolve_starpragmapop, pseudo_emit_starpragmapop)
sstr_ = _ps(pseudo_parse_setstr, pseudo_resolve_setstr, pseudo_emit_setstr)
os9_  = _ps(pseudo_parse_os9,    pseudo_resolve_os9,    pseudo_emit_os9)
mod_  = _ps(pseudo_parse_mod,    pseudo_resolve_mod,    pseudo_emit_mod)
emod_ = _ps(pseudo_parse_emod,   pseudo_resolve_emod,   pseudo_emit_emod)
dts_  = _ps(pseudo_parse_dts,    pseudo_resolve_dts,    pseudo_emit_dts)
dtb_  = _ps(pseudo_parse_dtb,    pseudo_resolve_dtb,    pseudo_emit_dtb)

def _I(op, ops, flags, funcs):
    return InstaEntry(op, ops, flags, funcs[0], funcs[1], funcs[2])

# ── Full instruction table — faithful translation of instab.c ─────────────────
INSTAB = [
# 6309 conv
_I('negq',   [-1,     -1,     -1,     12    ], I9|C39,cv),
_I('tstq',   [0x10ed, 0x7c,   -1,      9    ], I9|C39,cv),
# emulator extensions
_I('break',  [0x113e, -1,     -1,     -1    ], EE,    inh),
_I('log',    [0x103e, -1,     -1,     -1    ], EE,    inh),
# main 6809 instruction set (alphabetical)
_I('abx',    [0x3a,   -1,     -1,     -1    ], N,     inh),
_I('adca',   [0x99,   0xa9,   0xb9,   0x89  ], N,     g8),
_I('adcb',   [0xd9,   0xe9,   0xf9,   0xc9  ], N,     g8),
_I('adcd',   [0x1099, 0x10a9, 0x10b9, 0x1089], I9,    g16),
_I('adcr',   [0x1031, -1,     -1,     -1    ], I9,    rr),
_I('adda',   [0x9b,   0xab,   0xbb,   0x8b  ], N,     g8),
_I('addb',   [0xdb,   0xeb,   0xfb,   0xcb  ], N,     g8),
_I('addd',   [0xd3,   0xe3,   0xf3,   0xc3  ], N,     g16),
_I('adde',   [0x119b, 0x11ab, 0x11bb, 0x118b], I9,    g8),
_I('addf',   [0x11db, 0x11eb, 0x11fb, 0x11cb], I9,    g8),
_I('addr',   [0x1030, -1,     -1,     -1    ], I9,    rr),
_I('addw',   [0x109b, 0x10ab, 0x10bb, 0x108b], I9,    g16),
_I('aim',    [0x02,   0x62,   0x72,   -1    ], I9,    lm),
_I('anda',   [0x94,   0xa4,   0xb4,   0x84  ], N,     g8),
_I('andb',   [0xd4,   0xe4,   0xf4,   0xc4  ], N,     g8),
_I('andcc',  [0x1c,   -1,     -1,     0x1c  ], N,     ac),
_I('andd',   [0x1094, 0x10a4, 0x10b4, 0x1084], I9,    g16),
_I('andr',   [0x1034, -1,     -1,     -1    ], I9,    rr),
_I('asl',    [0x08,   0x68,   0x78,   -1    ], N,     g0),
_I('asla',   [0x48,   -1,     -1,     -1    ], N,     inh),
_I('aslb',   [0x58,   -1,     -1,     -1    ], N,     inh),
_I('asld',   [0x1048, -1,     -1,     -1    ], I9,    inh),
_I('asr',    [0x07,   0x67,   0x77,   -1    ], N,     g0),
_I('asra',   [0x47,   -1,     -1,     -1    ], N,     inh),
_I('asrb',   [0x57,   -1,     -1,     -1    ], N,     inh),
_I('asrd',   [0x1047, -1,     -1,     -1    ], I9,    inh),
_I('band',   [0x1130, -1,     -1,     -1    ], I9,    bb),
_I('bcc',    [0x24,    8,     0x24, 0x1024  ], N,     rg),
_I('bcs',    [0x25,    8,     0x25, 0x1025  ], N,     rg),
_I('beor',   [0x1134, -1,     -1,     -1    ], I9,    bb),
_I('beq',    [0x27,    8,     0x27, 0x1027  ], N,     rg),
_I('bge',    [0x2c,    8,     0x2c, 0x102c  ], N,     rg),
_I('bgt',    [0x2e,    8,     0x2e, 0x102e  ], N,     rg),
_I('bhi',    [0x22,    8,     0x22, 0x1022  ], N,     rg),
_I('bhs',    [0x24,    8,     0x24, 0x1024  ], N,     rg),
_I('biand',  [0x1131, -1,     -1,     -1    ], I9,    bb),
_I('bieor',  [0x1135, -1,     -1,     -1    ], I9,    bb),
_I('bior',   [0x1133, -1,     -1,     -1    ], I9,    bb),
_I('bita',   [0x95,   0xa5,   0xb5,   0x85  ], N,     g8),
_I('bitb',   [0xd5,   0xe5,   0xf5,   0xc5  ], N,     g8),
_I('bitd',   [0x1095, 0x10a5, 0x10b5, 0x1085], I9,    g16),
_I('bitmd',  [0x113c, -1,     -1,     0x113c], I9,    i8),
_I('ble',    [0x2f,    8,     0x2f, 0x102f  ], N,     rg),
_I('blo',    [0x25,    8,     0x25, 0x1025  ], N,     rg),
_I('bls',    [0x23,    8,     0x23, 0x1023  ], N,     rg),
_I('blt',    [0x2d,    8,     0x2d, 0x102d  ], N,     rg),
_I('bmi',    [0x2b,    8,     0x2b, 0x102b  ], N,     rg),
_I('bne',    [0x26,    8,     0x26, 0x1026  ], N,     rg),
_I('bor',    [0x1132, -1,     -1,     -1    ], I9,    bb),
_I('bpl',    [0x2a,    8,     0x2a, 0x102a  ], N,     rg),
_I('bra',    [0x20,    8,     0x20,   0x16  ], N,     rg),
_I('brn',    [0x21,    8,     0x21, 0x1021  ], N,     rg),
_I('bsr',    [0x8d,    8,     0x8d,   0x17  ], N,     rg),
_I('bvc',    [0x28,    8,     0x28, 0x1028  ], N,     rg),
_I('bvs',    [0x29,    8,     0x29, 0x1029  ], N,     rg),
_I('clr',    [0x0f,   0x6f,   0x7f,   -1    ], N,     g0),
_I('clra',   [0x4f,   -1,     -1,     -1    ], N,     inh),
_I('clrb',   [0x5f,   -1,     -1,     -1    ], N,     inh),
_I('clrd',   [0x104f, -1,     -1,     -1    ], I9,    inh),
_I('clre',   [0x114f, -1,     -1,     -1    ], I9,    inh),
_I('clrf',   [0x115f, -1,     -1,     -1    ], I9,    inh),
_I('clrw',   [0x105f, -1,     -1,     -1    ], I9,    inh),
_I('cmpa',   [0x91,   0xa1,   0xb1,   0x81  ], N,     g8),
_I('cmpb',   [0xd1,   0xe1,   0xf1,   0xc1  ], N,     g8),
_I('cmpd',   [0x1093, 0x10a3, 0x10b3, 0x1083], N,     g16),
_I('cmpe',   [0x1191, 0x11a1, 0x11b1, 0x1181], I9,    g8),
_I('cmpf',   [0x11d1, 0x11e1, 0x11f1, 0x11c1], I9,    g8),
_I('cmpr',   [0x1037, -1,     -1,     -1    ], I9,    rr),
_I('cmps',   [0x119c, 0x11ac, 0x11bc, 0x118c], N,     g16),
_I('cmpu',   [0x1193, 0x11a3, 0x11b3, 0x1183], N,     g16),
_I('cmpw',   [0x1091, 0x10a1, 0x10b1, 0x1081], I9,    g16),
_I('cmpx',   [0x9c,   0xac,   0xbc,   0x8c  ], N,     g16),
_I('cmpy',   [0x109c, 0x10ac, 0x10bc, 0x108c], N,     g16),
_I('com',    [0x03,   0x63,   0x73,   -1    ], N,     g0),
_I('coma',   [0x43,   -1,     -1,     -1    ], N,     inh),
_I('comb',   [0x53,   -1,     -1,     -1    ], N,     inh),
_I('comd',   [0x1043, -1,     -1,     -1    ], I9,    inh),
_I('come',   [0x1143, -1,     -1,     -1    ], I9,    inh),
_I('comf',   [0x1153, -1,     -1,     -1    ], I9,    inh),
_I('comw',   [0x1053, -1,     -1,     -1    ], I9,    inh),
_I('cwai',   [0x3c,   -1,     -1,     -1    ], N,     ac),
_I('daa',    [0x19,   -1,     -1,     -1    ], N,     inh),
_I('dec',    [0x0a,   0x6a,   0x7a,   -1    ], N,     g0),
_I('deca',   [0x4a,   -1,     -1,     -1    ], N,     inh),
_I('decb',   [0x5a,   -1,     -1,     -1    ], N,     inh),
_I('decd',   [0x104a, -1,     -1,     -1    ], I9,    inh),
_I('dece',   [0x114a, -1,     -1,     -1    ], I9,    inh),
_I('decf',   [0x115a, -1,     -1,     -1    ], I9,    inh),
_I('decw',   [0x105a, -1,     -1,     -1    ], I9,    inh),
_I('divd',   [0x119d, 0x11ad, 0x11bd, 0x118d], I9,    g8),
_I('divq',   [0x119e, 0x11ae, 0x11be, 0x118e], I9,    g16),
_I('eim',    [0x05,   0x65,   0x75,   -1    ], I9,    lm),
_I('eora',   [0x98,   0xa8,   0xb8,   0x88  ], N,     g8),
_I('eorb',   [0xd8,   0xe8,   0xf8,   0xc8  ], N,     g8),
_I('eord',   [0x1098, 0x10a8, 0x10b8, 0x1088], I9,    g16),
_I('eorr',   [0x1036, -1,     -1,     -1    ], I9,    rr),
_I('exg',    [0x1e,   -1,     -1,     -1    ], N,     rr),
_I('hcf',    [0x14,   -1,     -1,     -1    ], I809,  inh),
_I('inc',    [0x0c,   0x6c,   0x7c,   -1    ], N,     g0),
_I('inca',   [0x4c,   -1,     -1,     -1    ], N,     inh),
_I('incb',   [0x5c,   -1,     -1,     -1    ], N,     inh),
_I('incd',   [0x104c, -1,     -1,     -1    ], I9,    inh),
_I('ince',   [0x114c, -1,     -1,     -1    ], I9,    inh),
_I('incf',   [0x115c, -1,     -1,     -1    ], I9,    inh),
_I('incw',   [0x105c, -1,     -1,     -1    ], I9,    inh),
_I('jmp',    [0x0e,   0x6e,   0x7e,   -1    ], N,     g0),
_I('jsr',    [0x9d,   0xad,   0xbd,   -1    ], N,     g0),
_I('lbcc',   [0x1024,  16,    0x24, 0x1024  ], N,     rg),
_I('lbcs',   [0x1025,  16,    0x25, 0x1025  ], N,     rg),
_I('lbeq',   [0x1027,  16,    0x27, 0x1027  ], N,     rg),
_I('lbge',   [0x102c,  16,    0x2c, 0x102c  ], N,     rg),
_I('lbgt',   [0x102e,  16,    0x2e, 0x102e  ], N,     rg),
_I('lbhi',   [0x1022,  16,    0x22, 0x1022  ], N,     rg),
_I('lbhs',   [0x1024,  16,    0x24, 0x1024  ], N,     rg),
_I('lble',   [0x102f,  16,    0x2f, 0x102f  ], N,     rg),
_I('lblo',   [0x1025,  16,    0x25, 0x1025  ], N,     rg),
_I('lbls',   [0x1023,  16,    0x23, 0x1023  ], N,     rg),
_I('lblt',   [0x102d,  16,    0x2d, 0x102d  ], N,     rg),
_I('lbmi',   [0x102b,  16,    0x2b, 0x102b  ], N,     rg),
_I('lbne',   [0x1026,  16,    0x26, 0x1026  ], N,     rg),
_I('lbpl',   [0x102a,  16,    0x2a, 0x102a  ], N,     rg),
_I('lbra',   [0x16,    16,    0x20,   0x16  ], N,     rg),
_I('lbrn',   [0x1021,  16,    0x21, 0x1021  ], N,     rg),
_I('lbsr',   [0x17,    16,    0x8d,   0x17  ], N,     rg),
_I('lbvc',   [0x1028,  16,    0x28, 0x1028  ], N,     rg),
_I('lbvs',   [0x1029,  16,    0x29, 0x1029  ], N,     rg),
_I('lda',    [0x96,   0xa6,   0xb6,   0x86  ], N,     g8),
_I('ldb',    [0xd6,   0xe6,   0xf6,   0xc6  ], N,     g8),
_I('ldbt',   [0x1136, -1,     -1,     -1    ], I9,    bb),
_I('ldd',    [0xdc,   0xec,   0xfc,   0xcc  ], N,     g16),
_I('lde',    [0x1196, 0x11a6, 0x11b6, 0x1186], I9,    g8),
_I('ldf',    [0x11d6, 0x11e6, 0x11f6, 0x11c6], I9,    g8),
_I('ldq',    [0x10dc, 0x10ec, 0x10fc, 0xcd  ], I9,    g32),
_I('lds',    [0x10de, 0x10ee, 0x10fe, 0x10ce], N,     g16),
_I('ldu',    [0xde,   0xee,   0xfe,   0xce  ], N,     g16),
_I('ldw',    [0x1096, 0x10a6, 0x10b6, 0x1086], I9,    g16),
_I('ldx',    [0x9e,   0xae,   0xbe,   0x8e  ], N,     g16),
_I('ldy',    [0x109e, 0x10ae, 0x10be, 0x108e], N,     g16),
_I('ldmd',   [0x113d, -1,     -1,     0x113d], I9,    i8),
_I('leas',   [0x32,   -1,     -1,     -1    ], N,     idx),
_I('leau',   [0x33,   -1,     -1,     -1    ], N,     idx),
_I('leax',   [0x30,   -1,     -1,     -1    ], N,     idx),
_I('leay',   [0x31,   -1,     -1,     -1    ], N,     idx),
_I('lsl',    [0x08,   0x68,   0x78,   -1    ], N,     g0),
_I('lsla',   [0x48,   -1,     -1,     -1    ], N,     inh),
_I('lslb',   [0x58,   -1,     -1,     -1    ], N,     inh),
_I('lsld',   [0x1048, -1,     -1,     -1    ], I9,    inh),
_I('lsr',    [0x04,   0x64,   0x74,   -1    ], N,     g0),
_I('lsra',   [0x44,   -1,     -1,     -1    ], N,     inh),
_I('lsrb',   [0x54,   -1,     -1,     -1    ], N,     inh),
_I('lsrd',   [0x1044, -1,     -1,     -1    ], I9,    inh),
_I('lsrw',   [0x1054, -1,     -1,     -1    ], I9,    inh),
_I('mul',    [0x3d,   -1,     -1,     -1    ], N,     inh),
_I('muld',   [0x119f, 0x11af, 0x11bf, 0x118f], I9,    g16),
_I('neg',    [0x00,   0x60,   0x70,   -1    ], N,     g0),
_I('nega',   [0x40,   -1,     -1,     -1    ], N,     inh),
_I('negb',   [0x50,   -1,     -1,     -1    ], N,     inh),
_I('negd',   [0x1040, -1,     -1,     -1    ], I9,    inh),
_I('nop',    [0x12,   -1,     -1,     -1    ], N,     inh),
_I('oim',    [0x01,   0x61,   0x71,   -1    ], I9,    lm),
_I('ora',    [0x9a,   0xaa,   0xba,   0x8a  ], N,     g8),
_I('orb',    [0xda,   0xea,   0xfa,   0xca  ], N,     g8),
_I('orcc',   [0x1a,   -1,     -1,     0x1a  ], N,     oc),
_I('ord',    [0x109a, 0x10aa, 0x10ba, 0x108a], I9,    g16),
_I('orr',    [0x1035, -1,     -1,     -1    ], I9,    rr),
_I('pshs',   [0x34,   -1,     -1,     -1    ], N,     rl),
_I('pshsw',  [0x1038, -1,     -1,     -1    ], I9,    inh),
_I('pshu',   [0x36,   -1,     -1,     -1    ], N,     rl),
_I('pshuw',  [0x103a, -1,     -1,     -1    ], I9,    inh),
_I('puls',   [0x35,   -1,     -1,     -1    ], N,     rl),
_I('pulsw',  [0x1039, -1,     -1,     -1    ], I9,    inh),
_I('pulu',   [0x37,   -1,     -1,     -1    ], N,     rl),
_I('puluw',  [0x103b, -1,     -1,     -1    ], I9,    inh),
_I('reset',  [0x3e,   -1,     -1,     -1    ], I809,  inh),
_I('rhf',    [0x14,   -1,     -1,     -1    ], I809,  inh),
_I('rol',    [0x09,   0x69,   0x79,   -1    ], N,     g0),
_I('rola',   [0x49,   -1,     -1,     -1    ], N,     inh),
_I('rolb',   [0x59,   -1,     -1,     -1    ], N,     inh),
_I('rold',   [0x1049, -1,     -1,     -1    ], I9,    inh),
_I('rolw',   [0x1059, -1,     -1,     -1    ], I9,    inh),
_I('ror',    [0x06,   0x66,   0x76,   -1    ], N,     g0),
_I('rora',   [0x46,   -1,     -1,     -1    ], N,     inh),
_I('rorb',   [0x56,   -1,     -1,     -1    ], N,     inh),
_I('rord',   [0x1046, -1,     -1,     -1    ], I9,    inh),
_I('rorw',   [0x1056, -1,     -1,     -1    ], I9,    inh),
_I('rti',    [0x3b,   -1,     -1,     -1    ], N,     inh),
_I('rts',    [0x39,   -1,     -1,     -1    ], N,     inh),
_I('sbca',   [0x92,   0xa2,   0xb2,   0x82  ], N,     g8),
_I('sbcb',   [0xd2,   0xe2,   0xf2,   0xc2  ], N,     g8),
_I('sbcd',   [0x1092, 0x10a2, 0x10b2, 0x1082], I9,    g16),
_I('sbcr',   [0x1033, -1,     -1,     -1    ], I9,    rr),
_I('sex',    [0x1d,   -1,     -1,     -1    ], N,     inh),
_I('sexw',   [0x14,   -1,     -1,     -1    ], I9,    inh),
_I('sta',    [0x97,   0xa7,   0xb7,   -1    ], N,     g0),
_I('stb',    [0xd7,   0xe7,   0xf7,   -1    ], N,     g0),
_I('stbt',   [0x1137, -1,     -1,     -1    ], I9,    bb),
_I('std',    [0xdd,   0xed,   0xfd,   -1    ], N,     g0),
_I('ste',    [0x1197, 0x11a7, 0x11b7, -1    ], I9,    g0),
_I('stf',    [0x11d7, 0x11e7, 0x11f7, -1    ], I9,    g0),
_I('stq',    [0x10dd, 0x10ed, 0x10fd, -1    ], I9,    g0),
_I('sts',    [0x10df, 0x10ef, 0x10ff, -1    ], N,     g0),
_I('stu',    [0xdf,   0xef,   0xff,   -1    ], N,     g0),
_I('stw',    [0x1097, 0x10a7, 0x10b7, -1    ], I9,    g0),
_I('stx',    [0x9f,   0xaf,   0xbf,   -1    ], N,     g0),
_I('sty',    [0x109f, 0x10af, 0x10bf, -1    ], N,     g0),
_I('suba',   [0x90,   0xa0,   0xb0,   0x80  ], N,     g8),
_I('subb',   [0xd0,   0xe0,   0xf0,   0xc0  ], N,     g8),
_I('subd',   [0x93,   0xa3,   0xb3,   0x83  ], N,     g16),
_I('sube',   [0x1190, 0x11a0, 0x11b0, 0x1180], I9,    g8),
_I('subf',   [0x11d0, 0x11e0, 0x11f0, 0x11c0], I9,    g8),
_I('subr',   [0x1032, -1,     -1,     -1    ], I9,    rr),
_I('subw',   [0x1090, 0x10a0, 0x10b0, 0x1080], I9,    g16),
_I('swi',    [0x3f,   -1,     -1,     -1    ], N,     inh),
_I('swi2',   [0x103f, -1,     -1,     -1    ], N,     inh),
_I('swi3',   [0x113f, -1,     -1,     -1    ], N,     inh),
_I('sync',   [0x13,   -1,     -1,     -1    ], N,     inh),
_I('tfm',    [0x1138, 0x1139, 0x113a, 0x113b], I9,    tfm_),
_I('copy',   [0x1138, -1,     -1,     -1    ], I9,    tfmr),
_I('copy+',  [0x1138, -1,     -1,     -1    ], I9,    tfmr),
_I('tfrp',   [0x1138, -1,     -1,     -1    ], I9,    tfmr),
_I('copy-',  [0x1139, -1,     -1,     -1    ], I9,    tfmr),
_I('tfrm',   [0x1139, -1,     -1,     -1    ], I9,    tfmr),
_I('imp',    [0x113a, -1,     -1,     -1    ], I9,    tfmr),
_I('implode',[0x113a, -1,     -1,     -1    ], I9,    tfmr),
_I('tfrs',   [0x113a, -1,     -1,     -1    ], I9,    tfmr),
_I('exp',    [0x113b, -1,     -1,     -1    ], I9,    tfmr),
_I('expand', [0x113b, -1,     -1,     -1    ], I9,    tfmr),
_I('tfrr',   [0x113b, -1,     -1,     -1    ], I9,    tfmr),
_I('tfr',    [0x1f,   -1,     -1,     -1    ], N,     rr),
_I('tim',    [0x0b,   0x6b,   0x7b,   -1    ], I9,    lm),
_I('tst',    [0x0d,   0x6d,   0x7d,   -1    ], N,     g0),
_I('tsta',   [0x4d,   -1,     -1,     -1    ], N,     inh),
_I('tstb',   [0x5d,   -1,     -1,     -1    ], N,     inh),
_I('tstd',   [0x104d, -1,     -1,     -1    ], I9,    inh),
_I('tste',   [0x114d, -1,     -1,     -1    ], I9,    inh),
_I('tstf',   [0x115d, -1,     -1,     -1    ], I9,    inh),
_I('tstw',   [0x105d, -1,     -1,     -1    ], I9,    inh),
# directives / pseudo-ops
_I('org',      [-1,-1,-1,-1], OR,       org_),
_I('reorg',    [-1,-1,-1,-1], N,        reorg_),
_I('phase',    [-1,-1,-1,-1], N,        ph_),
_I('dephase',  [-1,-1,-1,-1], N,        dp_),
_I('equ',      [-1,-1,-1,-1], SS,       eq_),
_I('=',        [-1,-1,-1,-1], SS,       eq_),
_I('extern',   [-1,-1,-1,-1], SS,       ext_),
_I('external', [-1,-1,-1,-1], SS,       ext_),
_I('import',   [-1,-1,-1,-1], SS,       ext_),
_I('export',   [-1,-1,-1,-1], SS,       exp_),
_I('extdep',   [-1,-1,-1,-1], SS,       exd_),
_I('rmb',      [-1,-1,-1,-1], ST|SD,    rmb_),
_I('rmd',      [-1,-1,-1,-1], ST|SD,    rmd_),
_I('rmw',      [-1,-1,-1,-1], ST|SD,    rmd_),
_I('rmq',      [-1,-1,-1,-1], ST|SD,    rmd_),  # rmd parse handles rmq too
_I('zmb',      [-1,-1,-1,-1], N,        zmb_),
_I('bsz',      [-1,-1,-1,-1], N,        zmb_),
_I('fzb',      [-1,-1,-1,-1], N,        zmb_),
_I('zmd',      [-1,-1,-1,-1], N,        zmb_),
_I('zmq',      [-1,-1,-1,-1], N,        zmb_),
_I('fcc',      [-1,-1,-1,-1], N,        fcc_),
_I('fcn',      [-1,-1,-1,-1], N,        fcn_),
_I('fcs',      [-1,-1,-1,-1], N,        fcs_),
_I('fcz',      [-1,-1,-1,-1], N,        fcn_),
_I('fcb',      [-1,-1,-1,-1], N,        fcb_),
_I('fdb',      [-1,-1,-1,-1], N,        fdb_),
_I('fdbs',     [-1,-1,-1,-1], N,        fdbs_),
_I('fqb',      [-1,-1,-1,-1], N,        fqb_),
_I('end',      [-1,-1,-1,-1], N,        end_),
_I('includebin',[-1,-1,-1,-1],N,        ibin_),
_I('includestr',[-1,-1,-1,-1],N,        istr_),
_I('include',  [-1,-1,-1,-1], N,        inc_),
_I('incl',     [-1,-1,-1,-1], N,        inc_),
_I('use',      [-1,-1,-1,-1], N,        inc_),
_I('align',    [-1,-1,-1,-1], N,        al_),
_I('fill',     [-1,-1,-1,-1], N,        fi_),
_I('error',    [-1,-1,-1,-1], N,        err_),
_I('warning',  [-1,-1,-1,-1], N,        wrn_),
_I('msg',      [-1,-1,-1,-1], N,        wrn_),
_I('ifp1',     [-1,-1,-1,-1], C,        ifp1_),
_I('ifp2',     [-1,-1,-1,-1], C,        ifp2_),
_I('ifeq',     [-1,-1,-1,-1], C,        ifeq__),
_I('ifne',     [-1,-1,-1,-1], C,        ifne__),
_I('if',       [-1,-1,-1,-1], C,        if__),
_I('ifgt',     [-1,-1,-1,-1], C,        ifgt__),
_I('ifge',     [-1,-1,-1,-1], C,        ifge__),
_I('iflt',     [-1,-1,-1,-1], C,        iflt__),
_I('ifle',     [-1,-1,-1,-1], C,        ifle__),
_I('endc',     [-1,-1,-1,-1], C,        endc_),
_I('endif',    [-1,-1,-1,-1], C,        endif_),
_I('else',     [-1,-1,-1,-1], C,        else_),
_I('ifdef',    [-1,-1,-1,-1], C,        ifdf_),
_I('ifndef',   [-1,-1,-1,-1], C,        ifnd_),
_I('ifpragma', [-1,-1,-1,-1], C,        ifpg_),
_I('ifopt',    [-1,-1,-1,-1], C,        ifpg_),
_I('ifstr',    [-1,-1,-1,-1], C,        ifst_),
_I('macro',    [-1,-1,-1,-1], C|SS,     mac_),
_I('macr',     [-1,-1,-1,-1], C|SS,     mac_),
_I('endm',     [-1,-1,-1,-1], C|SS|EM,  endm_),
_I('setdp',    [-1,-1,-1,-1], N,        sdp_),
_I('setstr',   [-1,-1,-1,-1], N,        sstr_),
_I('set',      [-1,-1,-1,-1], SS,       st_),
_I('section',  [-1,-1,-1,-1], N,        sec_),
_I('sect',     [-1,-1,-1,-1], N,        sec_),
_I('endsect',  [-1,-1,-1,-1], N,        esec_),
_I('endsection',[-1,-1,-1,-1],N,        esec_),
_I('struct',   [-1,-1,-1,-1], N,        str_),
_I('ends',     [-1,-1,-1,-1], ST,       estr_),
_I('endstruct',[-1,-1,-1,-1], ST,       estr_),
_I('pragma',   [-1,-1,-1,-1], N,        prg_),
_I('*pragma',  [-1,-1,-1,-1], N,        sprg_),
_I('**pragma', [-1,-1,-1,-1], N,        sprg_),
_I('opt',      [-1,-1,-1,-1], N,        sprg_),
_I('*pragmapush',[-1,-1,-1,-1],N,       spp_),
_I('*pragmapop', [-1,-1,-1,-1],N,       spop_),
_I('os9',      [-1,-1,-1,-1], N,        os9_),
_I('mod',      [-1,-1,-1,-1], N,        mod_),
_I('emod',     [-1,-1,-1,-1], N,        emod_),
_I('.area',    [-1,-1,-1,-1], N,        sec_),
_I('.globl',   [-1,-1,-1,-1], N,        exp_),
_I('.module',  [-1,-1,-1,-1], N,        nop_),
_I('.4byte',   [-1,-1,-1,-1], N,        fqb_),
_I('.quad',    [-1,-1,-1,-1], N,        fqb_),
_I('.word',    [-1,-1,-1,-1], N,        fdb_),
_I('.dw',      [-1,-1,-1,-1], N,        fdb_),
_I('.byte',    [-1,-1,-1,-1], N,        fcb_),
_I('.db',      [-1,-1,-1,-1], N,        fcb_),
_I('.ascii',   [-1,-1,-1,-1], N,        fcc_),
_I('.str',     [-1,-1,-1,-1], N,        fcc_),
_I('.ascis',   [-1,-1,-1,-1], N,        fcs_),
_I('.strs',    [-1,-1,-1,-1], N,        fcs_),
_I('.asciz',   [-1,-1,-1,-1], N,        fcn_),
_I('.strz',    [-1,-1,-1,-1], N,        fcn_),
_I('.blkb',    [-1,-1,-1,-1], ST|SD,    rmb_),
_I('.ds',      [-1,-1,-1,-1], ST|SD,    rmb_),
_I('.rs',      [-1,-1,-1,-1], ST|SD,    rmb_),
_I('.end',     [-1,-1,-1,-1], N,        end_),
_I('dts',      [-1,-1,-1,-1], N,        dts_),
_I('dtb',      [-1,-1,-1,-1], N,        dtb_),
_I('nam',      [-1,-1,-1,-1], N,        nop_),
_I('pag',      [-1,-1,-1,-1], N,        nop_),
_I('page',     [-1,-1,-1,-1], N,        nop_),
_I('spc',      [-1,-1,-1,-1], N,        nop_),
_I('ttl',      [-1,-1,-1,-1], N,        nop_),
_I('.bank',    [-1,-1,-1,-1], N,        nop_),
# 6800 compat
_I('aba',  [0x3404, 0xabe0, -1,  12], I8, i68),
_I('cba',  [0x3404, 0xa1e0, -1,  12], I8, i68),
_I('clc',  [0x1cfe, -1,     -1,   3], I8, i68),
_I('clf',  [0x1cbf, -1,     -1,   3], I8, i68),
_I('cli',  [0x1cef, -1,     -1,   3], I8, i68),
_I('clif', [0x1caf, -1,     -1,   3], I8, i68),
_I('clv',  [0x1cfd, -1,     -1,   3], I8, i68),
_I('cpx',  [0x9c,   0xac,  0xbc, 0x8c], I8, g16),
_I('des',  [0x327f, -1,     -1,   5], I8, i68),
_I('dex',  [0x301f, -1,     -1,   5], I8, i68),
_I('dey',  [0x313f, -1,     -1,   5], I8, i68),
_I('ins',  [0x3261, -1,     -1,   5], I8, i68),
_I('inx',  [0x3001, -1,     -1,   5], I8, i68),
_I('iny',  [0x3121, -1,     -1,   5], I8, i68),
_I('sba',  [0x3404, 0xa0e0, -1,  12], I8, i68),
_I('sec',  [0x1a01, -1,     -1,   3], I8, i68),
_I('sef',  [0x1a40, -1,     -1,   3], I8, i68),
_I('sei',  [0x1a10, -1,     -1,   3], I8, i68),
_I('seif', [0x1a50, -1,     -1,   3], I8, i68),
_I('sev',  [0x1a02, -1,     -1,   3], I8, i68),
_I('tab',  [0x1f89, 0x4d,   -1,   8], I8, i68),
_I('tap',  [0x1f8a, -1,     -1,   6], I8, i68),
_I('tba',  [0x1f98, 0x4d,   -1,   8], I8, i68),
_I('tpa',  [0x1fa8, -1,     -1,   6], I8, i68),
_I('tsx',  [0x1f41, -1,     -1,   6], I8, i68),
_I('txs',  [0x1f14, -1,     -1,   6], I8, i68),
_I('wai',  [0x3cff, -1,     -1,  22], I8, i68),
]

# Assign opnum to each entry, build fast lookup dict
INSTAB_BY_NAME = {}   # uppercase opcode -> InstaEntry
for _i, _e2 in enumerate(INSTAB):
    _e2.opnum = _i
    INSTAB_BY_NAME[_e2.opcode.upper()] = _e2

