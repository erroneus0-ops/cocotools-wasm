"""
cocotools — CoCo assembly and disk image toolkit
"""
from .lwasm import assemble, AsmError
from .diagnostics import DiagnosticLog, W_UNDEFINED_PREDEC1_SU, W_CC_CLOBBERED_BEFORE_BRANCH
