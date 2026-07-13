"""
cocotools — CoCo assembly and disk image toolkit
"""
# NOTE: cocotools/lwasm.py is an earlier, self-contained prototype that is
# NOT used by the real cocotools.py CLI (which imports pass1/passes/
# lwasm_core/input_system directly) and has not been through the lwasm
# translation audit. It previously was, unintentionally, the only thing
# this __init__.py exported as `assemble` -- meaning `from cocotools import
# assemble` silently returned a different, unaudited implementation than
# the one the CLI actually runs. Exporting the real pipeline here instead.
from .lwasm_core     import AsmState
from .input_system   import InputSystem
from .pass1          import do_pass1
from .passes         import assemble, collect_decb_bytes
from .diagnostics import DiagnosticLog, W_UNDEFINED_PREDEC1_SU, W_CC_CLOBBERED_BEFORE_BRANCH
from .source_diag import analyze_source

# AsmError is kept for backward compatibility with any existing code that
# imports it from here; it originates in the old lwasm.py prototype.
from .lwasm import AsmError
