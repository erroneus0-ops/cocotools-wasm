"""
cocotools/make_translation_packages.py

Extracts C functions from lwasm source files and creates per-function
translation packages for the function-level translation project.

Each package contains:
  source.c        -- the C function to translate
  checklist.md    -- pre-filled checklist for this function
  existing.py     -- current Python translation to compare against
  brief.md        -- complete brief for the translation Claude instance

Usage:
  python cocotools/make_translation_packages.py
  python cocotools/make_translation_packages.py --function insn_parse_indexed_aux
  python cocotools/make_translation_packages.py --list
  python cocotools/make_translation_packages.py --all
"""

import os
import re
import sys
import argparse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(REPO_ROOT, 'translation_packages')

# Priority-ordered list: (function_name, c_source_path_relative, python_file)
# Ordered by complexity score (lines * 2 + branches * 3 + gotos * 5)
PRIORITY_FUNCTIONS = [
    ('lw_expr_simplify_l',       'lwtools-4.24/lwlib/lw_expr.c',     'lw_expr.py'),
    ('insn_parse_indexed_aux',   'lwtools-4.24/lwasm/insn_indexed.c', 'insn_funcs.py'),
    ('insn_resolve_indexed_aux', 'lwtools-4.24/lwasm/insn_gen.c',     'insn_funcs.py'),
    ('insn_parse_rlist',         'lwtools-4.24/lwasm/insn_rlist.c',   'insn_funcs.py'),
    ('insn_emit_rlist',          'lwtools-4.24/lwasm/insn_rlist.c',   'insn_funcs.py'),
    ('insn_parse_rtor',          'lwtools-4.24/lwasm/insn_rtor.c',    'insn_funcs.py'),
    ('insn_emit_rtor',           'lwtools-4.24/lwasm/insn_rtor.c',    'insn_funcs.py'),
    ('insn_emit_indexed_aux',    'lwtools-4.24/lwasm/insn_indexed.c', 'insn_funcs.py'),
    ('lw_expr_parse_expr',       'lwtools-4.24/lwlib/lw_expr.c',      'lw_expr.py'),
    ('lw_expr_parse_term',       'lwtools-4.24/lwlib/lw_expr.c',      'lw_expr.py'),
    ('insn_parse_tfm',           'lwtools-4.24/lwasm/insn_tfm.c',     'insn_funcs.py'),
    ('insn_emit_tfm',            'lwtools-4.24/lwasm/insn_tfm.c',     'insn_funcs.py'),
    ('insn_parse_bitbit',        'lwtools-4.24/lwasm/insn_bitbit.c',  'insn_funcs.py'),
    ('insn_emit_bitbit',         'lwtools-4.24/lwasm/insn_bitbit.c',  'insn_funcs.py'),
    ('insn_parse_logicmem',      'lwtools-4.24/lwasm/insn_logicmem.c','insn_funcs.py'),
    ('insn_emit_logicmem',       'lwtools-4.24/lwasm/insn_logicmem.c','insn_funcs.py'),
]


def find_function(source, fname):
    """Extract a named C function. Returns (start_line, end_line, text) or None.
    
    Handles both direct definitions and macro-wrapped definitions:
      void insn_parse_rlist(...)  -- direct
      PARSEFUNC(insn_parse_rlist) -- macro (expands to same thing)
    """
    lines = source.split('\n')
    for i, line in enumerate(lines):
        # Match direct definition OR macro-wrapped definition
        direct  = re.search(r'\b' + re.escape(fname) + r'\s*\(', line)
        macro   = re.search(r'(?:PARSEFUNC|EMITFUNC|RESOLVEFUNC)\s*\(\s*' + re.escape(fname) + r'\s*\)', line)
        if not (direct or macro):
            continue
        if line and line[0].isspace():
            continue
        # Find opening brace
        depth = 0
        brace_line = i
        found = False
        for j in range(i, min(i + 10, len(lines))):
            for ch in lines[j]:
                if ch == '{':
                    depth = 1
                    brace_line = j
                    found = True
                    break
            if found:
                break
        if not found:
            continue
        # Find matching close brace
        j = brace_line
        start_pos = lines[j].index('{') + 1
        in_str = False
        while j < len(lines):
            ln = lines[j] if j > brace_line else lines[j][start_pos:]
            for ch in ln:
                if in_str:
                    if ch == '"':
                        in_str = False
                elif ch == '"':
                    in_str = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return (i + 1, j + 1, '\n'.join(lines[i:j + 1]))
            j += 1
    return None


def analyze_risks(c_text):
    """Analyze C function for translation risk patterns."""
    lines = c_text.split('\n')
    code_lines = [l for l in lines if not l.strip().startswith('//') and l.strip()]

    gotos = [l.strip() for l in code_lines if re.search(r'\bgoto\b', l)]
    masks = [l.strip() for l in code_lines if re.search(r'& 0x[0-9A-Fa-f]+', l)][:6]
    branches = sum(1 for l in code_lines
                   for kw in ['if ', 'else if', 'while ', 'for ', 'switch ', 'case ']
                   if kw in l)
    return {
        'lines':      len(lines),
        'branches':   branches,
        'gotos':      gotos,
        'char_ptr':   any('char **' in l for l in code_lines),
        'div_mod':    any(re.search(r'(?<![/])/(?![/])|[^*]%', l) for l in code_lines),
        'complement': any('~' in l for l in code_lines if not l.strip().startswith('//')),
        'toupper':    any('toupper' in l for l in code_lines),
        'isspace':    any('isspace' in l for l in code_lines),
        'masks':      masks,
    }


def make_checklist(fname, r):
    goto_items = ('\n'.join(f'  - `{g}`' for g in r['gotos'])
                  if r['gotos'] else '  None.')
    mask_items = ('\n'.join(f'  - `{m}`' for m in r['masks'])
                  if r['masks'] else '  None.')
    return f"""# Pre-Translation Checklist: `{fname}`

Metrics: {r['lines']} lines, {r['branches']} branches, {len(r['gotos'])} gotos

## 1. Integer width at assignment sites
Check every assignment destination type.
Bit mask operations found (may need `c_uint8` etc.):
{mask_items}

## 2. Division / modulo
{'**FOUND** -- use `c_trunc_div()` / `c_trunc_mod()` for signed operands.' if r['div_mod'] else 'Not found.'}

## 3. char ** pointer parameters
{'**FOUND** -- pass the same `Ptr` instance through all callers. Do NOT create new Ptr from `p.remaining()`.' if r['char_ptr'] else 'Not found.'}

## 4. goto statements
{goto_items}
Classify each: A=exit (return), B=shared code (helper fn), C=alternate parse (call fn).

## 5. char signedness
{'Low risk -- check comparisons of `*p` > 127.' if r['char_ptr'] else 'Low risk.'}

## 6. Argument evaluation order
Check for `(*p)++` in function argument position.
Python evaluates left-to-right -- verify this matches C behavior.

## 7. Integer promotion
Check compound expressions. Add mask only where C destination type truncates.

## 8. Bitwise complement
{'**FOUND** -- use `c_complement8(v)` for 8-bit, `c_uint16(~v)` for 16-bit.' if r['complement'] else 'Not found.'}

## 9. Register lookup advancement
{'**Check** lookupreg2/3 calls share Ptr correctly.' if r['char_ptr'] else 'N/A.'}

## Character classification
{'`toupper` found -- use `c.upper()` or `c_toupper(c)`' if r['toupper'] else ''}
{'`isspace` found -- use `c_isspace(c)`' if r['isspace'] else ''}

## Interaction risks identified
[ Fill in before translating ]

## Mitigations applied
[ Fill in during translation ]
"""


def make_brief(fname, c_path, py_file, r):
    return f"""# Translation Brief: `{fname}`

## Your task

Produce a faithful Python translation of the C function `{fname}`.

**Translate this faithfully because a learner who cannot distinguish tool
errors from their own errors will incorrectly conclude they are wrong.**

This is a mechanical translation task. The output must match lwasm 4.24
behavior exactly -- same bytes, same errors, same internal state.

## The function

C source: `{c_path}`
Python target: `cocotools/{py_file}`
Size: {r['lines']} lines, {r['branches']} branches, {len(r['gotos'])} gotos

The C function is in `source.c`.
The current Python translation (if any) is in `existing.py`.

## Required reading (in order)

1. `source.c` -- the C function
2. `checklist.md` -- pre-filled risk analysis
3. `existing.py` -- current Python translation to compare
4. `cocotools/TRANSLATION_GUIDE.md` -- full checklist and risk catalog
5. `cocotools/DATA_STRUCTURE_AUDIT.md` -- shared struct reference
6. `cocotools/c_compat.py` -- C compatibility primitives

## Compat primitives

```python
from cocotools.c_compat import (
    c_uint8, c_int8, c_uint16, c_int16,
    c_5bit, c_complement8,
    c_trunc_div, c_trunc_mod,
    c_isspace, c_toupper,
    Ptr,
)
```

## Verification

After translating:
1. Run `python cocotools/test_fidelity.py` -- all 211 tests must pass
2. Add 3+ new test cases covering branches in this function
3. Run `-v` to inspect structural state for new tests

Do not modify existing tests to make them pass.
Fix the translation until the tests pass.

## Reference

lwtools 4.24: http://www.lwtools.ca/hg/index.cgi/file/0baeffe2747f/{c_path}
Repository: https://github.com/erroneus0-ops/SuperComm-disassembled
TRANSLATION_GUIDE: cocotools/TRANSLATION_GUIDE.md
"""


def make_package(fname, c_rel_path, py_file):
    """Create a translation package directory for one function."""
    c_full = os.path.join(REPO_ROOT, c_rel_path)
    if not os.path.exists(c_full):
        print(f"  ERROR: not found: {c_full}")
        return False

    src = open(c_full).read()
    result = find_function(src, fname)
    if result is None:
        print(f"  ERROR: `{fname}` not found in {c_rel_path}")
        return False

    start, end, c_text = result
    risks = analyze_risks(c_text)

    # Find existing Python
    py_full = os.path.join(REPO_ROOT, 'cocotools', py_file)
    existing = f"# {fname} not yet located in cocotools/{py_file}\n"
    if os.path.exists(py_full):
        py_src = open(py_full).read()
        for candidate in [fname,
                          fname.replace('insn_parse_', '_parse_'),
                          fname.replace('insn_resolve_', '_resolve_'),
                          fname.replace('insn_emit_', '_emit_')]:
            m = re.search(r'(def ' + re.escape(candidate) + r'\b.*?)(?=\ndef |\Z)',
                          py_src, re.DOTALL)
            if m:
                existing = m.group(1)
                break

    pkg = os.path.join(OUTPUT_DIR, fname)
    os.makedirs(pkg, exist_ok=True)

    open(os.path.join(pkg, 'source.c'), 'w').write(
        f"/* {fname}\n   {c_rel_path} lines {start}-{end} */\n\n{c_text}\n")
    open(os.path.join(pkg, 'checklist.md'), 'w').write(make_checklist(fname, risks))
    open(os.path.join(pkg, 'existing.py'), 'w').write(
        f"# Current Python translation of {fname}\n# cocotools/{py_file}\n\n{existing}\n")
    open(os.path.join(pkg, 'brief.md'), 'w').write(make_brief(fname, c_rel_path, py_file, risks))

    print(f"  OK  translation_packages/{fname}/  "
          f"({risks['lines']} lines, {risks['branches']} branches, {len(risks['gotos'])} gotos)")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--function', '-f', metavar='NAME',
                    help='Create package for one named function')
    ap.add_argument('--list', '-l', action='store_true',
                    help='List priority-ordered functions')
    ap.add_argument('--all', '-a', action='store_true',
                    help='Create packages for all priority functions')
    args = ap.parse_args()

    if args.list:
        print(f"Priority-ordered functions ({len(PRIORITY_FUNCTIONS)} total):\n")
        print(f"{'#':<4} {'Function':<40} {'C source':<40} {'Python'}")
        print('-' * 105)
        for i, (f, c, p) in enumerate(PRIORITY_FUNCTIONS, 1):
            print(f"{i:<4} {f:<40} {c:<40} {p}")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if args.function:
        matches = [(f, c, p) for f, c, p in PRIORITY_FUNCTIONS if f == args.function]
        if not matches:
            print(f"'{args.function}' not in PRIORITY_FUNCTIONS. Add it first.")
            sys.exit(1)
        for t in matches:
            make_package(*t)

    elif args.all:
        print(f"Creating {len(PRIORITY_FUNCTIONS)} packages...\n")
        for t in PRIORITY_FUNCTIONS:
            make_package(*t)

    else:
        f, c, p = PRIORITY_FUNCTIONS[0]
        print(f"Creating package for top-priority function: {f}\n"
              f"(Use --list to see all, --all to create all)\n")
        make_package(f, c, p)

    print(f"\nPackages written to: {OUTPUT_DIR}/")
    print("Give the Claude instance brief.md as its opening prompt.")


if __name__ == '__main__':
    main()
