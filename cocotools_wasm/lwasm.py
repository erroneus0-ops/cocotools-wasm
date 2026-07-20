"""
cocotools_wasm/lwasm.py -- Python wrapper around lwasm.wasm

Calls lwasm via Node.js subprocess, parses unicorns output,
returns structured result.

Usage:
    from cocotools_wasm.lwasm import assemble, AssemblyResult

    result = assemble(source, format='decb')
    if result.success:
        open('output.bin', 'wb').write(result.binary)
    else:
        for err in result.errors:
            print(f"{err['file']}:{err['line']}: {err['message']}")
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import unquote

# Path to the WASM module relative to this file
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WASM_DIR  = os.path.join(_REPO_ROOT, 'wasm', 'lwasm')
_LWASM_JS  = os.path.join(_WASM_DIR, 'lwasm.js')

# Node.js runner -- calls lwasm_assemble and writes output files
_RUNNER_TEMPLATE = """\
const LwasmModule = require({lwasm_js!r});
const fs = require('fs');

LwasmModule().then(m => {{
    const assemble = m.cwrap('lwasm_assemble', 'number', ['string', 'string']);

    let result;
    try {{
        result = assemble({source!r}, {format!r});
    }} catch(e) {{
        if (e && e.name === 'ExitStatus') {{
            result = e.status;
        }} else {{
            process.stderr.write('WASM error: ' + e + '\\n');
            process.exit(2);
        }}
    }}

    // Write return code
    fs.writeFileSync({rc_path!r}, String(result));

    // Write binary output if it exists
    try {{
        const bin = m.FS.readFile('/out.bin');
        fs.writeFileSync({bin_path!r}, bin);
    }} catch(e) {{}}

    // Write errors/warnings (unicorns format)
    try {{
        const errs = m.FS.readFile('/out.errors', {{encoding: 'utf8'}});
        fs.writeFileSync({err_path!r}, errs);
    }} catch(e) {{}}

    process.exit(0);
}});
"""


@dataclass
class AssemblyMessage:
    """A single error or warning from lwasm."""
    file:    str
    line:    int
    col:     Optional[int]
    message: str


@dataclass
class AssemblyResult:
    """Result of an lwasm assembly operation."""
    success:  bool
    binary:   bytes                        = field(default_factory=bytes)
    errors:   List[AssemblyMessage]        = field(default_factory=list)
    warnings: List[AssemblyMessage]        = field(default_factory=list)
    rc:       int                          = 0


def _parse_unicorns(text: str) -> tuple:
    """Parse lwasm unicorns output into (errors, warnings) lists."""
    errors   = []
    warnings = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line == 'UNICORNSAWAY:':
            continue
        if line.startswith('RESOURCE:'):
            continue  # file/macro/struct listings -- ignore for now

        for tag, bucket in [('ERROR:', errors), ('WARNING:', warnings)]:
            if not line.startswith(tag):
                continue
            # Format: TAG: key=value,key=value,...
            parts = {}
            for kv in line[len(tag):].strip().split(','):
                if '=' in kv:
                    k, v = kv.split('=', 1)
                    parts[k.strip()] = unquote(v.strip())
            bucket.append(AssemblyMessage(
                file    = parts.get('filename', ''),
                line    = int(parts.get('lineno', 0)),
                col     = int(parts['col']) if 'col' in parts else None,
                message = parts.get('message', line),
            ))

    return errors, warnings


def assemble(source: str, format: str = 'decb') -> AssemblyResult:
    """
    Assemble 6809 source code using lwasm WASM.

    Args:
        source: Assembly source text
        format: Output format -- 'decb', 'raw', or 'os9'

    Returns:
        AssemblyResult with binary output and any errors/warnings
    """
    if not os.path.exists(_LWASM_JS):
        raise FileNotFoundError(
            f"lwasm.js not found at {_LWASM_JS}\n"
            f"Trigger the 'Build lwasm WASM' GitHub Actions workflow to build it."
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        rc_path  = os.path.join(tmpdir, 'rc.txt')
        bin_path = os.path.join(tmpdir, 'out.bin')
        err_path = os.path.join(tmpdir, 'out.errors')
        run_path = os.path.join(tmpdir, 'run.js')

        runner = _RUNNER_TEMPLATE.format(
            lwasm_js = _LWASM_JS,
            source   = source,
            format   = format,
            rc_path  = rc_path,
            bin_path = bin_path,
            err_path = err_path,
        )
        open(run_path, 'w').write(runner)

        proc = subprocess.run(
            ['node', run_path],
            capture_output=True, text=True
        )

        if proc.returncode != 0:
            raise RuntimeError(
                f"Node.js runner failed (exit {proc.returncode}):\n{proc.stderr}"
            )

        rc = int(open(rc_path).read().strip()) if os.path.exists(rc_path) else -1

        binary = b''
        if os.path.exists(bin_path):
            binary = open(bin_path, 'rb').read()

        errors, warnings = [], []
        if os.path.exists(err_path):
            errors, warnings = _parse_unicorns(open(err_path).read())

        return AssemblyResult(
            success  = (rc == 0 and len(errors) == 0),
            binary   = binary,
            errors   = errors,
            warnings = warnings,
            rc       = rc,
        )
