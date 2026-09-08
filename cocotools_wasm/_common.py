"""
cocotools_wasm/discrete/_common.py -- shared infrastructure for the
discrete decb.py / os9.py / cecb.py wrappers.

All three call into the SAME compiled toolshed.wasm (one shared
Emscripten virtual filesystem per Node.js subprocess invocation) --
splitting the Python-level API into per-tool-family files doesn't
mean separate WASM modules. See toolshed.py's own module docstring
history for why: one compiled blob, multiple thin front doors.

This is a real fix, not a cosmetic reorganization, in one respect:
the original toolshed.py defined a _run() helper that properly
surfaces Node's real stderr on failure, but every actual function in
that file -- all 15 of them, DECB and OS-9 and CECB alike -- used
its own hand-copied inline subprocess.run(..., check=True,
capture_output=True) instead, which silently swallows the real error
message on failure (confirmed directly: a user hit exactly this,
seeing only "exit status 1" with no indication why). _run() itself
was never actually called anywhere -- dead code, an abandoned first
attempt at unifying this that never got adopted. This shared helper
is that same idea, actually wired up this time.
"""

import os
import subprocess
import tempfile

def _find_wasm_dir():
    """
    Walk upward from this file's own location looking for a real
    wasm_builds/toolshed/toolshed.js, instead of assuming a fixed
    folder depth. A fixed dirname()-chain count broke the first time
    these files were placed one level shallower than assumed (flat in
    cocotools_wasm/ instead of cocotools_wasm/discrete/) -- confirmed
    directly: the exact bug this replaces.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):  # generous, cheap upper bound -- never actually needed past 2-3
        candidate = os.path.join(here, 'wasm_builds', 'toolshed', 'toolshed.js')
        if os.path.exists(candidate):
            return os.path.join(here, 'wasm_builds', 'toolshed')
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    # Fall back to the old assumption if nothing was found, so the
    # error message at least shows a real, currently-assumed path
    # rather than silently returning None.
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'wasm_builds', 'toolshed'
    )


_WASM_DIR    = _find_wasm_dir()
_TOOLSHED_JS = os.path.join(_WASM_DIR, 'toolshed.js')


def run_wasm(fn_name, arg_types, call_args, input_files=None, output_files=None):
    """
    Call one exported toolshed WASM function via Node.js.

    fn_name:      the ts_* export name, e.g. 'ts_dir'
    arg_types:    list of cwrap type strings matching the C signature,
                  e.g. ['string','string']
    call_args:    list of Python values to pass as JS literals (repr'd)
                  in the same order as arg_types
    input_files:  list of (local_path, vfs_path) written into the
                  virtual FS before the call
    output_files: list of (vfs_path, local_path) read back out after
                  a successful (rc==0) call

    Returns (rc, tmp_dir) -- tmp_dir still exists at return time so
    callers can do their own additional readback before it's cleaned
    up by the caller's own `with` block if they opened one, or you
    can pass output_files and let this function do it for you.
    """
    if not os.path.exists(_TOOLSHED_JS):
        raise FileNotFoundError(
            f"toolshed.js not found at {_TOOLSHED_JS}\n"
            "Trigger the 'Build toolshed WASM' GitHub Actions workflow, "
            "or check that wasm_builds/toolshed/ contains a real build."
        )

    with tempfile.TemporaryDirectory() as tmp:
        rc_path = os.path.join(tmp, 'rc.txt')

        setup_parts = []
        if input_files:
            for local, vfs in input_files:
                data = open(local, 'rb').read()
                arr = ','.join(str(b) for b in data)
                setup_parts.append(f"m.FS.writeFile({vfs!r}, new Uint8Array([{arr}]));")
        setup_parts.append(
            f"const fn = m.cwrap({fn_name!r}, 'number', {arg_types!r});"
        )

        readback_parts = []
        if output_files:
            for vfs, local in output_files:
                local_out = os.path.join(tmp, os.path.basename(local) + '.out')
                readback_parts.append(
                    f"try {{ fs.writeFileSync({local_out!r}, "
                    f"m.FS.readFile({vfs!r})); }} catch(e) {{}}"
                )

        args_js = ', '.join(repr(a) for a in call_args)

        runner = f"""\
const ToolshedModule = require({_TOOLSHED_JS!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    {chr(10).join('    '+p for p in setup_parts)}
    let rc;
    try {{ rc = fn({args_js}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    {chr(10).join('    '+p for p in readback_parts)}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)

        proc = subprocess.run(['node', run_path], capture_output=True, text=True)
        if proc.returncode != 0:
            # The real fix: show what Node actually said, not just "failed."
            raise RuntimeError(
                f"Node.js runner for {fn_name} failed (exit {proc.returncode}):\n"
                f"{proc.stderr}"
            )

        rc = int(open(rc_path).read().strip()) if os.path.exists(rc_path) else -1

        if rc == 0 and output_files:
            for vfs, local in output_files:
                local_out = os.path.join(tmp, os.path.basename(local) + '.out')
                if os.path.exists(local_out):
                    open(local, 'wb').write(open(local_out, 'rb').read())

        return rc


def csv_to_dicts(csv_text):
    """Parse a header+rows CSV string into a list of dicts."""
    import csv, io
    reader = csv.DictReader(io.StringIO(csv_text))
    return list(reader)


def kv_to_dict(kv_text):
    """Parse 'key,value' lines (the actual toolshed wrapper output format,
    confirmed directly -- not 'key: value' as first assumed) into a dict."""
    out = {}
    for line in kv_text.splitlines():
        if ',' in line:
            k, v = line.split(',', 1)
            out[k.strip()] = v.strip()
    return out
