"""
cocotools_wasm/toolshed.py -- Python wrapper around toolshed.wasm

Provides Python functions for DECB and OS-9 disk operations,
backed by the monolithic toolshed WASM module (DECB + OS-9 + CECB).

DECB operations:
    dskini(diskpath, tracks=35)
    copy(srcpath, dstpathlist, file_type=2, data_type=0)
    read(srcpathlist, dstpath)
    dir(diskpath) -> list of dicts
    kill(pathlist)
    free(diskpath) -> dict
    rename(pathlist, newname)
    fstat(pathlist) -> dict

OS-9 operations:
    os9_dir(pathlist) -> str
    os9_copy(srcpathlist, dstpathlist)
    os9_del(pathlist)
    os9_free(imagepath) -> str
    os9_id(imagepath) -> str

Direct CLI usage:
    python cocotools_wasm/toolshed.py dskini BLANK.DSK
    python cocotools_wasm/toolshed.py copy HELLO.BIN BLANK.DSK,HELLO.BIN:0
    python cocotools_wasm/toolshed.py dir BLANK.DSK
    python cocotools_wasm/toolshed.py kill BLANK.DSK,HELLO.BIN:0
    python cocotools_wasm/toolshed.py free BLANK.DSK
    python cocotools_wasm/toolshed.py rename BLANK.DSK,HELLO.BIN:0 WORLD.BIN
    python cocotools_wasm/toolshed.py read BLANK.DSK,HELLO.BIN:0 HELLO.BIN
    python cocotools_wasm/toolshed.py fstat BLANK.DSK,HELLO.BIN:0
    python cocotools_wasm/toolshed.py os9dir IMAGE.OS9,/DD
    python cocotools_wasm/toolshed.py os9id IMAGE.OS9
"""

import csv
import io
import os
import subprocess
import sys
import tempfile

_REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WASM_DIR    = os.path.join(_REPO_ROOT, 'wasm', 'toolshed')
_TOOLSHED_JS = os.path.join(_WASM_DIR, 'toolshed.js')

# ── Node.js runner template ────────────────────────────────────────────────

_RUNNER = """\
const ToolshedModule = require({js!r});
const fs = require('fs');

ToolshedModule().then(m => {{
    {setup}

    let rc;
    try {{
        rc = fn({args});
    }} catch(e) {{
        if (e && e.name === 'ExitStatus') rc = e.status;
        else {{ process.stderr.write('WASM error: ' + e + '\\n'); process.exit(2); }}
    }}

    fs.writeFileSync({rc_path!r}, String(rc));
    {readback}
    process.exit(0);
}});
"""

def _run(fn_name, args_js, setup_js='', readback_js='', input_files=None,
         output_files=None):
    """
    Call a toolshed WASM function via Node.js.
    
    input_files:  list of (local_path, vfs_path) to write into virtual FS
    output_files: list of (vfs_path, local_path) to read back after call
    """
    if not os.path.exists(_TOOLSHED_JS):
        raise FileNotFoundError(
            f"toolshed.js not found at {_TOOLSHED_JS}\n"
            "Trigger the 'Build toolshed WASM' GitHub Actions workflow."
        )

    with tempfile.TemporaryDirectory() as tmp:
        rc_path = os.path.join(tmp, 'rc.txt')

        # Build setup JS -- write input files to virtual FS
        setup_parts = []
        if input_files:
            for local, vfs in input_files:
                data = open(local, 'rb').read()
                arr = ','.join(str(b) for b in data)
                setup_parts.append(
                    f"m.FS.writeFile({vfs!r}, new Uint8Array([{arr}]));"
                )
        setup_parts.append(f"const fn = m.cwrap({fn_name!r}, 'number', {setup_js});")
        setup_js_full = '\n    '.join(setup_parts)

        # Build readback JS -- read output files from virtual FS
        readback_parts = []
        if output_files:
            for vfs, local in output_files:
                readback_parts.append(
                    f"try {{ fs.writeFileSync({local!r}, "
                    f"m.FS.readFile({vfs!r})); }} catch(e) {{}}"
                )
        readback_js_full = '\n    '.join(readback_parts)

        runner = _RUNNER.format(
            js=_TOOLSHED_JS,
            setup=setup_js_full,
            args=args_js,
            rc_path=rc_path,
            readback=readback_js_full,
        )

        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)

        proc = subprocess.run(['node', run_path], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f"Node.js runner failed (exit {proc.returncode}):\n{proc.stderr}"
            )

        rc = int(open(rc_path).read().strip()) if os.path.exists(rc_path) else -1
        return rc, tmp


def _csv_to_dicts(csv_text):
    """Parse CSV text (with header row) into list of dicts."""
    reader = csv.DictReader(io.StringIO(csv_text.strip()))
    return list(reader)


def _kv_to_dict(kv_text):
    """Parse key,value CSV (no header) into a dict."""
    result = {}
    for line in kv_text.strip().splitlines():
        parts = line.split(',', 1)
        if len(parts) == 2:
            result[parts[0]] = parts[1]
    return result


# ── DECB Operations ────────────────────────────────────────────────────────

def dskini(diskpath, tracks=35):
    """Create a blank formatted DECB DSK image."""
    with tempfile.TemporaryDirectory() as tmp:
        vfs_disk = '/disk.dsk'
        out_path = os.path.join(tmp, 'disk.dsk')

        js = _TOOLSHED_JS
        runner = f"""\
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    const fn = m.cwrap('ts_dskini', 'number', ['string', 'number']);
    let rc;
    try {{ rc = fn({vfs_disk!r}, {int(tracks)}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    if (rc === 0) fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_disk!r}));
    fs.writeFileSync({os.path.join(tmp, 'rc.txt')!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(os.path.join(tmp, 'rc.txt')).read().strip())
        if rc != 0:
            raise RuntimeError(f"ts_dskini failed: rc={rc}")
        data = open(out_path, 'rb').read()

    open(diskpath, 'wb').write(data)
    return len(data)


def copy(srcpath, dstpathlist, file_type=2, data_type=0):
    """Copy a native file into a DECB DSK image."""
    src_data = open(srcpath, 'rb').read()

    # Parse dstpathlist to extract disk path
    comma = dstpathlist.index(',')
    disk_path = dstpathlist[:comma]
    decb_name = dstpathlist[comma:]  # e.g. ",HELLO.BIN:0"

    disk_data = open(disk_path, 'rb').read()

    with tempfile.TemporaryDirectory() as tmp:
        vfs_disk = '/disk.dsk'
        vfs_src  = '/src.bin'
        vfs_dst  = vfs_disk + decb_name
        out_path = os.path.join(tmp, 'disk.dsk')
        rc_path  = os.path.join(tmp, 'rc.txt')

        src_arr  = ','.join(str(b) for b in src_data)
        disk_arr = ','.join(str(b) for b in disk_data)

        js = _TOOLSHED_JS
        runner = f"""\
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_disk!r}, new Uint8Array([{disk_arr}]));
    m.FS.writeFile({vfs_src!r},  new Uint8Array([{src_arr}]));
    const fn = m.cwrap('ts_copy', 'number', ['string','string','number','number']);
    let rc;
    try {{ rc = fn({vfs_src!r}, {vfs_dst!r}, {int(file_type)}, {int(data_type)}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    if (rc === 0) fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_disk!r}));
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc != 0:
            raise RuntimeError(f"ts_copy failed: rc={rc}")
        updated = open(out_path, 'rb').read()

    open(disk_path, 'wb').write(updated)


def read(srcpathlist, dstpath):
    """Read a file from a DECB DSK image to a native file."""
    comma = srcpathlist.index(',')
    disk_path = srcpathlist[:comma]
    decb_name = srcpathlist[comma:]
    disk_data = open(disk_path, 'rb').read()
    disk_arr  = ','.join(str(b) for b in disk_data)

    with tempfile.TemporaryDirectory() as tmp:
        vfs_disk = '/disk.dsk'
        vfs_src  = vfs_disk + decb_name
        vfs_out  = '/out.bin'
        out_path = os.path.join(tmp, 'out.bin')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS

        runner = f"""\
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_disk!r}, new Uint8Array([{disk_arr}]));
    const fn = m.cwrap('ts_read', 'number', ['string','string']);
    let rc;
    try {{ rc = fn({vfs_src!r}, {vfs_out!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    try {{ fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_out!r})); }} catch(e) {{}}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc != 0:
            raise RuntimeError(f"ts_read failed: rc={rc}")
        data = open(out_path, 'rb').read()

    open(dstpath, 'wb').write(data)


def dir(diskpath):
    """List files on a DECB DSK image. Returns list of dicts."""
    disk_data = open(diskpath, 'rb').read()
    disk_arr  = ','.join(str(b) for b in disk_data)

    with tempfile.TemporaryDirectory() as tmp:
        vfs_disk = '/disk.dsk'
        vfs_out  = '/dir.csv'
        out_path = os.path.join(tmp, 'dir.csv')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS

        runner = f"""\
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_disk!r}, new Uint8Array([{disk_arr}]));
    const fn = m.cwrap('ts_dir', 'number', ['string','string']);
    let rc;
    try {{ rc = fn({vfs_disk!r}, {vfs_out!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    try {{ fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_out!r})); }} catch(e) {{}}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc != 0:
            raise RuntimeError(f"ts_dir failed: rc={rc}")
        csv_text = open(out_path).read()

    return _csv_to_dicts(csv_text)


def kill(pathlist):
    """Delete a file from a DECB DSK image."""
    comma = pathlist.index(',')
    disk_path = pathlist[:comma]
    decb_name = pathlist[comma:]
    disk_data = open(disk_path, 'rb').read()
    disk_arr  = ','.join(str(b) for b in disk_data)

    with tempfile.TemporaryDirectory() as tmp:
        vfs_disk = '/disk.dsk'
        vfs_file = vfs_disk + decb_name
        out_path = os.path.join(tmp, 'disk.dsk')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS

        runner = f"""\
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_disk!r}, new Uint8Array([{disk_arr}]));
    const fn = m.cwrap('ts_kill', 'number', ['string']);
    let rc;
    try {{ rc = fn({vfs_file!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    if (rc === 0) fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_disk!r}));
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc != 0:
            raise RuntimeError(f"ts_kill failed: rc={rc}")
        updated = open(out_path, 'rb').read()

    open(disk_path, 'wb').write(updated)


def free(diskpath):
    """Get free space info for a DECB DSK image. Returns dict."""
    disk_data = open(diskpath, 'rb').read()
    disk_arr  = ','.join(str(b) for b in disk_data)

    with tempfile.TemporaryDirectory() as tmp:
        vfs_disk = '/disk.dsk'
        vfs_out  = '/free.csv'
        out_path = os.path.join(tmp, 'free.csv')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS

        runner = f"""\
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_disk!r}, new Uint8Array([{disk_arr}]));
    const fn = m.cwrap('ts_free', 'number', ['string','string']);
    let rc;
    try {{ rc = fn({vfs_disk!r}, {vfs_out!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    try {{ fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_out!r})); }} catch(e) {{}}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc != 0:
            raise RuntimeError(f"ts_free failed: rc={rc}")
        return _kv_to_dict(open(out_path).read())


def rename(pathlist, newname):
    """Rename a file in a DECB DSK image."""
    comma = pathlist.index(',')
    disk_path = pathlist[:comma]
    disk_data = open(disk_path, 'rb').read()
    disk_arr  = ','.join(str(b) for b in disk_data)

    with tempfile.TemporaryDirectory() as tmp:
        vfs_disk = '/disk.dsk'
        vfs_file = vfs_disk + pathlist[comma:]
        out_path = os.path.join(tmp, 'disk.dsk')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS

        runner = f"""\
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_disk!r}, new Uint8Array([{disk_arr}]));
    const fn = m.cwrap('ts_rename', 'number', ['string','string']);
    let rc;
    try {{ rc = fn({vfs_file!r}, {newname!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    if (rc === 0) fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_disk!r}));
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc != 0:
            raise RuntimeError(f"ts_rename failed: rc={rc}")
        updated = open(out_path, 'rb').read()

    open(disk_path, 'wb').write(updated)


def fstat(pathlist):
    """Get file status from a DECB DSK image. Returns dict."""
    comma = pathlist.index(',')
    disk_path = pathlist[:comma]
    disk_data = open(disk_path, 'rb').read()
    disk_arr  = ','.join(str(b) for b in disk_data)

    with tempfile.TemporaryDirectory() as tmp:
        vfs_disk = '/disk.dsk'
        vfs_file = vfs_disk + pathlist[comma:]
        vfs_out  = '/fstat.csv'
        out_path = os.path.join(tmp, 'fstat.csv')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS

        runner = f"""\
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_disk!r}, new Uint8Array([{disk_arr}]));
    const fn = m.cwrap('ts_fstat', 'number', ['string','string']);
    let rc;
    try {{ rc = fn({vfs_file!r}, {vfs_out!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    try {{ fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_out!r})); }} catch(e) {{}}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc != 0:
            raise RuntimeError(f"ts_fstat failed: rc={rc}")
        return _kv_to_dict(open(out_path).read())


# ── OS-9 Operations ────────────────────────────────────────────────────────

def _os9_op(fn_name, *pathargs):
    """Generic OS-9 operation returning text output."""
    comma = pathargs[0].index(',')
    disk_path = pathargs[0][:comma]
    disk_data = open(disk_path, 'rb').read()
    disk_arr  = ','.join(str(b) for b in disk_data)

    vfs_disk = '/image.os9'
    vfs_args = [vfs_disk + pathargs[0][comma:]] + list(pathargs[1:])

    with tempfile.TemporaryDirectory() as tmp:
        vfs_out  = '/out.txt'
        out_path = os.path.join(tmp, 'out.txt')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS
        args_str = ', '.join(repr(a) for a in vfs_args) + f', {vfs_out!r}'

        runner = f"""\
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_disk!r}, new Uint8Array([{disk_arr}]));
    const fn = m.cwrap({fn_name!r}, 'number', {['string'] * len(vfs_args + [vfs_out])!r});
    let rc;
    try {{ rc = fn({args_str}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    try {{ fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_out!r})); }} catch(e) {{}}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc != 0:
            raise RuntimeError(f"{fn_name} failed: rc={rc}")
        return open(out_path).read() if os.path.exists(out_path) else ''


def os9_dir(pathlist):
    """List directory of an OS-9 image. Returns text."""
    return _os9_op('ts_os9_dir', pathlist)

def os9_free(imagepath_with_comma):
    """Show free space on an OS-9 image. Returns text."""
    return _os9_op('ts_os9_free', imagepath_with_comma)

def os9_id(imagepath_with_comma):
    """Show OS-9 image identification. Returns text."""
    return _os9_op('ts_os9_id', imagepath_with_comma)


# ── CECB Operations ──────────────────────────────────────────────────────────

def cecb_bulkerase(caspath):
    """Create/erase a CAS file (bulk erase = create blank cassette)."""
    with tempfile.TemporaryDirectory() as tmp:
        vfs_cas = '/out.cas'
        out_path = os.path.join(tmp, 'out.cas')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS
        runner = f"""
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    const fn = m.cwrap('ts_cecb_bulkerase', 'number', ['string']);
    let rc;
    try {{ rc = fn({vfs_cas!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    try {{ fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_cas!r})); }} catch(e) {{}}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        open(os.path.join(tmp, 'run.js'), 'w').write(runner)
        subprocess.run(['node', os.path.join(tmp, 'run.js')], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc == 0 and os.path.exists(out_path):
            open(caspath, 'wb').write(open(out_path, 'rb').read())
    return rc


def cecb_copy(srcpath, dstpathlist, file_type=2, load_addr='', exec_addr=''):
    """
    Copy a binary file into a CAS image.

    Args:
        srcpath:     source binary file
        dstpathlist: destination CAS pathlist (e.g. DISK.CAS,HELLO)
                     Note: CECB format uses no drive number (:0)
        file_type:   0=BASIC, 1=data, 2=ML (default), 3=text
        load_addr:   load address as hex string (e.g. '3F00')
        exec_addr:   exec address as hex string (e.g. '3F00')
    """
    src_data = open(srcpath, 'rb').read()
    src_arr  = ','.join(str(b) for b in src_data)
    comma = dstpathlist.index(',')
    cas_path = dstpathlist[:comma]
    # Strip :0 drive suffix if present (CECB doesn't use drive numbers)
    dstpathlist = dstpathlist.split(':')[0]
    cas_data = open(cas_path, 'rb').read() if os.path.exists(cas_path) else b''
    cas_arr  = ','.join(str(b) for b in cas_data)

    with tempfile.TemporaryDirectory() as tmp:
        vfs_cas  = '/out.cas'
        vfs_src  = '/in.bin'
        vfs_dst  = vfs_cas + dstpathlist[comma:]
        out_path = os.path.join(tmp, 'out.cas')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS
        runner = f"""
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_cas!r}, new Uint8Array([{cas_arr}]));
    m.FS.writeFile({vfs_src!r}, new Uint8Array([{src_arr}]));
    const fn = m.cwrap('ts_cecb_copy', 'number',
        ['string','string','number','string','string']);
    let rc;
    try {{ rc = fn({vfs_src!r}, {vfs_dst!r}, {int(file_type)},
                  {load_addr!r}, {exec_addr!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    try {{ fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_cas!r})); }} catch(e) {{}}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        open(os.path.join(tmp, 'run.js'), 'w').write(runner)
        subprocess.run(['node', os.path.join(tmp, 'run.js')], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc == 0 and os.path.exists(out_path):
            open(cas_path, 'wb').write(open(out_path, 'rb').read())
    return rc


def cecb_dir(caspath):
    """List files on a CAS image. Returns text."""
    cas_data = open(caspath, 'rb').read()
    cas_arr  = ','.join(str(b) for b in cas_data)
    with tempfile.TemporaryDirectory() as tmp:
        vfs_cas = '/in.cas'
        vfs_out = '/out.txt'
        out_path = os.path.join(tmp, 'out.txt')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOOLSHED_JS
        runner = f"""
const ToolshedModule = require({js!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    m.FS.writeFile({vfs_cas!r}, new Uint8Array([{cas_arr}]));
    const fn = m.cwrap('ts_cecb_dir', 'number', ['string','string']);
    let rc;
    try {{ rc = fn({vfs_cas!r}, {vfs_out!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    try {{ fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_out!r})); }} catch(e) {{}}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        open(os.path.join(tmp, 'run.js'), 'w').write(runner)
        subprocess.run(['node', os.path.join(tmp, 'run.js')], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        return open(out_path).read() if os.path.exists(out_path) else ''


# ── CLI ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        prog='toolshed.py',
        description='DECB and OS-9 disk operations via toolshed WASM'
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    # Pathlist format explanation (used in multiple help strings)
    PATHLIST_HELP = """
Pathlist format:  DISKIMAGE.DSK,FILENAME.EXT:0
  DISKIMAGE.DSK   -- the disk image file on your computer
  FILENAME.EXT    -- the file name as it appears on the CoCo disk
  :0              -- drive number (always 0 for single-drive images)

Example:  BLANK.DSK,HELLO.BIN:0
"""

    p = sub.add_parser('dskini',
        help='Create blank DECB DSK image',
        description='Create a blank formatted DECB DSK image.',
        epilog='Example:\n  toolshed.py dskini BLANK.DSK\n  toolshed.py dskini BLANK80.DSK --tracks 80',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('disk', help='Output DSK file')
    p.add_argument('--tracks', type=int, choices=[35,40,80], default=35,
                   help='Number of tracks (default: 35)')

    p = sub.add_parser('copy',
        help='Copy file into DECB DSK image',
        description='Copy a native file into a DECB DSK image.\n' + PATHLIST_HELP,
        epilog='Examples:\n  toolshed.py copy HELLO.BIN BLANK.DSK,HELLO.BIN:0       (native file INTO disk)\n  toolshed.py copy GUESS.BAS GAMES.DSK,GUESS.BAS:0 --type 0 --ascii\n\nTo read a file back OUT of a disk, use the read command:\n  toolshed.py read BLANK.DSK,HELLO.BIN:0 HELLO.BIN',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('src', help='Source file on your computer')
    p.add_argument('dst', help='Destination: DISK.DSK,FILENAME.EXT:0')
    p.add_argument('--type', type=int, choices=[0,1,2,3], default=2,
                   dest='file_type',
                   help='File type: 0=BASIC program, 1=BASIC data, 2=ML program (default), 3=text')
    p.add_argument('--ascii', action='store_true',
                   help='Mark as ASCII data type (default: binary)')

    p = sub.add_parser('read',
        help='Read file from DECB DSK image',
        description='Read a file from a DECB DSK image to your computer.\n' + PATHLIST_HELP,
        epilog='Example:\n  toolshed.py read BLANK.DSK,HELLO.BIN:0 HELLO.BIN',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('src', help='Source: DISK.DSK,FILENAME.EXT:0')
    p.add_argument('dst', help='Destination file on your computer')

    p = sub.add_parser('dir',
        help='List DECB DSK directory',
        description='List the directory of a DECB DSK image.',
        epilog='Example:\n  toolshed.py dir BLANK.DSK',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('disk', help='DSK file')

    p = sub.add_parser('kill',
        help='Delete file from DECB DSK image',
        description='Delete a file from a DECB DSK image.\n' + PATHLIST_HELP,
        epilog='Example:\n  toolshed.py kill BLANK.DSK,HELLO.BIN:0',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('pathlist', help='File to delete: DISK.DSK,FILENAME.EXT:0')

    p = sub.add_parser('free',
        help='Show free space on DECB DSK image',
        description='Show free granule and byte count for a DECB DSK image.',
        epilog='Example:\n  toolshed.py free BLANK.DSK',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('disk', help='DSK file')

    p = sub.add_parser('rename',
        help='Rename file in DECB DSK image',
        description='Rename a file in a DECB DSK image.\n' + PATHLIST_HELP,
        epilog='Example:\n  toolshed.py rename BLANK.DSK,HELLO.BIN:0 WORLD.BIN',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('pathlist', help='File to rename: DISK.DSK,FILENAME.EXT:0')
    p.add_argument('newname', help='New filename (without disk path)')

    p = sub.add_parser('fstat',
        help='Show file info from DECB DSK image',
        description='Show file type, data type, and size for a file on a DECB DSK image.\n' + PATHLIST_HELP,
        epilog='Example:\n  toolshed.py fstat BLANK.DSK,HELLO.BIN:0',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('pathlist', help='File to inspect: DISK.DSK,FILENAME.EXT:0')

    p = sub.add_parser('cecbbulkerase',
        help='Create blank CAS image (bulk erase)',
        epilog='Example:\n  toolshed.py cecbbulkerase BLANK.CAS',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('cas', help='Output CAS file')

    p = sub.add_parser('cecbcopy',
        help='Copy binary into CAS image',
        description='Copy a binary file into a CAS cassette image.\n\nPathlist format: CASSETTE.CAS,FILENAME:0',
        epilog='Examples:\n  toolshed.py cecbcopy HELLO.BIN BLANK.CAS,HELLO --type 2 --load 3F00 --exec 3F00',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('src', help='Source binary file')
    p.add_argument('dst', help='Destination: CAS.CAS,FILENAME (no drive number)')
    p.add_argument('--type', type=int, choices=[0,1,2,3], default=2,
                   dest='file_type', help='File type: 0=BASIC, 1=data, 2=ML (default), 3=text')
    p.add_argument('--load', default='', dest='load_addr',
                   help='Load address as hex (e.g. 3F00)')
    p.add_argument('--exec', default='', dest='exec_addr',
                   help='Exec address as hex (e.g. 3F00)')

    p = sub.add_parser('cecbdir',
        help='List CAS image directory',
        epilog='Example:\n  toolshed.py cecbdir BLANK.CAS',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('cas', help='CAS file')

    p = sub.add_parser('os9dir',
        help='List OS-9 image directory',
        description='List a directory inside an OS-9 disk image.',
        epilog='Example:\n  toolshed.py os9dir NITROS9.OS9,/DD',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('pathlist', help='Path: IMAGE.OS9,/directory')

    p = sub.add_parser('os9free',
        help='Show OS-9 image free space',
        description='Show free space on an OS-9 disk image.',
        epilog='Example:\n  toolshed.py os9free NITROS9.OS9,/DD',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('pathlist', help='Path: IMAGE.OS9,/directory')

    p = sub.add_parser('os9id',
        help='Show OS-9 image identification',
        description='Show the OS-9 disk image identification block.',
        epilog='Example:\n  toolshed.py os9id NITROS9.OS9,/DD',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('pathlist', help='Path: IMAGE.OS9,/directory')

    p = sub.add_parser('version',
        help='Show toolshed WASM version and build info',
        description='Show the toolshed WASM build date and size.')
    p.set_defaults(func=None)

    p = sub.add_parser('help',
        help='Show help for a specific command',
        description='Show detailed help for a specific command.')
    p.add_argument('command', nargs='?', help='Command to get help for')

    args = parser.parse_args()

    try:
        if args.cmd == 'dskini':
            n = dskini(args.disk, args.tracks)
            print(f"OK: {n} bytes -> {args.disk}")

        elif args.cmd == 'copy':
            copy(args.src, args.dst, args.file_type, 0xFF if args.ascii else 0)
            print(f"OK: {args.src} -> {args.dst}")

        elif args.cmd == 'read':
            read(args.src, args.dst)
            print(f"OK: {args.src} -> {args.dst}")

        elif args.cmd == 'dir':
            entries = dir(args.disk)
            print(f"{'Name':<12} {'Ext':<4} {'Type':<5} {'Data':<5} {'Gran':>4} {'Size':>6}")
            print('-' * 40)
            for e in entries:
                print(f"{e['name']:<12} {e['ext']:<4} {e['type']:<5} "
                      f"{e['ascii']:<5} {e['first_granule']:>4} {e['last_sector_bytes']:>6}")

        elif args.cmd == 'kill':
            kill(args.pathlist)
            print(f"OK: deleted {args.pathlist}")

        elif args.cmd == 'free':
            info = free(args.disk)
            print(f"Free granules: {info.get('free_granules')}")
            print(f"Free bytes:    {info.get('free_bytes')}")
            print(f"Used granules: {info.get('used_granules')}")

        elif args.cmd == 'rename':
            rename(args.pathlist, args.newname)
            print(f"OK: renamed to {args.newname}")

        elif args.cmd == 'fstat':
            info = fstat(args.pathlist)
            types = {0:'BASIC', 1:'Data', 2:'ML', 3:'Text'}
            print(f"File type: {info.get('file_type')} ({types.get(int(info.get('file_type',0)),'?')})")
            print(f"Data type: {'ASCII' if int(info.get('data_type',0)) else 'Binary'}")
            print(f"File size: {info.get('file_size')} bytes")

        elif args.cmd == 'cecbbulkerase':
            rc = cecb_bulkerase(args.cas)
            if rc == 0:
                print(f"OK: {args.cas} created")
            else:
                print(f"ERROR: rc={rc}", file=sys.stderr)
                sys.exit(1)

        elif args.cmd == 'cecbcopy':
            rc = cecb_copy(args.src, args.dst, args.file_type,
                          args.load_addr, args.exec_addr)
            if rc == 0:
                print(f"OK: {args.src} -> {args.dst}")
            else:
                print(f"ERROR: rc={rc}", file=sys.stderr)
                sys.exit(1)

        elif args.cmd == 'cecbdir':
            print(cecb_dir(args.cas), end='')

        elif args.cmd == 'os9dir':
            print(os9_dir(args.pathlist), end='')

        elif args.cmd == 'os9free':
            print(os9_free(args.pathlist), end='')

        elif args.cmd == 'os9id':
            print(os9_id(args.pathlist), end='')

        elif args.cmd == 'version':
            import os, glob, datetime
            js = _TOOLSHED_JS
            wasm = js.replace('.js', '.wasm')
            print("cocotools_wasm/toolshed.py -- toolshed WASM wrapper")

            if os.path.exists(wasm):
                # Get version from WASM itself -- ts_version() returns "Toolshed X.Y.Z"
                mtime = os.path.getmtime(wasm)
                built = datetime.datetime.fromtimestamp(mtime).strftime('%d%b%Y').upper()

                import subprocess, tempfile
                with tempfile.TemporaryDirectory() as tmp:
                    rc_path = os.path.join(tmp, 'ver.txt')
                    runner = f"""
const ToolshedModule = require({_TOOLSHED_JS!r});
const fs = require('fs');
ToolshedModule().then(m => {{
    const ver = m.cwrap('ts_version', 'string', []);
    fs.writeFileSync({rc_path!r}, ver());
    process.exit(0);
}});
"""
                    rp = os.path.join(tmp, 'run.js')
                    open(rp, 'w').write(runner)
                    proc = subprocess.run(['node', rp], capture_output=True, text=True)
                    ts_ver = open(rc_path).read().strip() if os.path.exists(rc_path) else 'unknown'

                print(f"toolshed.wasm: built {built} based on {ts_ver}")
            else:
                print("toolshed.wasm: NOT FOUND")
                print("  Run 'Build toolshed WASM' GitHub Actions workflow to build.")

        elif args.cmd == 'help':
            if hasattr(args, 'command') and args.command:
                # Show help for specific command
                sys.argv = [sys.argv[0], args.command, '--help']
                parser.parse_args()
            else:
                parser.print_help()

    except SystemExit:
        raise
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
