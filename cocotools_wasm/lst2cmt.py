"""
cocotools_wasm/lst2cmt.py -- Python wrapper around lst2cmt.wasm

Converts lwasm listing files to MAME/XRoar debugger comment files.

Usage:
    from cocotools_wasm.lst2cmt import convert
    convert('HELLO.lst', 'HELLO.xml', system='coco', cpu=':maincpu')

CLI:
    python cocotools_wasm/lst2cmt.py convert HELLO.lst HELLO.xml --system coco
    python cocotools_wasm/lst2cmt.py version
    python cocotools_wasm/lst2cmt.py --help
"""

import os
import subprocess
import sys
import tempfile

_REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WASM_DIR    = os.path.join(_REPO_ROOT, 'wasm', 'lst2cmt')
_LST2CMT_JS  = os.path.join(_WASM_DIR, 'lst2cmt.js')

_RUNNER = """\
const Lst2cmtModule = require({js!r});
const fs = require('fs');
Lst2cmtModule().then(m => {{
    {setup}
    let rc;
    try {{ rc = fn({args}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    fs.writeFileSync({rc_path!r}, String(rc));
    {readback}
    process.exit(0);
}});
"""


def _run_lst2cmt(fn_name, args_js, input_files=None, output_files=None):
    if not os.path.exists(_LST2CMT_JS):
        raise FileNotFoundError(
            f"lst2cmt.js not found at {_LST2CMT_JS}\n"
            "Trigger the 'Build lst2cmt WASM' GitHub Actions workflow."
        )

    with tempfile.TemporaryDirectory() as tmp:
        rc_path = os.path.join(tmp, 'rc.txt')

        setup_parts = []
        if input_files:
            for local, vfs in input_files:
                data = open(local, 'rb').read()
                arr = ','.join(str(b) for b in data)
                setup_parts.append(f"m.FS.writeFile({vfs!r}, new Uint8Array([{arr}]));")
        setup_parts.append(f"const fn = m.cwrap({fn_name!r}, 'number', ['string','string','string','string','number','number','number']);")
        
        readback_parts = []
        if output_files:
            for vfs, local in output_files:
                readback_parts.append(
                    f"try {{ require('fs').writeFileSync({local!r}, m.FS.readFile({vfs!r})); }} catch(e) {{}}"
                )

        runner = _RUNNER.format(
            js=_LST2CMT_JS,
            setup='\n    '.join(setup_parts),
            args=args_js,
            rc_path=rc_path,
            readback='\n    '.join(readback_parts),
        )

        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        proc = subprocess.run(['node', run_path], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"Node.js runner failed:\n{proc.stderr}")

        rc = int(open(rc_path).read().strip()) if os.path.exists(rc_path) else -1
        return rc, tmp


def convert(srcpath, dstpath, system='', cpu=':maincpu',
            nocrc=False, nolinenumbers=False, offset=0):
    """
    Convert an lwasm listing file to a MAME/XRoar debugger comment file.

    Args:
        srcpath:       lwasm listing file (.lst)
        dstpath:       output XML comment file
        system:        MAME system name (e.g. 'coco', 'coco2b')
        cpu:           CPU to attach comments to (default: ':maincpu')
        nocrc:         omit CRC field
        nolinenumbers: omit line numbers
        offset:        memory offset

    Returns:
        0 on success, non-zero on error
    """
    vfs_src = '/in.lst'
    vfs_dst = '/out.xml'

    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, 'out.xml')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _LST2CMT_JS

        src_data = open(srcpath, 'rb').read()
        src_arr  = ','.join(str(b) for b in src_data)

        runner = f"""\
const Lst2cmtModule = require({js!r});
const fs = require('fs');
Lst2cmtModule().then(m => {{
    m.FS.writeFile({vfs_src!r}, new Uint8Array([{src_arr}]));
    const fn = m.cwrap('lst2cmt_convert', 'number',
        ['string','string','string','string','number','number','number']);
    let rc;
    try {{
        rc = fn({vfs_src!r}, {vfs_dst!r}, {system!r}, {cpu!r},
                {int(nocrc)}, {int(nolinenumbers)}, {int(offset)});
    }} catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
    try {{ fs.writeFileSync({out_path!r}, m.FS.readFile({vfs_dst!r})); }} catch(e) {{}}
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        subprocess.run(['node', run_path], check=True, capture_output=True)
        rc = int(open(rc_path).read().strip())
        if rc == 0 and os.path.exists(out_path):
            open(dstpath, 'wb').write(open(out_path, 'rb').read())
    return rc


def get_version():
    """Get version string from WASM module."""
    with tempfile.TemporaryDirectory() as tmp:
        ver_path = os.path.join(tmp, 'ver.txt')
        js = _LST2CMT_JS
        runner = f"""\
const Lst2cmtModule = require({js!r});
const fs = require('fs');
Lst2cmtModule().then(m => {{
    const fn = m.cwrap('lst2cmt_version', 'string', []);
    fs.writeFileSync({ver_path!r}, fn());
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        proc = subprocess.run(['node', run_path], capture_output=True, text=True)
        if proc.returncode == 0 and os.path.exists(ver_path):
            return open(ver_path).read().strip()
    return 'unknown'


if __name__ == '__main__':
    import argparse, datetime

    parser = argparse.ArgumentParser(
        prog='lst2cmt.py',
        description='Convert lwasm listing files to MAME/XRoar debugger comment files'
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('convert', help='Convert listing to debugger comments',
        description='Convert an lwasm listing file to MAME/XRoar debugger XML comments.\n\nGenerate a listing with: lwasm --list=HELLO.lst HELLO.ASM',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  lst2cmt.py convert HELLO.lst HELLO.xml --system coco2b')
    p.add_argument('src', help='lwasm listing file (.lst)')
    p.add_argument('dst', help='Output XML comment file')
    p.add_argument('--system', default='', help='MAME system name (e.g. coco, coco2b)')
    p.add_argument('--cpu', default=':maincpu', help='CPU tag (default: :maincpu)')
    p.add_argument('--nocrc', action='store_true', help='Omit CRC field')
    p.add_argument('--nolinenumbers', action='store_true', help='Omit line numbers')
    p.add_argument('--offset', type=int, default=0, help='Memory offset')

    p = sub.add_parser('version', help='Show version')
    p = sub.add_parser('help', help='Show help for a command')
    p.add_argument('command', nargs='?')

    args = parser.parse_args()

    try:
        if args.cmd == 'convert':
            rc = convert(args.src, args.dst, args.system, args.cpu,
                        args.nocrc, args.nolinenumbers, args.offset)
            if rc == 0:
                print(f"OK: {args.src} -> {args.dst}")
            else:
                print(f"ERROR: rc={rc}", file=sys.stderr)
                sys.exit(1)

        elif args.cmd == 'version':
            if not os.path.exists(_LST2CMT_JS):
                print("lst2cmt.wasm: NOT FOUND")
            else:
                ver = get_version()
                mtime = os.path.getmtime(_LST2CMT_JS.replace('.js', '.wasm'))
                built = datetime.datetime.fromtimestamp(mtime).strftime('%d%b%Y').upper()
                print(f"cocotools_wasm/lst2cmt.py -- lst2cmt WASM wrapper")
                print(f"lst2cmt.wasm: built {built} based on {ver}")

        elif args.cmd == 'help':
            if hasattr(args, 'command') and args.command:
                sys.argv = [sys.argv[0], args.command, '--help']
                parser.parse_args()
            else:
                parser.print_help()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
