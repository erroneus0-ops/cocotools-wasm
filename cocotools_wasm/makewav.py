"""
cocotools_wasm/makewav.py -- Python wrapper around makewav.wasm

Converts CoCo binary files to cassette WAV files for loading via tape.

CLI:
    python cocotools_wasm/makewav.py convert HELLO.BIN HELLO.WAV
    python cocotools_wasm/makewav.py version
    python cocotools_wasm/makewav.py --help
"""

import datetime
import os
import subprocess
import sys
import tempfile

_REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WASM_DIR   = os.path.join(_REPO_ROOT, 'wasm', 'makewav')
_MAKEWAV_JS = os.path.join(_WASM_DIR, 'makewav.js')


def convert(srcpath, dstpath):
    """
    Convert a CoCo binary to a cassette WAV file.

    Args:
        srcpath: input binary file
        dstpath: output WAV file

    Returns:
        0 on success
    """
    if not os.path.exists(_MAKEWAV_JS):
        raise FileNotFoundError(
            f"makewav.js not found at {_MAKEWAV_JS}\n"
            "Trigger the 'Build makewav WASM' GitHub Actions workflow."
        )

    src_data = open(srcpath, 'rb').read()
    src_arr  = ','.join(str(b) for b in src_data)

    with tempfile.TemporaryDirectory() as tmp:
        vfs_src  = '/in.bin'
        vfs_dst  = '/out.wav'
        out_path = os.path.join(tmp, 'out.wav')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _MAKEWAV_JS

        runner = f"""\
const MakewavModule = require({js!r});
const fs = require('fs');
MakewavModule().then(m => {{
    m.FS.writeFile({vfs_src!r}, new Uint8Array([{src_arr}]));
    const fn = m.cwrap('makewav_run', 'number', ['string', 'string']);
    let rc;
    try {{ rc = fn({vfs_src!r}, {vfs_dst!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}
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
    with tempfile.TemporaryDirectory() as tmp:
        ver_path = os.path.join(tmp, 'ver.txt')
        js = _MAKEWAV_JS
        runner = f"""\
const MakewavModule = require({js!r});
const fs = require('fs');
MakewavModule().then(m => {{
    const fn = m.cwrap('makewav_version', 'string', []);
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
    import argparse

    parser = argparse.ArgumentParser(
        prog='makewav.py',
        description='Convert CoCo binary files to cassette WAV files'
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('convert', help='Convert binary to WAV',
        epilog='Example:\n  makewav.py convert HELLO.BIN HELLO.WAV',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('src', help='Input binary file')
    p.add_argument('dst', help='Output WAV file')

    p = sub.add_parser('version', help='Show version')
    p = sub.add_parser('help', help='Show help for a command')
    p.add_argument('command', nargs='?')

    args = parser.parse_args()

    try:
        if args.cmd == 'convert':
            rc = convert(args.src, args.dst)
            if rc == 0:
                size = os.path.getsize(args.dst)
                print(f"OK: {args.src} -> {args.dst} ({size:,} bytes)")
            else:
                print(f"ERROR: rc={rc}", file=sys.stderr)
                sys.exit(1)

        elif args.cmd == 'version':
            if not os.path.exists(_MAKEWAV_JS):
                print("makewav.wasm: NOT FOUND")
            else:
                ver = get_version()
                mtime = os.path.getmtime(_MAKEWAV_JS.replace('.js', '.wasm'))
                built = datetime.datetime.fromtimestamp(mtime).strftime('%d%b%Y').upper()
                print(f"cocotools_wasm/makewav.py -- makewav WASM wrapper")
                print(f"makewav.wasm: built {built} based on {ver}")

        elif args.cmd == 'help':
            if hasattr(args, 'command') and args.command:
                sys.argv = [sys.argv[0], args.command, '--help']
                parser.parse_args()
            else:
                parser.print_help()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
