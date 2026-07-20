"""
cocotools_wasm/tocgen.py -- Python wrapper around tocgen.wasm

Sierra AGI table of contents generator for CoCo Sierra games.

CLI:
    python cocotools_wasm/tocgen.py generate SIERRA.DSK OUTPUT.TOC
    python cocotools_wasm/tocgen.py version
    python cocotools_wasm/tocgen.py --help
"""

import datetime
import os
import subprocess
import sys
import tempfile

_REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WASM_DIR   = os.path.join(_REPO_ROOT, 'wasm', 'tocgen')
_TOCGEN_JS  = os.path.join(_WASM_DIR, 'tocgen.js')


def generate(srcpath, dstpath):
    """
    Generate a Sierra AGI table of contents file.

    Args:
        srcpath: input file (Sierra AGI game disk or file)
        dstpath: output TOC file

    Returns:
        0 on success
    """
    if not os.path.exists(_TOCGEN_JS):
        raise FileNotFoundError(
            f"tocgen.js not found at {_TOCGEN_JS}\n"
            "Trigger the 'Build tocgen WASM' GitHub Actions workflow."
        )

    src_data = open(srcpath, 'rb').read()
    src_arr  = ','.join(str(b) for b in src_data)

    with tempfile.TemporaryDirectory() as tmp:
        vfs_src  = '/in.dsk'
        vfs_dst  = '/out.toc'
        out_path = os.path.join(tmp, 'out.toc')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _TOCGEN_JS

        runner = f"""\
const TocgenModule = require({js!r});
const fs = require('fs');
TocgenModule().then(m => {{
    m.FS.writeFile({vfs_src!r}, new Uint8Array([{src_arr}]));
    const fn = m.cwrap('tocgen_run', 'number', ['string', 'string']);
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
        js = _TOCGEN_JS
        runner = f"""\
const TocgenModule = require({js!r});
const fs = require('fs');
TocgenModule().then(m => {{
    const fn = m.cwrap('tocgen_version', 'string', []);
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
        prog='tocgen.py',
        description='Sierra AGI table of contents generator for CoCo Sierra games'
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('generate', help='Generate TOC file',
        epilog='Example:\n  tocgen.py generate KINGSQUEST.DSK KQ.TOC',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('src', help='Input Sierra AGI game file or disk')
    p.add_argument('dst', help='Output TOC file')

    p = sub.add_parser('version', help='Show version')
    p = sub.add_parser('help', help='Show help for a command')
    p.add_argument('command', nargs='?')

    args = parser.parse_args()

    try:
        if args.cmd == 'generate':
            rc = generate(args.src, args.dst)
            if rc == 0:
                print(f"OK: {args.src} -> {args.dst}")
            else:
                print(f"ERROR: rc={rc}", file=sys.stderr)
                sys.exit(1)

        elif args.cmd == 'version':
            if not os.path.exists(_TOCGEN_JS):
                print("tocgen.wasm: NOT FOUND")
            else:
                ver = get_version()
                mtime = os.path.getmtime(_TOCGEN_JS.replace('.js', '.wasm'))
                built = datetime.datetime.fromtimestamp(mtime).strftime('%d%b%Y').upper()
                print(f"cocotools_wasm/tocgen.py -- tocgen WASM wrapper")
                print(f"tocgen.wasm: built {built} based on {ver}")

        elif args.cmd == 'help':
            if hasattr(args, 'command') and args.command:
                sys.argv = [sys.argv[0], args.command, '--help']
                parser.parse_args()
            else:
                parser.print_help()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
