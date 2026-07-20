"""
cocotools_wasm/ar2.py -- Python wrapper around ar2.wasm

OS-9/NitrOS-9 archive manager. Extract, list, and add files in .ar archives.

Note: delete operations (ftruncate) are stubbed -- list, extract, and add work.

CLI:
    python cocotools_wasm/ar2.py list ARCHIVE.AR
    python cocotools_wasm/ar2.py extract ARCHIVE.AR
    python cocotools_wasm/ar2.py version
    python cocotools_wasm/ar2.py --help
"""

import datetime
import os
import subprocess
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WASM_DIR  = os.path.join(_REPO_ROOT, 'wasm', 'ar2')
_AR2_JS    = os.path.join(_WASM_DIR, 'ar2.js')


def _run(args_str, input_files=None, output_dir=None):
    """
    Run ar2 with the given argument string.
    args_str: space-separated ar2 arguments (e.g. "-t archive.ar")
    """
    if not os.path.exists(_AR2_JS):
        raise FileNotFoundError(
            f"ar2.js not found at {_AR2_JS}\n"
            "Trigger the 'Build ar2 WASM' GitHub Actions workflow."
        )

    with tempfile.TemporaryDirectory() as tmp:
        rc_path  = os.path.join(tmp, 'rc.txt')
        out_path = os.path.join(tmp, 'stdout.txt')
        js = _AR2_JS

        # Write input files to virtual FS
        setup_parts = []
        if input_files:
            for local, vfs in input_files:
                data = open(local, 'rb').read()
                arr = ','.join(str(b) for b in data)
                setup_parts.append(f"m.FS.writeFile({vfs!r}, new Uint8Array([{arr}]));")

        setup = '\n    '.join(setup_parts)

        runner = f"""\
const Ar2Module = require({js!r});
const fs = require('fs');
Ar2Module().then(m => {{
    {setup}
    // Capture stdout
    let output = '';
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk) => {{ output += chunk; return true; }};

    const fn = m.cwrap('ar2_run', 'number', ['string']);
    let rc;
    try {{ rc = fn({args_str!r}); }}
    catch(e) {{ rc = e.name === 'ExitStatus' ? e.status : 2; }}

    process.stdout.write = origWrite;
    fs.writeFileSync({out_path!r}, output);
    fs.writeFileSync({rc_path!r}, String(rc));
    process.exit(0);
}});
"""
        run_path = os.path.join(tmp, 'run.js')
        open(run_path, 'w').write(runner)
        proc = subprocess.run(['node', run_path], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"Node.js runner failed:\n{proc.stderr}")

        rc = int(open(rc_path).read().strip()) if os.path.exists(rc_path) else -1
        stdout = open(out_path).read() if os.path.exists(out_path) else proc.stdout
        return rc, stdout


def list_archive(archivepath):
    """List contents of an ar2 archive. Returns (rc, output_text)."""
    vfs_ar = '/archive.ar'
    rc, out = _run(f"-t {vfs_ar}", input_files=[(archivepath, vfs_ar)])
    return rc, out


def get_version():
    with tempfile.TemporaryDirectory() as tmp:
        ver_path = os.path.join(tmp, 'ver.txt')
        js = _AR2_JS
        runner = f"""\
const Ar2Module = require({js!r});
const fs = require('fs');
Ar2Module().then(m => {{
    const fn = m.cwrap('ar2_version', 'string', []);
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
        prog='ar2.py',
        description='OS-9/NitrOS-9 archive manager\nNote: delete operations are stubbed -- list and extract work.',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('list', help='List archive contents',
        epilog='Example:\n  ar2.py list CMDS.AR',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('archive', help='ar2 archive file (.ar)')

    p = sub.add_parser('run', help='Run ar2 with raw arguments',
        epilog='Example:\n  ar2.py run "-t CMDS.AR"',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('args', help='ar2 arguments as a quoted string')

    p = sub.add_parser('version', help='Show version')
    p = sub.add_parser('help', help='Show help for a command')
    p.add_argument('command', nargs='?')

    args = parser.parse_args()

    try:
        if args.cmd == 'list':
            rc, output = list_archive(args.archive)
            print(output, end='')
            if rc != 0:
                sys.exit(rc)

        elif args.cmd == 'run':
            rc, output = _run(args.args)
            print(output, end='')
            if rc != 0:
                sys.exit(rc)

        elif args.cmd == 'version':
            if not os.path.exists(_AR2_JS):
                print("ar2.wasm: NOT FOUND")
            else:
                ver = get_version()
                mtime = os.path.getmtime(_AR2_JS.replace('.js', '.wasm'))
                built = datetime.datetime.fromtimestamp(mtime).strftime('%d%b%Y').upper()
                print(f"cocotools_wasm/ar2.py -- ar2 WASM wrapper")
                print(f"ar2.wasm: built {built} based on {ver}")

        elif args.cmd == 'help':
            if hasattr(args, 'command') and args.command:
                sys.argv = [sys.argv[0], args.command, '--help']
                parser.parse_args()
            else:
                parser.print_help()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
