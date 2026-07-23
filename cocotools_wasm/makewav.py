"""
cocotools_wasm/makewav.py -- Python wrapper around makewav.wasm

Converts CoCo binary files to cassette WAV or CAS files for loading via tape.
XRoar accepts both WAV (audio) and CAS (digital) cassette formats.

CLI:
    python cocotools_wasm/makewav.py convert HELLO.BIN HELLO.WAV
    python cocotools_wasm/makewav.py convert HELLO.BIN HELLO.CAS --cas
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


def convert(srcpath, dstpath, cas=False, raw=True, decb=False, sample_rate=None):
    """
    Convert a file to a cassette WAV or CAS file.

    Args:
        srcpath: input file
        dstpath: output WAV or CAS file
        cas:     if True, output CAS format (-k flag)
        raw:     if True, treat input as raw binary (-r flag)
        decb:    if True, input has DECB header (-c flag)

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
    fn_name  = 'makewav_run_cas' if cas else 'makewav_run_raw'  # raw is default
    # sample_rate passed via fn_name for now -- WASM has 9600 hardcoded
    vfs_ext  = '.cas' if cas else '.wav'

    with tempfile.TemporaryDirectory() as tmp:
        vfs_src  = '/in.bin'
        vfs_dst  = f'/out{vfs_ext}'
        out_path = os.path.join(tmp, f'out{vfs_ext}')
        rc_path  = os.path.join(tmp, 'rc.txt')
        js = _MAKEWAV_JS

        runner = f"""\
const MakewavModule = require({js!r});
const fs = require('fs');
MakewavModule().then(m => {{
    m.FS.writeFile({vfs_src!r}, new Uint8Array([{src_arr}]));
    const fn = m.cwrap({fn_name!r}, 'number', ['string', 'string']);
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
        description='makewav -- S-record/binary to CoCo cassette WAV/CAS file',
        epilog='Examples:\n'
               '  makewav.py -r -o HELLO.WAV HELLO.BIN          (raw binary to WAV)\n'
               '  makewav.py -r -k -o HELLO.CAS HELLO.BIN       (raw binary to CAS)\n'
               '  makewav.py -c -r -o HELLO.WAV HELLO.BIN       (DECB binary to WAV)\n'
               '  makewav.py version                             (show version)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input', nargs='?', help='Input file (S-record or binary)')
    parser.add_argument('-r', action='store_true', dest='raw',
                        help='Treat input as raw binary (not S-record)')
    parser.add_argument('-c', action='store_true', dest='decb',
                        help='Input file has DECB header')
    parser.add_argument('-k', action='store_true', dest='cas',
                        help='Output CAS format instead of WAV')
    parser.add_argument('-s', dest='sample_rate', metavar='RATE',
                        help='Sample rate in Hz (default: 9600, match XRoar)')
    parser.add_argument('-n', dest='name', metavar='NAME',
                        help='Filename to encode in tape header (default: FILE)')
    parser.add_argument('-o', dest='output', metavar='FILE',
                        help='Output filename (default: file.wav or file.cas)')
    parser.add_argument('version', nargs='?', help=argparse.SUPPRESS)

    args = parser.parse_args()

    try:
        # Handle version subcommand
        if args.input == 'version' or args.version == 'version':
            if not os.path.exists(_MAKEWAV_JS):
                print("makewav.wasm: NOT FOUND")
            else:
                ver = get_version()
                mtime = os.path.getmtime(_MAKEWAV_JS.replace('.js', '.wasm'))
                built = datetime.datetime.fromtimestamp(mtime).strftime('%d%b%Y').upper()
                print(f"cocotools_wasm/makewav.py -- makewav WASM wrapper")
                print(f"makewav.wasm: built {built} based on {ver}")
            sys.exit(0)

        if not args.input:
            parser.print_help()
            sys.exit(0)

        # Determine output filename
        dst = args.output
        if not dst:
            base = os.path.splitext(args.input)[0]
            dst = base + ('.cas' if args.cas else '.wav')

        rc = convert(args.input, dst, cas=args.cas, sample_rate=args.sample_rate)
        if rc == 0:
            size = os.path.getsize(dst)
            fmt = 'CAS' if args.cas else 'WAV'
            print(f"OK: {args.input} -> {dst} ({fmt}, {size:,} bytes)")
        else:
            print(f"ERROR: rc={rc}", file=sys.stderr)
            sys.exit(1)

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
