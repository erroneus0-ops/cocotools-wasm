"""
cocotools_wasm/discrete/cecb.py -- CECB (cassette) operations via toolshed WASM.

One of three discrete wrappers split out of the original toolshed.py --
see decb.py's module docstring for the general context.
"""

import os
import sys
try:
    from ._common import run_wasm
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _common import run_wasm


def cecb_bulkerase(caspath):
    """Create/erase a CAS file (bulk erase = create a blank cassette image)."""
    rc = run_wasm(
        'ts_cecb_bulkerase', ['string'], ['/out.cas'],
        output_files=[('/out.cas', caspath)],
    )
    if rc != 0:
        raise RuntimeError(f"cecb_bulkerase failed: rc={rc}")
    return rc


def cecb_copy(srcpath, dstpathlist, file_type=2, load_addr='', exec_addr=''):
    """
    Copy a binary file into a CAS image.

    dstpathlist: destination CAS pathlist (e.g. 'DISK.CAS,HELLO').
                 CECB format uses no drive number (':0') -- any such
                 suffix is stripped automatically below.
    file_type:   0=BASIC, 1=data, 2=ML (default), 3=text
    load_addr:   load address as hex string (e.g. '3F00')
    exec_addr:   exec address as hex string (e.g. '3F00')
    """
    comma = dstpathlist.index(',')
    cas_path = dstpathlist[:comma]
    dstpathlist = dstpathlist.split(':')[0]  # CECB has no drive number

    # Matches the native cecb.exe CLI directly, e.g.:
    #   copy -2 -n -d0x3F00 -e0x3F00 /in.bin /out.cas,HELLO
    # -n: no gap -- required to trigger DECB header stripping for ML files.
    # Addresses always given the 0x prefix explicitly (after stripping any
    # the caller may have already added) -- native cecbcopy parses addresses
    # with strtol(..., 0), which treats a bare leading "0" as octal, so a
    # hex address like $0400 would silently misread as octal without this.
    flags = [f'-{int(file_type)}', '-n']
    if load_addr:
        flags.append('-d0x' + load_addr.lower().removeprefix('0x'))
    if exec_addr:
        flags.append('-e0x' + exec_addr.lower().removeprefix('0x'))

    vfs_cas = '/out.cas'
    vfs_src = '/in.bin'
    vfs_dst = vfs_cas + dstpathlist[comma:]
    cmdstr = 'copy ' + ' '.join(flags) + f' {vfs_src} {vfs_dst}'

    rc = run_wasm(
        'ts_cecb_run', ['string'], [cmdstr],
        input_files=[(srcpath, vfs_src)] + (
            [(cas_path, vfs_cas)] if os.path.exists(cas_path) else []
        ),
        output_files=[(vfs_cas, cas_path)],
    )
    if rc != 0:
        raise RuntimeError(f"cecb_copy failed: rc={rc}")
    return rc


def cecb_dir(caspath):
    """List files on a CAS image. Returns text."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, 'out.txt')
        rc = run_wasm(
            'ts_cecb_dir', ['string', 'string'], ['/in.cas', '/out.txt'],
            input_files=[(caspath, '/in.cas')],
            output_files=[('/out.txt', out_path)],
        )
        if rc != 0:
            raise RuntimeError(f"cecb_dir failed: rc={rc}")
        return open(out_path).read() if os.path.exists(out_path) else ''


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(prog='cecb.py', description='CECB (cassette) operations via toolshed WASM')
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('bulkerase'); p.add_argument('cas')
    p = sub.add_parser('copy')
    p.add_argument('src'); p.add_argument('dst')
    p.add_argument('--type', dest='file_type', type=int, default=2)
    p.add_argument('--load', dest='load_addr', default='')
    p.add_argument('--exec', dest='exec_addr', default='')
    p = sub.add_parser('dir'); p.add_argument('cas')

    args = parser.parse_args()
    try:
        if args.cmd == 'bulkerase':
            cecb_bulkerase(args.cas)
            print(f"OK: {args.cas}")
        elif args.cmd == 'copy':
            cecb_copy(args.src, args.dst, args.file_type, args.load_addr, args.exec_addr)
            print(f"OK: {args.src} -> {args.dst}")
        elif args.cmd == 'dir':
            print(cecb_dir(args.cas), end='')
    except (RuntimeError, FileNotFoundError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
