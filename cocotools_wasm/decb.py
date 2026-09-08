"""
cocotools_wasm/discrete/decb.py -- DECB disk operations via toolshed WASM.

One of three discrete, single-purpose wrappers (decb.py / os9.py /
cecb.py) split out of the original toolshed.py, which had all three
tool families undifferentiated in one file. All three still call into
the same compiled toolshed.wasm blob -- see _common.py's docstring for
why that's a deliberate choice, not something left unfinished.

Known issue, not fixed here (a behavior change, kept separate from this
reorganization on purpose): rename() fails with rc=215 (EOS_BPNAM) if
the pathlist includes a ":N" drive-number suffix, e.g.
"disk.dsk,FILE.BIN:0" -- every other DECB function here handles that
same suffix correctly. Confirmed directly at the C level (not a
wrapper bug): _decb_rename's filename validation doesn't strip the
suffix before checking it, unlike _decb_open/_decb_create. Workaround
proven working: omit the suffix, e.g. "disk.dsk,FILE.BIN".
"""

import os
import sys
try:
    from ._common import run_wasm, csv_to_dicts, kv_to_dict
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _common import run_wasm, csv_to_dicts, kv_to_dict


def dskini(diskpath, tracks=35):
    """Create a blank, formatted DECB disk image."""
    size = tracks * 18 * 256
    rc = run_wasm(
        'ts_dskini', ['string', 'number'], ['/disk.dsk', tracks],
        output_files=[('/disk.dsk', diskpath)],
    )
    if rc != 0:
        raise RuntimeError(f"dskini failed: rc={rc}")
    return size


def copy(srcpath, dstpathlist, file_type=2, data_type=0):
    """
    Copy a local file into a DECB disk image.

    dstpathlist: 'disk.dsk,FILENAME.EXT:N' where N is drive number
                 (always 0 for a single-drive image).
    file_type:   0=BASIC, 1=data, 2=ML (default), 3=text
    data_type:   0=binary (default), 1=ASCII
    """
    comma = dstpathlist.index(',')
    disk_path = dstpathlist[:comma]
    vfs_disk = '/disk.dsk'
    vfs_dst = vfs_disk + dstpathlist[comma:]
    disk_data = open(disk_path, 'rb').read() if os.path.exists(disk_path) else b''

    rc = run_wasm(
        'ts_copy', ['string', 'string', 'number', 'number'],
        ['/src.bin', vfs_dst, file_type, data_type],
        input_files=[(srcpath, '/src.bin')] + ([(disk_path, vfs_disk)] if disk_data else []),
        output_files=[(vfs_disk, disk_path)],
    )
    if rc != 0:
        raise RuntimeError(f"copy failed: rc={rc}")
    return rc


def read(srcpathlist, dstpath):
    """Read a file out of a DECB disk image to a local path."""
    comma = srcpathlist.index(',')
    disk_path = srcpathlist[:comma]
    vfs_disk = '/disk.dsk'
    vfs_src = vfs_disk + srcpathlist[comma:]
    rc = run_wasm(
        'ts_read', ['string', 'string'], [vfs_src, '/out.bin'],
        input_files=[(disk_path, vfs_disk)],
        output_files=[('/out.bin', dstpath)],
    )
    if rc != 0:
        raise RuntimeError(f"read failed: rc={rc}")
    return rc


def dir(diskpath):
    """List the directory of a DECB disk image. Returns list of dicts."""
    vfs_disk = '/disk.dsk'
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, 'out.csv')
        rc = run_wasm(
            'ts_dir', ['string', 'string'], [vfs_disk, '/out.csv'],
            input_files=[(diskpath, vfs_disk)],
            output_files=[('/out.csv', out_path)],
        )
        if rc != 0:
            raise RuntimeError(f"dir failed: rc={rc}")
        text = open(out_path).read() if os.path.exists(out_path) else ''
    return csv_to_dicts(text)


def kill(pathlist):
    """Delete a file from a DECB disk image."""
    comma = pathlist.index(',')
    disk_path = pathlist[:comma]
    vfs_disk = '/disk.dsk'
    vfs_target = vfs_disk + pathlist[comma:]
    rc = run_wasm(
        'ts_kill', ['string'], [vfs_target],
        input_files=[(disk_path, vfs_disk)],
        output_files=[(vfs_disk, disk_path)],
    )
    if rc != 0:
        raise RuntimeError(f"kill failed: rc={rc}")
    return rc


def free(diskpath):
    """Report free space on a DECB disk image. Returns dict."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, 'out.txt')
        rc = run_wasm(
            'ts_free', ['string', 'string'], ['/disk.dsk', '/out.txt'],
            input_files=[(diskpath, '/disk.dsk')],
            output_files=[('/out.txt', out_path)],
        )
        if rc != 0:
            raise RuntimeError(f"free failed: rc={rc}")
        text = open(out_path).read() if os.path.exists(out_path) else ''
    return kv_to_dict(text)


def rename(pathlist, newname):
    """
    Rename a file on a DECB disk image.

    KNOWN BUG (see module docstring): pathlist must NOT include a
    ":N" drive suffix, unlike every other function here. Use
    "disk.dsk,OLDNAME.EXT", not "disk.dsk,OLDNAME.EXT:0".
    """
    comma = pathlist.index(',')
    disk_path = pathlist[:comma]
    vfs_disk = '/disk.dsk'
    vfs_target = vfs_disk + pathlist[comma:]
    rc = run_wasm(
        'ts_rename', ['string', 'string'], [vfs_target, newname],
        input_files=[(disk_path, vfs_disk)],
        output_files=[(vfs_disk, disk_path)],
    )
    if rc != 0:
        raise RuntimeError(f"rename failed: rc={rc}")
    return rc


def fstat(pathlist):
    """Report metadata for a single file on a DECB disk image. Returns dict."""
    comma = pathlist.index(',')
    disk_path = pathlist[:comma]
    vfs_disk = '/disk.dsk'
    vfs_target = vfs_disk + pathlist[comma:]
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, 'out.txt')
        rc = run_wasm(
            'ts_fstat', ['string', 'string'], [vfs_target, '/out.txt'],
            input_files=[(disk_path, vfs_disk)],
            output_files=[('/out.txt', out_path)],
        )
        if rc != 0:
            raise RuntimeError(f"fstat failed: rc={rc}")
        text = open(out_path).read() if os.path.exists(out_path) else ''
    return kv_to_dict(text)


if __name__ == '__main__':
    import argparse, sys

    parser = argparse.ArgumentParser(prog='decb.py', description='DECB disk operations via toolshed WASM')
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('dskini'); p.add_argument('diskpath'); p.add_argument('--tracks', type=int, default=35)
    p = sub.add_parser('copy'); p.add_argument('src'); p.add_argument('dst'); p.add_argument('--type', dest='file_type', type=int, default=2); p.add_argument('--data-type', type=int, default=0)
    p = sub.add_parser('read'); p.add_argument('src'); p.add_argument('dst')
    p = sub.add_parser('dir'); p.add_argument('diskpath')
    p = sub.add_parser('kill'); p.add_argument('pathlist')
    p = sub.add_parser('free'); p.add_argument('diskpath')
    p = sub.add_parser('rename'); p.add_argument('pathlist'); p.add_argument('newname')
    p = sub.add_parser('fstat'); p.add_argument('pathlist')

    args = parser.parse_args()
    try:
        if args.cmd == 'dskini':
            size = dskini(args.diskpath, args.tracks)
            print(f"OK: {size} bytes -> {args.diskpath}")
        elif args.cmd == 'copy':
            copy(args.src, args.dst, args.file_type, args.data_type)
            print(f"OK: {args.src} -> {args.dst}")
        elif args.cmd == 'read':
            read(args.src, args.dst)
            print(f"OK: {args.src} -> {args.dst}")
        elif args.cmd == 'dir':
            rows = dir(args.diskpath)
            print(f"{'Name':<12} {'Ext':<4} {'Type':<5} {'Data':<5} {'Gran':<5} {'Size':<6}")
            print('-' * 42)
            for r in rows:
                print(f"{r.get('name',''):<12} {r.get('ext',''):<4} {r.get('type',''):<5} "
                      f"{r.get('ascii',''):<5} {r.get('first_granule',''):<5} {r.get('last_sector_bytes',''):<6}")
        elif args.cmd == 'kill':
            kill(args.pathlist)
            print(f"OK: killed {args.pathlist}")
        elif args.cmd == 'free':
            info = free(args.diskpath)
            for k, v in info.items():
                print(f"{k}: {v}")
        elif args.cmd == 'rename':
            rename(args.pathlist, args.newname)
            print(f"OK: {args.pathlist} -> {args.newname}")
        elif args.cmd == 'fstat':
            info = fstat(args.pathlist)
            for k, v in info.items():
                print(f"{k}: {v}")
    except (RuntimeError, FileNotFoundError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
