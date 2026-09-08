"""
cocotools_wasm/discrete/os9.py -- OS-9 filesystem operations via toolshed WASM.

One of three discrete wrappers split out of the original toolshed.py --
see decb.py's module docstring for the general context.

This one is a real functional extension, not just a reorganization:
the original toolshed.py only wired up os9_dir/os9_free/os9_id, even
though the compiled WASM (toolshed_wrapper.c) exposes ts_os9_copy and
ts_os9_del too -- genuine capability that was sitting there compiled
in but never reachable from Python. Both are implemented here.

Honesty check on testing: os9_dir/os9_free/os9_id/os9_copy/os9_del
are all confirmed to at least *run* without Python-level errors (the
WASM call completes, an rc comes back), but this project has no real
OS-9 filesystem image on hand to verify against, unlike the DECB
wrapper, which was tested against real HERO disk images end to end.
Treat the OS-9 functions here as structurally correct (right C
signatures, right argument order, confirmed byte-for-byte against
toolshed_wrapper.c) but not yet verified against real OS-9 data.
"""

import os
import sys
try:
    from ._common import run_wasm, kv_to_dict
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _common import run_wasm, kv_to_dict


def _split_disk(pathlist):
    comma = pathlist.index(',')
    return pathlist[:comma], pathlist[comma:]


def os9_dir(pathlist):
    """List a directory on an OS-9 image, e.g. 'image.os9,/DD'. Returns text."""
    disk_path, rest = _split_disk(pathlist)
    vfs_disk = '/image.os9'
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, 'out.txt')
        rc = run_wasm(
            'ts_os9_dir', ['string', 'string'], [vfs_disk + rest, '/out.txt'],
            input_files=[(disk_path, vfs_disk)],
            output_files=[('/out.txt', out_path)],
        )
        if rc != 0:
            raise RuntimeError(f"os9_dir failed: rc={rc}")
        return open(out_path).read() if os.path.exists(out_path) else ''


def os9_copy(srcpathlist, dstpathlist):
    """
    Copy a file within/into an OS-9 image.

    Both args are 'image.os9,/path/to/file' pathlists. Unlike os9_dir/
    os9_free/os9_id, ts_os9_copy takes no separate outpath -- the
    change happens directly on the image, so this writes the modified
    image back to srcpathlist's disk file (matching how decb.copy()
    handles the same shape of operation).
    """
    src_disk, src_rest = _split_disk(srcpathlist)
    dst_disk, dst_rest = _split_disk(dstpathlist)
    if src_disk != dst_disk:
        raise ValueError(
            "os9_copy: src and dst must be the same image for this wrapper "
            f"(got {src_disk!r} vs {dst_disk!r}) -- cross-image copy isn't "
            "wired up here yet."
        )
    vfs_disk = '/image.os9'
    rc = run_wasm(
        'ts_os9_copy', ['string', 'string'],
        [vfs_disk + src_rest, vfs_disk + dst_rest],
        input_files=[(src_disk, vfs_disk)],
        output_files=[(vfs_disk, src_disk)],
    )
    if rc != 0:
        raise RuntimeError(f"os9_copy failed: rc={rc}")
    return rc


def os9_del(pathlist):
    """Delete a file from an OS-9 image."""
    disk_path, rest = _split_disk(pathlist)
    vfs_disk = '/image.os9'
    rc = run_wasm(
        'ts_os9_del', ['string'], [vfs_disk + rest],
        input_files=[(disk_path, vfs_disk)],
        output_files=[(vfs_disk, disk_path)],
    )
    if rc != 0:
        raise RuntimeError(f"os9_del failed: rc={rc}")
    return rc


def os9_free(imagepath_with_comma):
    """Report free space on an OS-9 image. Returns dict."""
    disk_path, rest = _split_disk(imagepath_with_comma)
    vfs_disk = '/image.os9'
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, 'out.txt')
        rc = run_wasm(
            'ts_os9_free', ['string', 'string'], [vfs_disk + rest, '/out.txt'],
            input_files=[(disk_path, vfs_disk)],
            output_files=[('/out.txt', out_path)],
        )
        if rc != 0:
            raise RuntimeError(f"os9_free failed: rc={rc}")
        text = open(out_path).read() if os.path.exists(out_path) else ''
    return kv_to_dict(text)


def os9_id(imagepath_with_comma):
    """Report OS-9 image identification. Returns dict."""
    disk_path, rest = _split_disk(imagepath_with_comma)
    vfs_disk = '/image.os9'
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, 'out.txt')
        rc = run_wasm(
            'ts_os9_id', ['string', 'string'], [vfs_disk + rest, '/out.txt'],
            input_files=[(disk_path, vfs_disk)],
            output_files=[('/out.txt', out_path)],
        )
        if rc != 0:
            raise RuntimeError(f"os9_id failed: rc={rc}")
        text = open(out_path).read() if os.path.exists(out_path) else ''
    return kv_to_dict(text)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(prog='os9.py', description='OS-9 image operations via toolshed WASM')
    sub = parser.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('dir'); p.add_argument('pathlist', help='e.g. image.os9,/DD')
    p = sub.add_parser('copy'); p.add_argument('src'); p.add_argument('dst')
    p = sub.add_parser('del'); p.add_argument('pathlist')
    p = sub.add_parser('free'); p.add_argument('pathlist')
    p = sub.add_parser('id'); p.add_argument('pathlist')

    args = parser.parse_args()
    try:
        if args.cmd == 'dir':
            print(os9_dir(args.pathlist), end='')
        elif args.cmd == 'copy':
            os9_copy(args.src, args.dst)
            print(f"OK: {args.src} -> {args.dst}")
        elif args.cmd == 'del':
            os9_del(args.pathlist)
            print(f"OK: deleted {args.pathlist}")
        elif args.cmd == 'free':
            for k, v in os9_free(args.pathlist).items():
                print(f"{k}: {v}")
        elif args.cmd == 'id':
            for k, v in os9_id(args.pathlist).items():
                print(f"{k}: {v}")
    except (RuntimeError, FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=__import__('sys').stderr)
        __import__('sys').exit(1)
