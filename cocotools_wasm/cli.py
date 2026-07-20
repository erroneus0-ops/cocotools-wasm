"""
cocotools_wasm/cli.py -- Command line interface for WASM-backed CoCo tools

Usage:
    python cocotools_wasm/cli.py assemble <source.asm> -o <output.bin> [--format decb|raw|os9]
    python cocotools_wasm/cli.py makedsk <output.dsk> <file.bin> [file.bas] [--tracks 35|40|80]
    python cocotools_wasm/cli.py dskini <output.dsk> [--tracks 35|40|80]
    python cocotools_wasm/cli.py dskls <disk.dsk>
    python cocotools_wasm/cli.py version

Same interface as cocotools.py but backed by WASM builds of lwasm and toolshed.
Faithfulness is inherent -- William's and toolshed's actual C code runs.
"""

import argparse
import os
import sys

# Add repo root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def cmd_assemble(args):
    from cocotools_wasm.lwasm import assemble

    source_path = args.source
    if not os.path.exists(source_path):
        print(f"ERROR: source file not found: {source_path}", file=sys.stderr)
        sys.exit(1)

    source = open(source_path, 'r').read()
    fmt = args.format or 'decb'

    print(f"Assembling {source_path} (format={fmt})...")
    result = assemble(source, format=fmt)

    for w in result.warnings:
        loc = f"{w.file}:{w.line}" + (f":{w.col}" if w.col else "")
        print(f"WARNING {loc}: {w.message}")

    for e in result.errors:
        loc = f"{e.file}:{e.line}" + (f":{e.col}" if e.col else "")
        print(f"ERROR {loc}: {e.message}", file=sys.stderr)

    if not result.success:
        print("Assembly failed.", file=sys.stderr)
        sys.exit(1)

    output_path = args.output or os.path.splitext(source_path)[0] + '.bin'
    open(output_path, 'wb').write(result.binary)
    print(f"OK: {len(result.binary)} bytes -> {output_path}")


def cmd_dskini(args):
    from cocotools_wasm.toolshed import dskini

    tracks = args.tracks or 35
    output = args.disk

    print(f"Formatting {output} ({tracks} tracks)...")
    dsk = dskini(tracks=tracks)
    open(output, 'wb').write(dsk)
    print(f"OK: {len(dsk)} bytes -> {output}")


def cmd_makedsk(args):
    from cocotools_wasm.toolshed import dskini, copy_to_dsk
    from cocotools.decb import Dsk

    tracks = args.tracks or 35
    output = args.disk

    print(f"Creating {output} ({tracks} tracks)...")
    dsk_bytes = dskini(tracks=tracks)

    dsk = Dsk(bytearray(dsk_bytes))
    for f in args.files:
        if not os.path.exists(f):
            print(f"ERROR: file not found: {f}", file=sys.stderr)
            sys.exit(1)
        data = open(f, 'rb').read()
        name = os.path.basename(f)
        print(f"  Adding {name} ({len(data)} bytes)...")
        dsk.add_file(name, data)

    open(output, 'wb').write(bytes(dsk.to_bytes()))
    print(f"OK: {output}")


def cmd_dskls(args):
    from cocotools.decb import Dsk

    if not os.path.exists(args.disk):
        print(f"ERROR: disk not found: {args.disk}", file=sys.stderr)
        sys.exit(1)

    data = open(args.disk, 'rb').read()
    dsk = Dsk(bytearray(data))

    print(f"Directory of {args.disk}:")
    print(f"{'Name':<12} {'Ext':<4} {'Type':<6} {'Size':>6}")
    print('-' * 32)
    for entry in dsk.list_files():
        print(f"{entry['name']:<12} {entry['ext']:<4} {entry['type']:<6} {entry['size']:>6}")


def cmd_version(args):
    print("cocotools_wasm -- WASM-backed CoCo development tools")
    print("Engine: lwasm (William Astle) + toolshed, compiled via Emscripten")

    wasm_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'wasm', 'lwasm', 'lwasm.wasm'
    )
    if os.path.exists(wasm_path):
        size = os.path.getsize(wasm_path)
        mtime = os.path.getmtime(wasm_path)
        import datetime
        built = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')
        print(f"lwasm.wasm: {size:,} bytes, built {built}")
    else:
        print("lwasm.wasm: NOT FOUND (run GitHub Actions workflow to build)")


def main():
    parser = argparse.ArgumentParser(
        prog='cocotools_wasm',
        description='WASM-backed CoCo 6809 development tools'
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # assemble
    p = sub.add_parser('assemble', help='Assemble 6809 source to binary')
    p.add_argument('source', help='Assembly source file (.asm)')
    p.add_argument('-o', '--output', help='Output binary file (default: source.bin)')
    p.add_argument('--format', choices=['decb', 'raw', 'os9'], default='decb',
                   help='Output format (default: decb)')
    p.set_defaults(func=cmd_assemble)

    # dskini
    p = sub.add_parser('dskini', help='Create a blank formatted DSK image')
    p.add_argument('disk', help='Output DSK file')
    p.add_argument('--tracks', type=int, choices=[35, 40, 80], default=35,
                   help='Number of tracks (default: 35)')
    p.set_defaults(func=cmd_dskini)

    # makedsk
    p = sub.add_parser('makedsk', help='Create DSK image with files')
    p.add_argument('disk', help='Output DSK file')
    p.add_argument('files', nargs='+', help='Files to add to disk')
    p.add_argument('--tracks', type=int, choices=[35, 40, 80], default=35,
                   help='Number of tracks (default: 35)')
    p.set_defaults(func=cmd_makedsk)

    # dskls
    p = sub.add_parser('dskls', help='List files on a DSK image')
    p.add_argument('disk', help='DSK file to list')
    p.set_defaults(func=cmd_dskls)

    # version
    p = sub.add_parser('version', help='Show version and engine info')
    p.set_defaults(func=cmd_version)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
