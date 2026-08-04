#!/bin/bash
# build.sh -- compile toolshed as monolithic WASM (DECB + OS-9 + CECB)
#
# Run from: wasm/toolshed/
# toolshed source expected at: ../../emcc_workflow/toolshed-X.Y.Z/
# Output: toolshed.js + toolshed.wasm

set -e

# Auto-detect toolshed directory under emcc_workflow/ (all emcc-targeted
# source trees live there, keeping the repo root itself free of build source)
if [ -z "$TOOLSHED" ]; then
    TOOLSHED=$(find $(cd ../.. && pwd)/emcc_workflow -maxdepth 1 -type d -name "toolshed-*" | sort -V | tail -1)
    if [ -z "$TOOLSHED" ]; then
        echo "ERROR: no toolshed-* directory found in emcc_workflow/"
        exit 1
    fi
fi

LIBDECB="$TOOLSHED/libdecb"
LIBNATIVE="$TOOLSHED/libnative"
LIBMISC="$TOOLSHED/libmisc"
LIBCOCO="$TOOLSHED/libcoco"
LIBRBF="$TOOLSHED/librbf"
LIBCECB="$TOOLSHED/libcecb"
DECB="$TOOLSHED/decb"
OS9="$TOOLSHED/os9"
CECB="$TOOLSHED/cecb"
INCLUDE="$TOOLSHED/include"

# Extract version from toolshed build system -- same source as native tools
TS_VERSION=$(grep "^VERSION" "$TOOLSHED/build/unix/rules.mak" | awk '{print $3}')
echo "Building toolshed WASM (monolithic)..."
echo "  toolshed: $TOOLSHED"
echo "  version:  $TS_VERSION"

# Excluded files -- Emscripten libc compatibility issues
# Scan with: grep -rl "_fileno|ftruncate|digittoint" toolshed-NEW/lib*/
#
# libdecbsrec.c used digittoint() (BSD extension) -- NO LONGER EXCLUDED.
#   emcc_workflow/emscripten_libc_shims.c (shared across projects, not
#   toolshed-specific) now provides a real digittoint() implementation
#   (it's a genuinely trivial, portable function), so this file compiles
#   completely unmodified and its S-record encode/decode actually works,
#   rather than being permanently stubbed to an error.
#
# libnativegs.c:  path->fd->_fileno -- glibc internal, still excluded.
# libnativess.c:  ftruncate with _fileno -- same root cause as above,
#   still excluded. Unlike digittoint, this genuinely can't be fixed by
#   providing a same-named replacement -- _fileno is a struct field
#   access tied to glibc's own internal layout, not a portable function
#   call. The real fix, if this functionality is ever actually needed,
#   is a small source patch to these two files: replace fd->_fileno with
#   fileno(fd) (the standard, portable function), which Emscripten's
#   libc does support correctly. Not done here since native_gs/ss
#   functions are never called in practice in this WASM build (all
#   paths are virtual filesystem paths).

LIBDECB_SRCS=$(find "$LIBDECB" -name "*.c" | tr '\n' ' ')
LIBRBF_SRCS=$(find "$LIBRBF" -name "*.c" | tr '\n' ' ')
LIBCECB_SRCS=$(find "$LIBCECB" -name "*.c" | tr '\n' ' ')
LIBCOCO_SRCS=$(find "$LIBCOCO" -name "*.c" | tr '\n' ' ')

LIBNATIVE_SRCS="
    $LIBNATIVE/libnativeopen.c
    $LIBNATIVE/libnativewrite.c
    $LIBNATIVE/libnativeseek.c
    $LIBNATIVE/libnativeread.c
    $LIBNATIVE/libnativereadln.c
    $LIBNATIVE/libnativedelete.c
    $LIBNATIVE/libnativerename.c
    $LIBNATIVE/libnativemakdir.c
"

# os9diskfuncs.c excluded from libmisc: duplicate read_lsn with librbfread.c
LIBMISC_SRCS=$(find "$LIBMISC" -name "*.c" ! -name "os9diskfuncs.c" | tr '\n' ' ')

LIBSYS="$TOOLSHED/libsys"
LIBSYS_SRCS=$(find "$LIBSYS" -name "*.c" | tr '\n' ' ')

LIBTOOLSHED="$TOOLSHED/libtoolshed"
LIBTOOLSHED_SRCS=$(find "$LIBTOOLSHED" -name "*.c" | tr '\n' ' ')

# CLI source files -- rename main() to avoid conflicts
DECB_SRCS=$(find "$DECB" -name "*.c" ! -name "decb_main.c" ! -name "decbcopy.c" | tr '\n' ' ')
OS9_SRCS=$(find "$OS9" -name "*.c" ! -name "os9_main.c" | tr '\n' ' ')
CECB_SRCS=$(find "$CECB" -name "*.c" ! -name "cecb_main.c" | tr '\n' ' ')

EXPORTED='["_ts_version","_ts_dskini","_ts_copy","_ts_read","_ts_dir","_ts_kill","_ts_free","_ts_rename","_ts_fstat","_ts_os9_dir","_ts_os9_copy","_ts_os9_del","_ts_os9_free","_ts_os9_id","_ts_cecb_run","_ts_cecb_dir","_ts_cecb_bulkerase"]'

emcc \
    toolshed_wrapper.c \
    native_stubs.c \
    ../../emcc_workflow/emscripten_libc_shims.c \
    $LIBDECB_SRCS \
    $LIBRBF_SRCS \
    $LIBCECB_SRCS \
    $LIBCOCO_SRCS \
    $LIBNATIVE_SRCS \
    $LIBMISC_SRCS \
    $LIBSYS_SRCS \
    $LIBTOOLSHED_SRCS \
    $DECB_SRCS \
    $OS9_SRCS \
    $CECB_SRCS \
    -I"$INCLUDE" \
    -I../../emcc_workflow \
    -include ../../emcc_workflow/emscripten_libc_shims.h \
    -DTOOLSHED_VERSION=\"$TS_VERSION\" \
    -o toolshed.js \
    -s EXPORTED_FUNCTIONS="$EXPORTED" \
    -s EXPORTED_RUNTIME_METHODS='["FS","ccall","cwrap"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='ToolshedModule' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s FORCE_FILESYSTEM=1 \
    -s EXIT_RUNTIME=0 \
    -s INVOKE_RUN=0 \
    -O2

echo "Done. Output: toolshed.js + toolshed.wasm"
