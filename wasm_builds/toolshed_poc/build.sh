#!/bin/bash
# build.sh -- compile toolshed dskini to WASM using Emscripten
#
# Prerequisites:
#   - Emscripten installed and activated (source ~/emsdk/emsdk_env.sh)
#   - toolshed cloned at ~/src/toolshed
#
# Run from: wasm/toolshed_poc/
#
# Output:
#   dskini.js    -- Emscripten-generated JS loader
#   dskini.wasm  -- the WASM binary

set -e

#TOOLSHED="${TOOLSHED:-$HOME/src/toolshed}"
TOOLSHED="${TOOLSHED:-/mnt/d/git/toolshed}"
INCLUDE="$TOOLSHED/include"
LIBDECB="$TOOLSHED/libdecb"
LIBNATIVE="$TOOLSHED/libnative"
LIBMISC="$TOOLSHED/libmisc"

echo "Building dskini WASM..."
echo "  toolshed: $TOOLSHED"

# Compile all native library sources needed by _decb_dskini
NATIVE_SRCS="
    $LIBNATIVE/libnativeopen.c
    $LIBNATIVE/libnativewrite.c
    $LIBNATIVE/libnativeseek.c
"

# libmisc provides UnixToCoCoError and other shared utilities
MISC_SRCS="
    $LIBMISC/libmiscutil.c
    $LIBMISC/libmisccococonv.c
    $LIBMISC/libmiscendian.c
"

# The core dskini library source
DECB_SRC="$LIBDECB/libdecbdskini.c"

emcc \
    dskini_wrapper.c \
    $DECB_SRC \
    $NATIVE_SRCS \
    $MISC_SRCS \
    -I"$INCLUDE" \
    -o dskini.js \
    -s EXPORTED_FUNCTIONS='["_dskini"]' \
    -s EXPORTED_RUNTIME_METHODS='["FS"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='DskiniModule' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -O2

echo "Done. Output: dskini.js + dskini.wasm"
echo ""
echo "Test with Node.js:"
echo "  node -e \"DskiniModule = require('./dskini.js'); DskiniModule().then(m => { const r = m._dskini(35); console.log('result:', r); console.log('size:', m.FS.readFile('/out.dsk').length); })\""
