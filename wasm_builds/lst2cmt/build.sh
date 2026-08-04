#!/bin/bash
set -e

if [ -z "$TOOLSHED" ]; then
    TOOLSHED=$(find $(cd ../.. && pwd)/emcc_workflow -maxdepth 1 -type d -name "toolshed-*" | sort -V | tail -1)
fi

TS_VERSION=$(grep "^VERSION" "$TOOLSHED/build/unix/rules.mak" | awk '{print $3}')
INCLUDE="$TOOLSHED/include"
LIBMISC="$TOOLSHED/libmisc"

echo "Building lst2cmt WASM..."
echo "  toolshed: $TOOLSHED ($TS_VERSION)"

LIBMISC_SRCS=$(find "$LIBMISC" -name "*.c" ! -name "os9diskfuncs.c" | tr '\n' ' ')

emcc \
    lst2cmt_wrapper.c \
    "$TOOLSHED/lst2cmt/lst2cmt.c" \
    $LIBMISC_SRCS \
    -I"$INCLUDE" \
    -Dmain=lst2cmt_main \
    -DTOOLSHED_VERSION=\"$TS_VERSION\" \
    -o lst2cmt.js \
    -s EXPORTED_FUNCTIONS='["_lst2cmt_version","_lst2cmt_convert"]' \
    -s EXPORTED_RUNTIME_METHODS='["FS","ccall","cwrap"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='Lst2cmtModule' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s FORCE_FILESYSTEM=1 \
    -s EXIT_RUNTIME=0 \
    -s INVOKE_RUN=0 \
    -O2

echo "source: toolshed-$TS_VERSION" > VERSION
echo "built: $(date -u '+%d%b%Y')" >> VERSION
echo "Done."
