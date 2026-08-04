#!/bin/bash
set -e

if [ -z "$TOOLSHED" ]; then
    TOOLSHED=$(find $(cd ../.. && pwd)/emcc_workflow -maxdepth 1 -type d -name "toolshed-*" | sort -V | tail -1)
fi

TS_VERSION=$(grep "^VERSION" "$TOOLSHED/build/unix/rules.mak" | awk '{print $3}')
INCLUDE="$TOOLSHED/include"

echo "Building tocgen WASM..."
echo "  toolshed: $TOOLSHED ($TS_VERSION)"

# tocgen uses libcoco routing layer which requires all three format libraries
LIBDECB_SRCS=$(find "$TOOLSHED/libdecb" -name "*.c" ! -name "libdecbsrec.c" | tr '\n' ' ')
LIBRBF_SRCS=$(find "$TOOLSHED/librbf" -name "*.c" | tr '\n' ' ')
LIBCECB_SRCS=$(find "$TOOLSHED/libcecb" -name "*.c" | tr '\n' ' ')
LIBCOCO_SRCS=$(find "$TOOLSHED/libcoco" -name "*.c" | tr '\n' ' ')
LIBMISC_SRCS=$(find "$TOOLSHED/libmisc" -name "*.c" ! -name "os9diskfuncs.c" | tr '\n' ' ')
LIBSYS_SRCS=$(find "$TOOLSHED/libsys" -name "*.c" | tr '\n' ' ')
LIBTOOLSHED_SRCS=$(find "$TOOLSHED/libtoolshed" -name "*.c" | tr '\n' ' ')
LIBNATIVE_SRCS="
    $TOOLSHED/libnative/libnativeopen.c
    $TOOLSHED/libnative/libnativewrite.c
    $TOOLSHED/libnative/libnativeseek.c
    $TOOLSHED/libnative/libnativeread.c
    $TOOLSHED/libnative/libnativereadln.c
    $TOOLSHED/libnative/libnativedelete.c
    $TOOLSHED/libnative/libnativerename.c
    $TOOLSHED/libnative/libnativemakdir.c
"

emcc \
    tocgen_wrapper.c \
    ../toolshed/native_stubs.c \
    "$TOOLSHED/tocgen/tocgen_main.c" \
    $LIBDECB_SRCS \
    $LIBRBF_SRCS \
    $LIBCECB_SRCS \
    $LIBCOCO_SRCS \
    $LIBNATIVE_SRCS \
    $LIBMISC_SRCS \
    $LIBSYS_SRCS \
    $LIBTOOLSHED_SRCS \
    -I"$INCLUDE" \
    -Dmain=tocgen_main \
    -DTOOLSHED_VERSION=\"$TS_VERSION\" \
    -o tocgen.js \
    -s EXPORTED_FUNCTIONS='["_tocgen_version","_tocgen_run"]' \
    -s EXPORTED_RUNTIME_METHODS='["FS","ccall","cwrap"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='TocgenModule' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s FORCE_FILESYSTEM=1 \
    -s EXIT_RUNTIME=0 \
    -s INVOKE_RUN=0 \
    -O2

echo "source: toolshed-$TS_VERSION" > VERSION
echo "built: $(date -u '+%d%b%Y')" >> VERSION
echo "Done."
