#!/bin/bash
set -e

if [ -z "$TOOLSHED" ]; then
    TOOLSHED=$(find $(cd ../.. && pwd)/emcc_workflow -maxdepth 1 -type d -name "toolshed-*" | sort -V | tail -1)
fi

TS_VERSION=$(grep "^VERSION" "$TOOLSHED/build/unix/rules.mak" | awk '{print $3}')
INCLUDE="$TOOLSHED/include"
LIBMISC="$TOOLSHED/libmisc"
AR2="$TOOLSHED/ar2"

echo "Building ar2 WASM..."
echo "  toolshed: $TOOLSHED ($TS_VERSION)"

LIBMISC_SRCS=$(find "$LIBMISC" -name "*.c" ! -name "os9diskfuncs.c" | tr '\n' ' ')
# sys_dir.h has compatibility issues -- ar2/o2u.c includes it but we exclude o2u.c
AR2_SRCS="$AR2/ar.c $AR2/arsup.c $AR2/lz1.c"

emcc \
    ar2_wrapper.c \
    ar2_stubs.c \
    $AR2_SRCS \
    $LIBMISC_SRCS \
    -I"$INCLUDE" \
    -I"$(pwd)" \
    -include ar2_compat.h \
    -Wno-int-conversion \
    -Wno-incompatible-pointer-types \
    -I"$AR2" \
    -Dmain=ar2_main \
    -DCKLIB \
    -DTOOLSHED_VERSION=\"$TS_VERSION\" \
    -o ar2.js \
    -s EXPORTED_FUNCTIONS='["_ar2_version","_ar2_run"]' \
    -s EXPORTED_RUNTIME_METHODS='["FS","ccall","cwrap"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='Ar2Module' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s FORCE_FILESYSTEM=1 \
    -s EXIT_RUNTIME=0 \
    -s INVOKE_RUN=0 \
    -O2

echo "source: toolshed-$TS_VERSION" > VERSION
echo "built: $(date -u '+%d%b%Y')" >> VERSION
echo "Done."
