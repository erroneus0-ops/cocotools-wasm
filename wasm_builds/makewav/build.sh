#!/bin/bash
set -e

if [ -z "$TOOLSHED" ]; then
    TOOLSHED=$(find $(cd ../.. && pwd)/emcc_workflow -maxdepth 1 -type d -name "toolshed-*" | sort -V | tail -1)
fi

TS_VERSION=$(grep "^VERSION" "$TOOLSHED/build/unix/rules.mak" | awk '{print $3}')
INCLUDE="$TOOLSHED/include"
LIBMISC="$TOOLSHED/libmisc"

echo "Building makewav WASM..."
echo "  toolshed: $TOOLSHED ($TS_VERSION)"

# makewav is self-contained -- defines its own swap_short/swap_int
# libmisc excluded to avoid duplicate symbol errors

emcc \
    makewav_wrapper.c \
    makewav_stubs.c \
    "$TOOLSHED/makewav/makewav.c" \
    -I"$INCLUDE" \
    -Dmain=makewav_main \
    -Wno-implicit-function-declaration \
    -DTOOLSHED_VERSION=\"$TS_VERSION\" \
    -o makewav.js \
    -s EXPORTED_FUNCTIONS='["_makewav_version","_makewav_run","_makewav_run_cas","_makewav_run_raw","_makewav_run_args"]' \
    -s EXPORTED_RUNTIME_METHODS='["FS","ccall","cwrap"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='MakewavModule' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s FORCE_FILESYSTEM=1 \
    -s EXIT_RUNTIME=0 \
    -s INVOKE_RUN=0 \
    -O2

echo "source: toolshed-$TS_VERSION" > VERSION
echo "built: $(date -u '+%d%b%Y')" >> VERSION
echo "Done."
# forced rebuild Mon Jul 20 22:32:06 UTC 2026
