#!/bin/bash
# build.sh -- compile lwasm to WASM using Emscripten
#
# Run from: wasm/lwasm/
# lwtools source expected at: ../../emcc_workflow/lwtools-4.24/ (or set LWTOOLS env var)
#
# Output:
#   lwasm.js    -- Emscripten JS loader
#   lwasm.wasm  -- the WASM binary

set -e

# Auto-detect lwtools directory -- finds the highest versioned lwtools-* folder
# under emcc_workflow/ (all emcc-targeted source trees live there, keeping the
# repo root itself free of build source). Set LWTOOLS env var to override.
if [ -z "$LWTOOLS" ]; then
    LWTOOLS=$(find $(cd ../.. && pwd)/emcc_workflow -maxdepth 1 -type d -name "lwtools-*" | sort -V | tail -1)
    if [ -z "$LWTOOLS" ]; then
        echo "ERROR: no lwtools-* directory found in emcc_workflow/"
        exit 1
    fi
fi
LWASM_SRC="$LWTOOLS/lwasm"
LWLIB_SRC="$LWTOOLS/lwlib"
INCLUDE="$LWTOOLS/lwasm $LWTOOLS/lwlib $LWTOOLS/common"

echo "Building lwasm WASM..."
echo "  lwtools: $LWTOOLS"

# Collect lwasm C sources EXCEPT main.c
LWASM_SRCS=$(find "$LWASM_SRC" -name "*.c" ! -name "main.c" | tr '\n' ' ')
LWLIB_SRCS=$(find "$LWLIB_SRC" -name "*.c" | tr '\n' ' ')

# Build include flags
IFLAGS=""
for d in $INCLUDE; do
    IFLAGS="$IFLAGS -I$d"
done

# Compile main.c separately with main renamed to lwasm_main
# All other files compiled without the rename flag
emcc -c "$LWASM_SRC/main.c" $IFLAGS -Dmain=lwasm_main -O2 -o /tmp/lwasm_main.o

emcc \
    lwasm_wrapper.c \
    $LWASM_SRCS \
    $LWLIB_SRCS \
    /tmp/lwasm_main.o \
    $IFLAGS \
    -o lwasm.js \
    -s EXPORTED_FUNCTIONS='["_lwasm_assemble"]' \
    -s EXPORTED_RUNTIME_METHODS='["FS","ccall","cwrap"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='LwasmModule' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s FORCE_FILESYSTEM=1 \
    -s EXIT_RUNTIME=0 \
    -s INVOKE_RUN=0 \
    -O2

echo "Done. Output: lwasm.js + lwasm.wasm"
