/*
 * dskini_wrapper.c -- Emscripten WASM wrapper for toolshed _decb_dskini
 *
 * Exports one function:
 *
 *   int dskini(int tracks)
 *
 * Returns 0 on success, non-zero on error.
 * On success, the DSK image is written to the Emscripten virtual filesystem
 * at the path "/out.dsk" and can be read back by JavaScript.
 *
 * Usage from JavaScript:
 *
 *   const result = Module._dskini(35);
 *   if (result === 0) {
 *     const data = Module.FS.readFile('/out.dsk');  // Uint8Array
 *   }
 *
 * Compile with:
 *   emcc dskini_wrapper.c libdecbdskini.c \
 *        [libnative objects] \
 *        -I../../include \
 *        -o dskini.js \
 *        -s EXPORTED_FUNCTIONS='["_dskini"]' \
 *        -s EXPORTED_RUNTIME_METHODS='["FS"]' \
 *        -s MODULARIZE=1 \
 *        -s EXPORT_NAME='DskiniModule'
 */

#include <decbpath.h>
#include <emscripten.h>

#define OUTPUT_PATH "/out.dsk"

EMSCRIPTEN_KEEPALIVE
int dskini(int tracks)
{
    /* Validate track count */
    if (tracks != 35 && tracks != 40 && tracks != 80)
        tracks = 35;

    /* Call the real toolshed function */
    /* tracks, no disk name, 1 HDB drive, 256 bps, no skitzo */
    error_code ec = _decb_dskini(OUTPUT_PATH, tracks, NULL, 1, 256, 0);

    return (int)ec;
}
