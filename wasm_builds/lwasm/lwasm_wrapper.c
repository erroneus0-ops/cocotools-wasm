/*
 * lwasm_wrapper.c -- Emscripten WASM wrapper for lwasm
 *
 * Exports one function:
 *
 *   int lwasm_assemble(const char *source, const char *format)
 *
 * Parameters:
 *   source  -- assembly source text (null-terminated string)
 *   format  -- output format: "decb", "raw", "os9" (default: "decb")
 *
 * Returns 0 on success, non-zero on error.
 *
 * On success:
 *   - Binary output written to virtual FS at /out.bin
 *   - Error/warning messages written to /out.errors (unicorns format)
 *
 * Read results from JavaScript:
 *   const bin    = Module.FS.readFile('/out.bin');
 *   const errors = Module.FS.readFile('/out.errors', {encoding: 'utf8'});
 *
 * Compile with build.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emscripten.h>

/* lwasm entry point -- forward declaration matches the renamed symbol from main.c */
extern int lwasm_main(int argc, char **argv);

#define SOURCE_PATH "/in.asm"
#define OUTPUT_PATH "/out.bin"
#define ERRORS_PATH "/out.errors"

EMSCRIPTEN_KEEPALIVE
int lwasm_assemble(const char *source, const char *format)
{
    /* Write source to virtual filesystem */
    FILE *f = fopen(SOURCE_PATH, "w");
    if (!f) return -1;
    fputs(source, f);
    fclose(f);

    /* Remove any previous output */
    remove(OUTPUT_PATH);
    remove(ERRORS_PATH);

    /* Build argv for lwasm */
    /* lwasm --format=decb --output=/out.bin /in.asm --unicorns=/out.errors */
    char fmt_arg[64];
    snprintf(fmt_arg, sizeof(fmt_arg), "--format=%s",
             format && *format ? format : "decb");

    char *argv[] = {
        "lwasm",
        fmt_arg,
        "--output=" OUTPUT_PATH,
        "--unicorns=" ERRORS_PATH,
        SOURCE_PATH,
        NULL
    };
    int argc = 5;

    return lwasm_main(argc, argv);
}
