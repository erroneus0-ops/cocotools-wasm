/*
 * tocgen_wrapper.c -- Emscripten WASM wrapper for tocgen
 */
#include <stdio.h>
#include <emscripten.h>

extern int tocgen_main(int argc, char **argv);

EMSCRIPTEN_KEEPALIVE
const char *tocgen_version(void)
{
    return "tocgen from Toolshed " TOOLSHED_VERSION;
}

EMSCRIPTEN_KEEPALIVE
int tocgen_run(const char *srcpath, const char *dstpath)
{
    char *argv[] = { "tocgen", (char *)srcpath, (char *)dstpath, NULL };
    return tocgen_main(3, argv);
}
