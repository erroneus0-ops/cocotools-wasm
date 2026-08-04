/*
 * ar2_wrapper.c -- Emscripten WASM wrapper for ar2
 *
 * OS-9/NitrOS-9 archive manager. Useful for extracting modules
 * from .ar archives found on OS-9 disk images.
 *
 * Note: delete operations (ftruncate) are stubbed -- archives can be
 * listed, extracted, and added to, but delete cleanup is impaired.
 *
 * Exported:
 *   const char *ar2_version()
 *   int ar2_run(const char *args)  -- space-separated argument string
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emscripten.h>

extern int ar2_main(int argc, char **argv);

EMSCRIPTEN_KEEPALIVE
const char *ar2_version(void)
{
    return "ar2 from Toolshed " TOOLSHED_VERSION;
}

EMSCRIPTEN_KEEPALIVE
int ar2_run(const char *argstr)
{
    /* Split argstr on spaces into argv */
    char *buf = strdup(argstr);
    char *argv[64];
    int argc = 0;
    argv[argc++] = "ar2";
    char *tok = strtok(buf, " ");
    while (tok && argc < 63) {
        argv[argc++] = tok;
        tok = strtok(NULL, " ");
    }
    argv[argc] = NULL;
    int rc = ar2_main(argc, argv);
    free(buf);
    return rc;
}
