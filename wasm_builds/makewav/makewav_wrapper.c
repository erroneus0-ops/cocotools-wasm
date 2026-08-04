/*
 * makewav_wrapper.c -- Emscripten WASM wrapper for makewav
 *
 * makewav usage: makewav [options] input-file
 *   -r        raw binary input
 *   -c        DECB header input
 *   -k        CAS output instead of WAV
 *   -s<rate>  sample rate (default: 9600 to match XRoar)
 *   -n<name>  filename in tape header
 *   -o<file>  output filename
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emscripten.h>

extern int makewav_main(int argc, char **argv);

EMSCRIPTEN_KEEPALIVE
const char *makewav_version(void)
{
    return "makewav from Toolshed " TOOLSHED_VERSION;
}

/* General purpose: pass space-separated args string + input/output paths */
EMSCRIPTEN_KEEPALIVE
int makewav_run_args(const char *argstr, const char *srcpath, const char *dstpath)
{
    char out_arg[256];
    snprintf(out_arg, sizeof(out_arg), "-o%s", dstpath);

    /* Split argstr into tokens */
    char *buf = argstr ? strdup(argstr) : strdup("");
    char *argv[64];
    int argc = 0;
    argv[argc++] = "makewav";
    char *tok = strtok(buf, " ");
    while (tok && argc < 60) {
        argv[argc++] = tok;
        tok = strtok(NULL, " ");
    }
    argv[argc++] = out_arg;
    argv[argc++] = (char *)srcpath;
    argv[argc] = NULL;

    int rc = makewav_main(argc, argv);
    free(buf);
    return rc;
}

/* Convenience: raw binary to WAV at 9600Hz */
EMSCRIPTEN_KEEPALIVE
int makewav_run(const char *srcpath, const char *dstpath)
{
    return makewav_run_args("-r -s9600", srcpath, dstpath);
}

/* Convenience: raw binary to CAS at 9600Hz */
EMSCRIPTEN_KEEPALIVE
int makewav_run_cas(const char *srcpath, const char *dstpath)
{
    return makewav_run_args("-r -k -s9600", srcpath, dstpath);
}

/* Convenience: raw binary to WAV at 9600Hz (alias) */
EMSCRIPTEN_KEEPALIVE
int makewav_run_raw(const char *srcpath, const char *dstpath)
{
    return makewav_run_args("-r -s9600", srcpath, dstpath);
}
