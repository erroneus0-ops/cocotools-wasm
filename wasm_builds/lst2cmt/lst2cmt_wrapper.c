/*
 * lst2cmt_wrapper.c -- Emscripten WASM wrapper for lst2cmt
 *
 * Converts lwasm listing files to MAME debugger comment files.
 * Useful for annotating XRoar/MAME debugger with source comments.
 *
 * Exported:
 *   int lst2cmt_convert(const char *srcpath, const char *dstpath,
 *                       const char *system, const char *cpu,
 *                       int nocrc, int nolinenumbers, int offset)
 *
 * Input/output are virtual filesystem paths.
 */

#include <stdio.h>
#include <emscripten.h>

/* lst2cmt main renamed to avoid conflict */
extern int lst2cmt_main(int argc, char **argv);

EMSCRIPTEN_KEEPALIVE
const char *lst2cmt_version(void)
{
    return "lst2cmt from Toolshed " TOOLSHED_VERSION;
}

EMSCRIPTEN_KEEPALIVE
int lst2cmt_convert(const char *srcpath, const char *dstpath,
                    const char *system, const char *cpu,
                    int nocrc, int nolinenumbers, int offset)
{
    char sys_arg[64], cpu_arg[64], off_arg[32];
    char *argv[16];
    int argc = 0;

    argv[argc++] = "lst2cmt";
    if (nocrc)        argv[argc++] = "-nocrc";
    if (nolinenumbers) argv[argc++] = "-nolinenumbers";
    if (system && *system) {
        snprintf(sys_arg, sizeof(sys_arg), "-s%s", system);
        argv[argc++] = sys_arg;
    }
    if (cpu && *cpu) {
        snprintf(cpu_arg, sizeof(cpu_arg), "-c%s", cpu);
        argv[argc++] = cpu_arg;
    }
    if (offset) {
        snprintf(off_arg, sizeof(off_arg), "-o%d", offset);
        argv[argc++] = off_arg;
    }
    argv[argc++] = (char *)srcpath;
    argv[argc++] = (char *)dstpath;
    argv[argc] = NULL;

    return lst2cmt_main(argc, argv);
}
