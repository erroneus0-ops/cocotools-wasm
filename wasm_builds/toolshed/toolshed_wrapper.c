/*
 * toolshed_wrapper.c -- Emscripten WASM wrapper for toolshed
 *
 * Complete monolithic build covering DECB, OS-9, and CECB formats.
 *
 * DECB operations:
 *   ts_dskini, ts_copy, ts_read, ts_dir, ts_kill, ts_free, ts_rename, ts_fstat
 *
 * OS-9 RBF operations:
 *   ts_os9_dir, ts_os9_copy, ts_os9_del, ts_os9_free, ts_os9_id
 *
 * Pathlist format:
 *   Native:  "/path/to/file"
 *   DECB:    "/disk.dsk,FILENAME.BIN:0"
 *   OS-9:    "/image.os9,/dir/file"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emscripten.h>

#include "decbpath.h"
#include "nativepath.h"
#include "cocotypes.h"

/* ================================================================== */
/* Version                                                              */
/* ================================================================== */

#ifndef TOOLSHED_VERSION
#define TOOLSHED_VERSION "unknown"
#endif

EMSCRIPTEN_KEEPALIVE
const char *ts_version(void)
{
    return "Toolshed " TOOLSHED_VERSION;
}

/* ================================================================== */
/* DECB Operations                                                      */
/* ================================================================== */

EMSCRIPTEN_KEEPALIVE
int ts_dskini(const char *diskpath, int tracks)
{
    if (tracks != 35 && tracks != 40 && tracks != 80) tracks = 35;
    return (int)_decb_dskini((char *)diskpath, tracks, NULL, 1, 256, 0);
}

EMSCRIPTEN_KEEPALIVE
int ts_copy(const char *srcpath, const char *dstpathlist,
            int file_type, int data_type)
{
    FILE *src;
    decb_path_id dst;
    error_code ec;
    unsigned char *buffer;
    long file_size;
    u_int write_size;

    src = fopen(srcpath, "rb");
    if (!src) return -1;
    fseek(src, 0, SEEK_END);
    file_size = ftell(src);
    fseek(src, 0, SEEK_SET);
    if (file_size <= 0) { fclose(src); return -1; }
    buffer = (unsigned char *)malloc(file_size);
    if (!buffer) { fclose(src); return -1; }
    if (fread(buffer, 1, file_size, src) != (size_t)file_size) {
        free(buffer); fclose(src); return -1;
    }
    fclose(src);

    if (file_type < 0) file_type = 2;
    if (data_type < 0) data_type = 0;

    ec = _decb_create(&dst, (char *)dstpathlist, FAM_WRITE, file_type, data_type);
    if (ec != 0) { free(buffer); return (int)ec; }

    write_size = (u_int)file_size;
    ec = _decb_write(dst, buffer, &write_size);
    free(buffer);

    if (ec == 0) {
        decb_file_stat fstat;
        _decb_gs_fd(dst, &fstat);
        fstat.file_type = (u_char)file_type;
        fstat.data_type = (u_char)data_type;
        _decb_ss_fd(dst, &fstat);
    }
    _decb_close(dst);
    return (int)ec;
}

EMSCRIPTEN_KEEPALIVE
int ts_read(const char *srcpathlist, const char *dstpath)
{
    decb_path_id src;
    FILE *dst;
    error_code ec;
    unsigned char buf[256];
    u_int size;

    ec = _decb_open(&src, (char *)srcpathlist, FAM_READ);
    if (ec != 0) return (int)ec;
    dst = fopen(dstpath, "wb");
    if (!dst) { _decb_close(src); return -1; }

    while (1) {
        size = sizeof(buf);
        ec = _decb_read(src, buf, &size);
        if (size > 0) fwrite(buf, 1, size, dst);
        if (ec != 0) break;
    }
    fclose(dst);
    _decb_close(src);
    return (ec == EOS_EOF) ? 0 : (int)ec;
}

EMSCRIPTEN_KEEPALIVE
int ts_dir(const char *diskpath, const char *outpath)
{
    decb_path_id path;
    decb_dir_entry entry;
    error_code ec;
    FILE *out;
    char pathlist[512];

    snprintf(pathlist, sizeof(pathlist), "%s,:0", diskpath);
    ec = _decb_open(&path, pathlist, FAM_DIR | FAM_READ);
    if (ec != 0) return (int)ec;

    out = fopen(outpath, "w");
    if (!out) { _decb_close(path); return -1; }

    fprintf(out, "name,ext,type,ascii,first_granule,last_sector_bytes\n");
    while (_decb_readdir(path, &entry) == 0) {
        if (entry.filename[0] == 0x00 || (unsigned char)entry.filename[0] == 0xFF)
            continue;
        char name[9] = {0}, ext[4] = {0};
        int i;
        for (i = 7; i >= 0 && entry.filename[i] == ' '; i--);
        strncpy(name, (char *)entry.filename, i + 1);
        for (i = 2; i >= 0 && entry.file_extension[i] == ' '; i--);
        strncpy(ext, (char *)entry.file_extension, i + 1);
        int last = (entry.last_sector_size[0] << 8) | entry.last_sector_size[1];
        fprintf(out, "%s,%s,%d,%d,%d,%d\n",
                name, ext, entry.file_type, entry.ascii_flag,
                entry.first_granule, last);
    }
    fclose(out);
    _decb_close(path);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int ts_kill(const char *pathlist)
{
    return (int)_decb_kill((char *)pathlist);
}

EMSCRIPTEN_KEEPALIVE
int ts_rename(const char *pathlist, const char *newname)
{
    return (int)_decb_rename((char *)pathlist, (char *)newname);
}

EMSCRIPTEN_KEEPALIVE
int ts_free(const char *diskpath, const char *outpath)
{
    decb_path_id path;
    error_code ec;
    FILE *out;
    char pathlist[512];
    int free_granules = 0, i;

    snprintf(pathlist, sizeof(pathlist), "%s,:0", diskpath);
    ec = _decb_open(&path, pathlist, FAM_READ);
    if (ec != 0) return (int)ec;

    for (i = 0; i < 68; i++)
        if (path->FAT[i] == 0xFF) free_granules++;
    _decb_close(path);

    out = fopen(outpath, "w");
    if (!out) return -1;
    fprintf(out, "free_granules,%d\nfree_bytes,%d\nused_granules,%d\n",
            free_granules, free_granules * 2304, 68 - free_granules);
    fclose(out);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int ts_fstat(const char *pathlist, const char *outpath)
{
    decb_path_id path;
    error_code ec;
    FILE *out;
    decb_file_stat fstat;

    ec = _decb_open(&path, (char *)pathlist, FAM_READ);
    if (ec != 0) return (int)ec;
    _decb_gs_fd(path, &fstat);
    _decb_close(path);

    out = fopen(outpath, "w");
    if (!out) return -1;
    fprintf(out, "file_type,%d\ndata_type,%d\nfile_size,%d\n",
            fstat.file_type, fstat.data_type, fstat.file_size);
    fclose(out);
    return 0;
}

/* ================================================================== */
/* OS-9 RBF Operations                                                  */
/* ================================================================== */

extern int os9dir(int argc, char **argv);
extern int os9copy(int argc, char **argv);
extern int os9del(int argc, char **argv);
extern int os9free(int argc, char **argv);
extern int os9id(int argc, char **argv);

static int redirect_stdout(const char *outpath, int (*fn)(int, char**),
                           int argc, char **argv)
{
    int rc;
    FILE *f = freopen(outpath, "w", stdout);
    if (!f) return -1;
    rc = fn(argc, argv);
    freopen("/dev/null", "w", stdout);
    return rc;
}

EMSCRIPTEN_KEEPALIVE
int ts_os9_dir(const char *pathlist, const char *outpath)
{
    char *argv[] = { "os9dir", (char *)pathlist, NULL };
    return redirect_stdout(outpath, os9dir, 2, argv);
}

EMSCRIPTEN_KEEPALIVE
int ts_os9_copy(const char *srcpathlist, const char *dstpathlist)
{
    char *argv[] = { "os9copy", (char *)srcpathlist, (char *)dstpathlist, NULL };
    return os9copy(3, argv);
}

EMSCRIPTEN_KEEPALIVE
int ts_os9_del(const char *pathlist)
{
    char *argv[] = { "os9del", (char *)pathlist, NULL };
    return os9del(2, argv);
}

EMSCRIPTEN_KEEPALIVE
int ts_os9_free(const char *imagepath, const char *outpath)
{
    char *argv[] = { "os9free", (char *)imagepath, NULL };
    return redirect_stdout(outpath, os9free, 2, argv);
}

EMSCRIPTEN_KEEPALIVE
int ts_os9_id(const char *imagepath, const char *outpath)
{
    char *argv[] = { "os9id", (char *)imagepath, NULL };
    return redirect_stdout(outpath, os9id, 2, argv);
}

/* ================================================================== */
/* CECB (Cassette Extended Color BASIC) Operations                      */
/* ================================================================== */

extern int cecbdir(int argc, char **argv);
extern int cecbcopy(int argc, char **argv);
extern int cecbbulkerase(int argc, char **argv);
extern int cecbfstat(int argc, char **argv);

/* General purpose cecb command runner -- same interface as native cecb.exe
 * cmdstr: subcommand + args, e.g. "copy -2 -n -d0x3F00 -e0x3F00 src dst"
 */
EMSCRIPTEN_KEEPALIVE
int ts_cecb_run(const char *cmdstr)
{
    char *buf = strdup(cmdstr);
    char *argv[64];
    int argc = 0;
    argv[argc++] = "cecb";
    char *tok = strtok(buf, " ");
    while (tok && argc < 63) {
        argv[argc++] = tok;
        tok = strtok(NULL, " ");
    }
    argv[argc] = NULL;

    /* Route to the right subcommand */
    if (strcmp(argv[1], "copy") == 0)
        { int rc = cecbcopy(argc - 1, &argv[1]); free(buf); return rc; }
    if (strcmp(argv[1], "bulkerase") == 0)
        { int rc = cecbbulkerase(argc - 1, &argv[1]); free(buf); return rc; }
    if (strcmp(argv[1], "dir") == 0)
        { int rc = cecbdir(argc - 1, &argv[1]); free(buf); return rc; }
    free(buf);
    return -1;
}

/* Convenience: bulkerase (create blank CAS/WAV) */
EMSCRIPTEN_KEEPALIVE
int ts_cecb_bulkerase(const char *casfile)
{
    char *argv[] = { "bulkerase", (char *)casfile, NULL };
    return cecbbulkerase(2, argv);
}

/* Convenience: dir to output file */
EMSCRIPTEN_KEEPALIVE
int ts_cecb_dir(const char *casfile, const char *outpath)
{
    if (!freopen(outpath, "w", stdout)) return -1;
    char *argv[] = { "dir", (char *)casfile, NULL };
    int rc = cecbdir(2, argv);
    freopen("/dev/null", "w", stdout);
    return rc;
}
/* force rebuild Thu Jul 23 19:42:31 UTC 2026 */
