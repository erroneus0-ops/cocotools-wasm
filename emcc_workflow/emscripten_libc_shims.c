/*
 * emscripten_libc_shims.c -- shared, reusable implementations of libc
 * functions that Emscripten's (musl-based) libc doesn't provide, but
 * that ARE genuinely portable, well-defined functions -- not tied to
 * any one specific C library's internal implementation details.
 *
 * Lives here, not inside any one project's own source (like
 * wasm/toolshed/native_stubs.c used to have its own copy) so that any
 * future emcc-compiled project in this repo hitting the SAME gap can
 * just compile this file alongside its own sources, rather than
 * rediscovering and reimplementing the same shim independently.
 *
 * IMPORTANT: this file is only for gaps that CAN be fixed this way --
 * a genuine, portable function with well-defined behavior, missing
 * only because Emscripten's libc doesn't happen to include it (often
 * because it's a BSD extension, not POSIX-standard). It is NOT the
 * right place for issues that are actually about a calling file relying
 * on a specific libc's internal implementation details (e.g. accessing
 * a glibc-internal struct field like `_fileno` directly) -- those need
 * an actual source patch to the calling code itself, not a shim, since
 * there's no portable "same name" replacement possible for a struct
 * field the way there is for a function. See
 * TOOLSHED_WASM_UPDATE_GUIDE.md and EMCC_WORKFLOW_SETUP_GUIDE.md for
 * the fuller explanation of this distinction.
 *
 * To use from a new project's build.sh: just add this file's path to
 * whatever source-file list gets passed to emcc, alongside the
 * project's own sources. See wasm/toolshed/build.sh for a real example.
 *
 * When you hit a NEW missing-function gap that's genuinely portable:
 * add it here, not to a project-specific file, so the next project
 * that hits the same gap doesn't have to rediscover it independently.
 */

#include "emscripten_libc_shims.h"

/* digittoint() -- BSD extension, not in Emscripten's (musl-based) libc.
 * Converts a hex digit character to its integer value.
 * First hit: toolshed's libdecbsrec.c (S-record encode/decode), 2026-08. */
int digittoint(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}
