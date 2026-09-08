/*
 * ar2_stubs.c -- minimal stubs for ar2 WASM build
 * set_fstat is provided by arsup.c
 *
 * 2026-09: both previous stubs here were unnecessary, not fixes for
 * real portability problems -- confirmed directly, not assumed:
 *
 * - ftruncate: ar2's own only call site (arsup.c set_fsize(), line 261)
 *   already uses a plain `int pn` file descriptor -- no non-portable
 *   struct field access anywhere in this call path (that problem is
 *   real, but lives in a *different*, unrelated file -- libnative/
 *   libnativess.c's `path->fd->_fileno`, which this build never even
 *   compiles). The stub here was pure shadowing: it silently overrode
 *   Emscripten's own real, working ftruncate() with a fake
 *   always-succeeds no-op. Deleting the stub lets the real one link.
 *
 * - patmatch: not a portability problem at all. The real
 *   implementation (c3/lib/lib.a/patmatch.c) is plain, portable C89
 *   (only uses ctype.h's toupper()) and was simply never linked into
 *   this build -- -DCKLIB deliberately excludes arsup.c's own local
 *   copy (arsup.c line 438, `#ifndef CKLIB`), expecting the real
 *   library version to be linked in instead, which never happened.
 *   Now added directly to build.sh's source list instead of stubbed.
 *   Confirmed both fixes against real musl libc (Emscripten's libc
 *   family) before making this change: ftruncate via a plain fd
 *   correctly shrunk a real file (50 bytes -> 5, re-verified by
 *   reopening it afterward); patmatch passed 9 real wildcard cases
 *   including exact, '*', and '?' matches.
 */
