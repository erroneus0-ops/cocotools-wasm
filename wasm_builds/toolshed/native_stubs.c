/*
 * native_stubs.c -- stub implementations for libnativegs/libnativess functions
 *
 * libnativegs.c and libnativess.c use path->fd->_fileno which is a glibc
 * internal not available in Emscripten libc. These stubs satisfy the linker.
 *
 * In our WASM build all paths are virtual filesystem paths -- native_gs/ss
 * functions are never called in practice. They return EOS_UNKSVC (unknown
 * service) to signal "not supported" if somehow reached.
 */

#include <sys/stat.h>
#include "nativepath.h"
#include "cocotypes.h"

#define EOS_UNKSVC 0x103  /* unknown service request */

error_code _native_gs_attr(native_path_id path, int *perms)
    { return EOS_UNKSVC; }

error_code _native_gs_eof(native_path_id path)
    { return EOS_UNKSVC; }

error_code _native_gs_fd(native_path_id path, struct stat *statbuf)
    { return EOS_UNKSVC; }

error_code _native_gs_fd_pathlist(char *pathlist, struct stat *statbuf)
    { return EOS_UNKSVC; }

error_code _native_gs_size(native_path_id path, u_int *size)
    { return EOS_UNKSVC; }

error_code _native_gs_size_pathlist(char *pathlist, u_int *size)
    { return EOS_UNKSVC; }

error_code _native_gs_pos(native_path_id path, u_int *pos)
    { return EOS_UNKSVC; }

error_code _native_ss_attr(native_path_id path, int perms)
    { return EOS_UNKSVC; }

error_code _native_ss_fd(native_path_id path, struct stat *statbuf)
    { return EOS_UNKSVC; }

error_code _native_ss_size(native_path_id path, int size)
    { return EOS_UNKSVC; }

/* digittoint() -- BSD extension, needed by libdecbsrec.c. Moved to the
   shared emcc_workflow/emscripten_libc_shims.c (2026-08-03), since it's
   a genuinely portable function any future emcc project might also
   need, not something specific to toolshed. build.sh now compiles that
   shared file alongside toolshed's own sources -- see there for the
   actual implementation.

   _decb_srec_encode/_decb_srec_decode are not stubbed here -- with
   digittoint() provided (from the shared shims file), libdecbsrec.c
   compiles completely unmodified and provides its own real
   implementations of both. Stubbing them here too would cause a
   duplicate-symbol linker error, since that file is no longer excluded
   from the build (see build.sh). */
