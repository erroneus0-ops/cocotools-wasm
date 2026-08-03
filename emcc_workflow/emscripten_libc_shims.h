/*
 * emscripten_libc_shims.h -- declarations for emscripten_libc_shims.c
 *
 * See the .c file for the full explanation of what belongs here (a
 * genuinely portable missing function) versus what doesn't (anything
 * tied to a specific libc's internal implementation details, which
 * needs an actual source patch instead, not a shim).
 */

#ifndef EMSCRIPTEN_LIBC_SHIMS_H
#define EMSCRIPTEN_LIBC_SHIMS_H

/* digittoint() -- BSD extension, converts a hex digit character to its
 * integer value ('0'-'9' -> 0-9, 'a'-'f'/'A'-'F' -> 10-15). */
int digittoint(int c);

#endif
