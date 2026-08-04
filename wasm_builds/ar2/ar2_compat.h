/* ar2_compat.h -- compatibility for Emscripten WASM build */
#ifndef AR2_COMPAT_H
#define AR2_COMPAT_H

#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/stat.h>

/* pflinit -- OS-9 path list init, no-op */
static inline void pflinit(void) { }

/* strucmp -- case-insensitive string compare */
static inline int strucmp(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        int d = tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
        if (d) return d;
        s1++; s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

/* OS-9 system call codes */
#define SS_ATTR  0x0001
#define SS_SIZE  0x0002
#define GS_SIZE  0x0003
#define SS_FD    0x0004
#define GS_FD    0x0005

/* OS-9 syscall stubs -- variadic to accept any number of args */
static inline int setstat(int code, ...) { return 0; }
static inline int getstat(int code, ...) { return 0; }

/* mknod -- OS-9 takes 2 args, POSIX takes 3 -- macro adds missing dev_t */
#define mknod(path, mode) mknod((path), (mode_t)(mode), (dev_t)0)

#endif
