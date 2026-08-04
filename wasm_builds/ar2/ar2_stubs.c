/*
 * ar2_stubs.c -- minimal stubs for ar2 WASM build
 * set_fstat is provided by arsup.c
 */
#include <sys/types.h>

/* ftruncate stub -- delete cleanup impaired but other ops work */
int ftruncate(int fd, off_t length) { return 0; }

/* patmatch -- wildcard filename matching, skipped by -DCKLIB in arsup.c
   Stub returns 0 (no match) -- wildcard ops won't work but basic ops will */
int patmatch(char *p, char *s, int f) { 
    /* Simple exact match fallback */
    if (!p || !s) return 0;
    while (*p && *s) {
        if (*p == '*') return 1;  /* wildcard -- assume match */
        if (*p != *s) return 0;
        p++; s++;
    }
    return (*p == 0 && *s == 0);
}
