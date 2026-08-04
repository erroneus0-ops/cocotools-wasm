/* makewav_stubs.c -- digittoint for makewav WASM build
   makewav.c defines it as static inline but linker needs it external */
int digittoint(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}
