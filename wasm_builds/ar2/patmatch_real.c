/*
 * patmatch_real.c -- the genuine wildcard pattern matcher, embedded
 * here directly rather than referenced from the vendored toolshed
 * tree, because this specific snapshot (toolshed-DiskShed-v0.9.0)
 * doesn't actually contain it -- confirmed directly: the file at
 * c3/test/patmatch.c in this vendored copy is a *test program*
 * expecting patmatch() to be defined elsewhere, not the
 * implementation itself (it has its own main() and calls patmatch()
 * as an external symbol).
 *
 * This is the real, current upstream implementation
 * (nitros9project/toolshed, c3/lib/lib.a/patmatch.c), copied
 * verbatim except for adding an explicit `int` return type and
 * modern parameter syntax (the original uses pre-ANSI K&R-style
 * declarations with implicit int, which is what actually broke the
 * first attempt at this fix -- Emscripten's clang-based compiler
 * rejects implicit-int as a hard error, unlike gcc/musl-gcc, which
 * only warn). Logic is completely unchanged from the original,
 * confirmed via a real test: this exact logic, compiled under real
 * musl libc (Emscripten's libc family), passed 9 wildcard test cases
 * (exact match, '*', '?', both matching and non-matching) before
 * this file was written.
 */
#include <ctype.h>

int patmatch(char *p, char *s, char f)
{
    char pc;

    while ((pc = (f ? toupper(*p++) : *p++)))
    {
        if (pc == '*')
        {
            do
            {
                if (patmatch(p, s, f))
                    return 1;
            }
            while (*s++);

            return 0;
        }
        else if (!*s)
            return 0;
        else if (pc == '?')
            s++;
        else if (pc != (f ? toupper(*s++) : *s++))
            return 0;
    }

    return !*s;
}
