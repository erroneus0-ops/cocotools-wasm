# How-To: Building a New Toolshed Release to WASM

Extracted 2026-08-01, before removing `toolshed-2.5.1/` (the source
tree used for the current, already-completed build). The compiled
output (`wasm/toolshed/toolshed.js` / `.wasm`) stays and keeps working
regardless -- this guide exists so that if toolshed is ever updated,
the actual process doesn't need to be reverse-engineered from scratch.

## The good news: most of this is already automated

`wasm/toolshed/build.sh` and `.github/workflows/build_toolshed_wasm.yml`
were already written to be reasonably version-agnostic -- they
auto-detect whichever `toolshed-*` directory exists at the repo root
(`find ... -name "toolshed-*" | sort -V | tail -1`) and extract the
version string directly from the toolshed build system itself
(`build/unix/rules.mak`). In the common case, updating just means:

1. **Download the new toolshed release** and extract it to the repo
   root as `toolshed-X.Y.Z/` (matching the existing naming pattern --
   this is what the auto-detect glob looks for). Toolshed is part of
   the NitrOS-9 project; check there for the current release location.
2. **Trigger the workflow** -- either push a change touching
   `wasm/toolshed/**` or the workflow file itself, or use
   `workflow_dispatch` from the Actions tab (it takes a `version` input
   for the build report label, defaulting to `2.5.1` -- update that
   default if you want, though it's cosmetic, not functional).
3. **Check the result**: `wasm/toolshed/BUILD_REPORT.md` gets rewritten
   with the new build's smoke test output. Look for `PASS -- toolshed
   WASM DECB and CECB paths both working` at the end. If it says FAIL
   or the smoke test didn't run at all, something broke -- see below.

## What can actually go wrong: Emscripten libc compatibility

The real, recurring risk with a toolshed update isn't the WASM
compilation process itself -- it's that toolshed's C source uses a few
libc functions/patterns Emscripten's compiled environment doesn't
support cleanly. Really only **one genuine root cause** has come up so
far, showing up in two files:

- `libnativegs.c` and `libnativess.c` both access `path->fd->_fileno`
  (`libnativess.c` via `ftruncate` combined with it) -- a glibc-internal
  struct field, not something Emscripten's (musl-based) libc has in the
  same layout at all. Both files are currently excluded from the build.

(A second issue -- `libdecbsrec.c` using `digittoint()`, a BSD
extension -- came up too, but is **fixed, not excluded**: as of
2026-08-03, `native_stubs.c` provides a real `digittoint()`
implementation, since it's a genuinely trivial, fully portable
function. `libdecbsrec.c` now compiles completely unmodified and its
S-record encode/decode actually works, rather than being permanently
stubbed to an error. This is the model to follow for future issues,
covered below.)

**When a new toolshed release triggers a similar undefined-symbol
error at link time, the first question to ask is: can the missing
thing be reimplemented directly, with the same name?** This is
strictly better than excluding the file and stubbing its higher-level
functions to an error, when it's possible -- it restores the actual,
real functionality instead of quietly disabling it. It's possible when
the missing thing is a genuine, portable *function* with well-defined
behavior (like `digittoint`) -- write it yourself in `native_stubs.c`
with the same name and signature, and the calling file compiles
unmodified.

It's *not* possible the same way when the issue is a struct field
access tied to a specific libc's internal layout (like `_fileno`) --
you can't "provide a replacement" for a struct field the way you can
for a function. The real fix there is a small source patch to the
calling file itself: replace `fd->_fileno` with the portable, standard
`fileno(fd)` function call, which Emscripten's libc does support
correctly. Worth doing if the functionality is ever actually needed;
not done here since native_gs/ss functions are never called in
practice in this WASM build (all paths are virtual filesystem paths).

**If a new toolshed release adds new files to these same libraries
(libdecb, libnative), or the excluded files themselves change
significantly, expect similar compatibility errors to resurface.** The
build will simply fail to link with undefined-symbol errors naming the
problem function/field. For each one: check whether it's a genuine
portable function (reimplement it in `native_stubs.c`, same name) or a
libc-internal struct/field access (needs an actual source patch to the
calling file, or exclusion if the functionality genuinely isn't
needed).

A reasonable first diagnostic step, matching how the exclusions were
originally found: `grep -rl "_fileno\|ftruncate\|digittoint" toolshed-NEW/lib*/`
against the new release before attempting a build, to catch likely
trouble spots early rather than debugging a link failure blind.

## The monolithic build itself

The WASM build combines DECB, OS-9 (RBF), and CECB support into one
module (`toolshed.js`/`.wasm`), not three separate ones -- pulling
source from `libdecb`, `librbf`, `libcecb`, `libcoco`, `libnative`
(a specific curated file list, not a full directory glob -- see
`build.sh`), `libmisc` (minus `os9diskfuncs.c`, excluded as a duplicate
of `librbfread.c`'s `read_lsn`), `libsys`, and `libtoolshed`, plus the
`decb`/`os9`/`cecb` CLI source directories (each with their own
`_main.c` excluded, since only one `main()` can exist in the combined
module -- `toolshed_wrapper.c` provides the actual WASM-facing entry
points instead).

The exported functions are already listed explicitly in `build.sh`
(`_ts_dskini`, `_ts_copy`, `_ts_dir`, `_ts_cecb_run`, etc.) -- if a
future toolshed version adds genuinely new capabilities worth exposing
to the WASM side, new wrapper functions would need to be added to
`toolshed_wrapper.c` and their names added to that exported-functions
list, following the same pattern as the existing ones.

## Verification

`wasm/toolshed/smoke_test.js` is the actual pass/fail gate, run
automatically by the workflow via `node wasm/toolshed/smoke_test.js`.
It creates a blank 35-track DSK image, writes a minimal hand-assembled
DECB binary (`LDA #$42, RTS`) into the virtual filesystem, copies it
onto the disk image, and lists the directory -- exercising the DECB
path. It also exercises the CECB path (bulk-erase, copy via
`ts_cecb_run`, directory listing to a `.cas` cassette image). A clean
pass on both paths is what "PASS -- toolshed WASM DECB and CECB paths
both working" in the build report actually confirms.

## Status

This is a guide for *if* toolshed gets updated -- not a task in
progress. The current build (source: toolshed-2.5.1, built
2026-07-24) is complete, its output already committed and in active
use, and the source tree itself has been removed now that this process
is documented and the source is trivially re-obtainable from the
NitrOS-9 project if ever needed again.
