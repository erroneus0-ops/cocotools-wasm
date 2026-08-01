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
libc functions Emscripten's compiled environment doesn't support
cleanly. The current build already had to exclude three files for
exactly this reason (documented directly in `build.sh`'s own
comments):

- `libdecbsrec.c` -- uses `digittoint()`, a BSD extension not available
- `libnativegs.c` -- uses `path->fd->_fileno`, a glibc-internal field
- `libnativess.c` -- uses `ftruncate` combined with `_fileno`, same
  glibc-internal issue

**If a new toolshed release adds new files to these same libraries
(libdecb, libnative), or the excluded files themselves change
significantly, expect similar compatibility errors to resurface.** The
build will simply fail to link with undefined-symbol errors naming the
problem function. The existing exclusion list in `build.sh`
(`! -name "libdecbsrec.c"` etc.) will need auditing -- a new file using
one of these same patterns needs the same treatment: exclude it from
the source list, and if the excluded functionality is actually needed
by something the smoke test exercises, either find a portable
replacement or stub it (see `native_stubs.c`, which already exists for
exactly this purpose -- functions the wrapper needs but that don't
port directly).

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
