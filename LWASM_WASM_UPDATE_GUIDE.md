# How-To: Updating lwasm's WASM Build to a New lwtools Release

Written 2026-08-01, as part of consolidating all emcc-targeted source
trees under `emcc_workflow/`. Unlike the toolshed guide, this isn't
written just before removing a source tree -- `wasm/lwasm/` is actively
maintained and the 4.24->4.25 upgrade has already been done once, as a
deliberate exercise in validating the upgrade *process* itself, not
just the destination version.

## The mechanism, already in place

`wasm/lwasm/build.sh` auto-detects the highest-versioned `lwtools-*`
directory under `emcc_workflow/` (`find .../emcc_workflow -maxdepth 1
-type d -name "lwtools-*" | sort -V | tail -1`). In the common case,
updating means:

1. **Download the new lwtools release** and extract it to
   `emcc_workflow/lwtools-X.Y.Z/` (matching the existing naming
   pattern the auto-detect glob looks for). Source:
   `http://www.6809.org.uk/lwtools/`.
2. **Trigger the workflow** -- `workflow_dispatch` from the Actions
   tab (takes a `version` input, cosmetic label only, defaults to
   `'4.24'` -- update that default when a new version becomes the norm)
   or push a change touching `wasm/lwasm/**`.
3. **Check the result**: `wasm/lwasm/BUILD_REPORT.md` gets rewritten
   with the smoke test output. Look for `PASS -- lwasm WASM produces
   correct output`.

## What changed last time (4.24 -> 4.25), for reference

The upgrade wasn't just "point the build at a new folder and
recompile" -- it also required updating three of `cocotools`'s Python
files (`c_compat.py`, `lw_expr.py`, `insn_funcs.py`) to match C-level
changes in the new lwtools release. That work is fully reflected in
the current live `cocotools/` files already (confirmed byte-identical
against the delta analysis that produced them). If a future lwtools
release changes any of the same underlying functions again, expect a
similar review of those three files to be needed -- `cocotools` is a
faithful line-by-line Python translation of specific lwtools C files
(see each file's own header for exactly which ones), so any C-side
change to those files is a real signal to re-check the corresponding
Python translation, not just recompile the WASM side.

## Known compatibility notes

No Emscripten-specific libc incompatibilities have been found in
lwasm's own source (unlike toolshed, which needed three files excluded
for `digittoint`/`_fileno`/`ftruncate` issues) -- `build.sh` compiles
the full `lwasm` and `lwlib` source trees without exclusions. This
could change with a future release, though; if the build fails to
link, check for undefined-symbol errors the same way toolshed's
exclusions were originally diagnosed.

One cosmetic-only oddity worth knowing about, not worth chasing: an
earlier `BUILD_REPORT.md` shows `**lwtools:** lwtools-4.25-listing.txt`
as the detected version label -- the version-detection glob picked up
a stray file rather than a real directory at some point. Doesn't affect
the actual build, just the label shown afterward.

## Status

`emcc_workflow/lwtools-4.24/` and `emcc_workflow/lwtools-4.25/` are
both currently absent from the repo (removed once superseded/redundant
-- 4.24 after its only dependent, `test_fidelity.py`, was retired as a
completed validation project; 4.25 once Daniel personally archived the
tarball and Windows zip outside the repo). Whichever version is needed
for a future rebuild, place it at `emcc_workflow/lwtools-X.Y.Z/` and
the existing automation picks it up without further changes.
