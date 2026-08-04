# How-To: Setting Up a New emcc/WASM GitHub Actions Workflow, From Scratch

A generic guide for standing up a brand-new "compile this C project to WASM
via GitHub Actions" workflow, written using this project's own three real
examples (xroar, lwasm, toolshed) throughout. Distinct from the per-project
update guides (`LWASM_WASM_UPDATE_GUIDE.md`, `TOOLSHED_WASM_UPDATE_GUIDE.md`)
-- those assume a workflow already exists and just needs pointing at a new
source version. This one is for when nothing exists yet at all -- a new
repo, a new tool, starting cold.

---

## Before you start: decide your build approach

Every C project we've dealt with here falls into one of two shapes, and
which one you're dealing with changes what Step 4 looks like:

**Autotools-based** (has a `configure` script, or a `configure.ac` +
`autogen.sh`) -- this is xroar's situation. You'll run `emconfigure` in
front of the normal `./configure` step, then `emmake make`.

**Plain source, no build system, or a build system that doesn't matter
for a WASM build** -- this is lwasm's and toolshed's situation. Both
have a hand-written `build.sh` that calls `emcc` directly on an explicit
list of source files, rather than going through the project's own
Makefile at all. This is usually *less* work to set up than wiring
autotools through Emscripten's wrappers, and gives you direct control
over exactly what gets compiled and what gets excluded (see the
troubleshooting section -- this matters more than it sounds like it
should).

If you're not sure which situation you're in: look for a `configure` or
`configure.ac` file in the project root. If one exists, you're
autotools-based. If not, plain source is almost always simpler.

---

## Step 1: Where the source goes

All source trees this project compiles to WASM live under
`emcc_workflow/` at the repo root (a deliberate consolidation done
2026-08-01 -- see `JOURNAL.md` and the commit history around that date
for why). Extract your new project's source there:

```
emcc_workflow/yourproject-X.Y.Z/
```

Match whatever versioned-folder naming convention the existing ones use
(`xroar-1.12.1`, `toolshed-2.5.1`) if there's any chance of needing this
again for a future version -- it makes auto-detection possible later,
the same way `wasm_builds/lwasm/build.sh` and `wasm_builds/toolshed/build.sh` already
auto-detect their own source folders by searching for a version-numbered
directory name rather than a hardcoded one.

---

## Step 2: Where the workflow file goes

GitHub Actions workflows are YAML files under `.github/workflows/` at
the repo root -- one file per workflow, any filename ending in `.yml` or
`.yaml`. Naming convention used throughout this project:
`build_<thing>_wasm.yml` (e.g. `build_lwasm_wasm.yml`).

```
.github/workflows/build_yourproject_wasm.yml
```

---

## Step 3: The workflow skeleton

Every workflow here starts with the same basic shape. This part barely
changes between projects:

```yaml
name: Build YourProject WASM

on:
  workflow_dispatch:
  push:
    paths:
      - 'emcc_workflow/yourproject-*/**'
      - '.github/workflows/build_yourproject_wasm.yml'

permissions:
  contents: write

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Emscripten
        uses: mymindstorm/setup-emsdk@v14
        with:
          version: latest

      - name: Verify emcc
        run: emcc --version
```

Two things worth understanding here, not just copying:

- **`permissions: contents: write`** is required for the later "commit
  the output back to the repo" step to actually be allowed to push.
  Without this, the workflow can build the WASM output just fine but
  will fail at the commit/push step with a permissions error -- a
  common, easy-to-misdiagnose-the-first-time failure (see
  Troubleshooting).
- **The `paths:` trigger** means this workflow only runs automatically
  when something under your source folder (or the workflow file
  itself) changes -- not on every push to the repo. `workflow_dispatch`
  additionally lets you trigger it manually from the Actions tab
  regardless of what changed, which is the more reliable way to test a
  new workflow the first few times, before you fully trust the
  automatic path trigger.

---

## Step 4: The actual build steps

### If autotools-based (xroar's pattern)

```yaml
      - name: Install autotools
        run: |
          sudo apt-get update
          sudo apt-get install -y autoconf automake libtool

      - name: Generate configure script (if needed)
        run: |
          cd emcc_workflow/yourproject-X.Y.Z
          if [ -f configure ]; then
            echo "configure already present -- fixing timestamps"
            find . \( -name "*.m4" -o -name "configure.ac" -o -name "Makefile.am" -o -name "acinclude.m4" \) -exec touch -t 202001010000 {} +
            sleep 1
            touch aclocal.m4 configure config.h.in
            find . -name "Makefile.in" -exec touch {} +
          elif [ -f autogen.sh ]; then
            bash autogen.sh
          else
            echo "Neither configure nor autogen.sh found!"
            exit 1
          fi

      - name: Configure for WASM
        run: |
          cd emcc_workflow/yourproject-X.Y.Z
          chmod +x configure config.guess config.sub install-sh missing compile ar-lib depcomp 2>/dev/null || true
          emconfigure ./configure --enable-wasm CFLAGS="-O3 -flto" LDFLAGS="-O3 -flto"

      - name: Build WASM
        id: build
        run: |
          cd emcc_workflow/yourproject-X.Y.Z
          set +e
          emmake make 2>&1 | tee /tmp/build.log
          BUILD_STATUS=${PIPESTATUS[0]}
          set -e
          echo "build_status=$BUILD_STATUS" >> "$GITHUB_OUTPUT"
          exit "$BUILD_STATUS"
        shell: bash
```

The "fixing timestamps" step exists for a real, previously-hit reason:
`git checkout` gives every file the same timestamp, which breaks
autotools' timestamp-based staleness detection -- it can think
pre-generated files are stale relative to their sources and try to
regenerate them with tools that may not be installed in the CI
runner. Touching sources older than the generated files sidesteps this
without needing those extra tools at all.

### If plain source, custom build script (lwasm's and toolshed's pattern)

Write a `build.sh` (or equivalent) that lives next to where you want
the output, and calls `emcc` directly against an explicit file list --
see `wasm_builds/lwasm/build.sh` or `wasm_builds/toolshed/build.sh` for real,
working examples. The workflow step is then just:

```yaml
      - name: Build WASM
        run: |
          cd wasm/yourproject
          bash build.sh
```

This approach gives you direct control over exactly which source files
get compiled -- important, because as covered below, not every file in
a real C project will compile cleanly under Emscripten's libc, and a
plain file-list approach makes excluding a problem file trivial (one
line), where fighting the project's own Makefile to exclude one file
can be considerably more awkward.

### Either way: verify and commit the output

```yaml
      - name: Verify output
        run: |
          test -s wasm/yourproject/yourproject.wasm && echo "OK"
          test -s wasm/yourproject/yourproject.js   && echo "OK"

      - name: Commit WASM output
        run: |
          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add wasm/yourproject/yourproject.js wasm/yourproject/yourproject.wasm
          git diff --staged --quiet || git commit -m "build: yourproject WASM [ci skip]"
          git pull --rebase --autostash origin main
          git push
```

`[ci skip]` in the commit message is worth keeping -- it prevents this
automated commit from re-triggering other workflows that might also
watch broad path patterns, avoiding an accidental trigger loop.

---

## Step 5: Triggering and monitoring

### Via the web UI

1. Go to your repository on github.com.
2. Click the **Actions** tab (top navigation bar, between "Pull requests"
   and "Projects").
3. Your new workflow's name (whatever you put after `name:` at the top
   of the YAML) appears in the left sidebar list once the file exists
   on the default branch.
4. Click it, then click the **Run workflow** dropdown button on the
   right (only appears because of `workflow_dispatch` in the trigger
   config) to trigger it manually, or just push a commit that touches
   one of the `paths:` patterns to trigger it automatically.
5. Click into the specific run to see live log output, expandable
   per-step.

### Via command line

The simplest, most reliable way from a plain git command line (no
GitHub CLI needed): push a commit that touches something the `paths:`
trigger watches -- even just the workflow file itself counts. That's
genuinely how most of tonight's workflow testing happened.

If you have the `gh` CLI installed, `gh workflow run <workflow-name>`
triggers it manually without needing a qualifying push at all, and
`gh run list` / `gh run watch` let you monitor status without leaving
the terminal -- worth installing if you'll be doing this often, though
not required.

---

## Troubleshooting: where to look, and what tends to actually go wrong

**First place to look, always: the Actions tab run log itself.** Click
into the failed run, then into the specific failed step -- the raw
build output is right there, usually with the actual compiler error
visible near the bottom.

**Second, project-specific place to look:** several of this project's
workflows also write a build log or report file back into the repo on
failure (see `build_xroar_stock_wasm.yml`'s "Save build log on failure"
step, which commits `wasm/XROAR_STOCK_BUILD_ERROR.log`). Worth adding
this pattern to a new workflow -- it means the last 300 lines of a
failed build are sitting in the repo itself afterward, readable without
needing to dig through the Actions UI's log viewer at all.

**Common failure categories actually hit in this project, roughly in
order of how often they come up:**

1. **Emscripten libc incompatibilities.** Some C library functions or
   patterns don't have a clean Emscripten equivalent -- `digittoint()`
   (a BSD extension) and `path->fd->_fileno` (a glibc-internal struct
   field) are the two real ones toolshed's build hit. Symptom: an
   undefined-symbol error at the *link* stage, not a compile error --
   the individual `.c` files compile fine, but linking the final
   `.js`/`.wasm` fails naming the missing symbol.

   **First question to ask: can the missing thing be reimplemented
   directly, with the same name?** This is strictly better than
   excluding the file and stubbing its higher-level functions to an
   error, when it's possible -- it restores the actual functionality
   instead of quietly disabling it. It's possible when the missing
   thing is a genuine, portable *function* with well-defined behavior
   (`digittoint` is exactly this -- a trivial, one-line, fully portable
   function, now reimplemented in the shared `emcc_workflow/emscripten_libc_shims.c` with
   the same name/signature, letting its calling file compile completely
   unmodified rather than staying excluded).

   It's *not* possible the same way when the issue is a struct field
   access tied to a specific libc's internal layout (`_fileno` is
   exactly this) -- you can't "provide a replacement" for a struct
   field the way you can for a function. The real fix there is a small
   source patch to the calling file itself (e.g. replace `fd->_fileno`
   with the portable, standard `fileno(fd)` call), not a stub. If the
   functionality genuinely isn't needed for what you're exposing to
   WASM, excluding the file and stubbing its higher-level entry points
   to an error (see the remaining stubs in
   project-specific stub file, e.g. `wasm_builds/toolshed/native_stubs.c`) is the reasonable fallback when a
   real patch isn't worth the effort. A reasonable first diagnostic pass before
   even attempting a build: `grep -rl "_fileno\|ftruncate\|digittoint" yourproject-source/`
   to catch likely trouble spots early.

2. **Autotools timestamp staleness**, covered above -- symptom is
   autotools trying to regenerate `configure` or `Makefile.in` using
   `automake`/`aclocal`/etc., which may not be the exact versions
   installed in the CI runner, causing a totally unrelated-looking
   failure. Fix is the timestamp-touching step already shown above.

3. **Missing `permissions: contents: write`.** Symptom: the build
   succeeds completely, but the final "Commit WASM output" step fails
   with a permission-denied-style error trying to push. Easy to
   misread as a build problem when it's actually a workflow-config
   problem -- check this specifically if everything up to the commit
   step looked fine.

4. **A stale rebase/push race**, if multiple workflows or a person's
   own `git push` land close together. The `git pull --rebase
   --autostash origin main` before the final push (shown above) handles
   the common case; if it still fails, the run's log will show exactly
   that, and the fix is almost always just re-running the workflow --
   the race is a timing coincidence, not a code problem.

5. **A source dependency that's simply missing**, if a `build.sh`
   auto-detects its source folder (as `wasm_builds/lwasm/build.sh` and
   `wasm_builds/toolshed/build.sh` both do) and that folder doesn't currently
   exist under `emcc_workflow/` -- exactly what happened when both of
   those got triggered by an unrelated edit while their source trees
   were deliberately absent. Symptom: an immediate, early "ERROR: no
   X-* directory found" message, not a real compile failure at all.
   Worth checking this first if a workflow fails within the first few
   seconds, before any real compilation could have even started.
