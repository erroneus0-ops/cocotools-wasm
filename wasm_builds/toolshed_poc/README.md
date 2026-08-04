# dskini WASM Proof of Concept

This is a proof of concept for compiling toolshed's `_decb_dskini` to
WebAssembly using Emscripten, and calling it from Python.

## What this proves

If this works, the entire toolshed + lwtools workflow can move to WASM:
- No binary trust concerns -- source is readable, compilation is reproducible
- No Python translation layer -- William's and toolshed's C runs as-is
- Updates are: new source -> Emscripten -> new WASM. No audit required.

## Files

- `dskini_wrapper.c` -- thin C wrapper exporting `dskini(tracks)` to WASM
- `dskini_glue.js`   -- JavaScript interface (reads result from virtual FS)
- `dskini_py.py`     -- Python interface via Node.js subprocess
- `build.sh`         -- Emscripten build script

## Prerequisites

```bash
# Emscripten (if not already installed from XRoar build)
source ~/emsdk/emsdk_env.sh

# toolshed
git clone https://github.com/nitros9project/toolshed ~/src/toolshed

# Node.js (for Python->WASM bridge)
node --version  # should be >= 14
```

## Build

```bash
cd wasm/toolshed_poc
chmod +x build.sh
./build.sh
```

## Test

Quick Node.js test:
```bash
node -e "
DskiniModule = require('./dskini.js');
DskiniModule().then(m => {
    const r = m._dskini(35);
    console.log('result:', r);
    const data = m.FS.readFile('/out.dsk');
    console.log('size:', data.length, '(expect 161280)');
    console.log('track0[0]:', data[0].toString(16), '(expect ff)');
    console.log('track17_s1[0]:', data[17*18*256].toString(16), '(expect 00)');
});
"
```

Python test:
```bash
python wasm/toolshed_poc/dskini_py.py 35
```

## Compare against cocotools

```python
from cocotools.decb import Dsk
from wasm.toolshed_poc.dskini_py import dskini_wasm

wasm_bytes  = dskini_wasm(35)
py_bytes    = bytes(Dsk.blank().to_bytes())

if wasm_bytes == py_bytes:
    print("MATCH -- decb.py is byte-for-byte identical to toolshed")
else:
    diffs = [(i, wasm_bytes[i], py_bytes[i])
             for i in range(len(wasm_bytes))
             if wasm_bytes[i] != py_bytes[i]]
    print(f"DIVERGE -- {len(diffs)} bytes differ")
    for off, w, p in diffs[:10]:
        print(f"  offset {off:#08x}: wasm={w:#04x} python={p:#04x}")
```
