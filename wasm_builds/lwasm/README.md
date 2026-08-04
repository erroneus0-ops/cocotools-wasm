# lwasm WASM

WebAssembly build of lwasm 4.24 (William Astle's 6809 assembler).

## Why

- No binary trust concerns -- compiled from readable C source
- No installation required -- runs in browser or Node.js
- Updates are: new source -> GitHub Actions -> new WASM
- Same correctness as native lwasm

## Building

### Via GitHub Actions (recommended)

Trigger the "Build lwasm WASM" workflow from the Actions tab.
Output is committed back to the repo automatically.

### Locally (requires Emscripten)

```bash
source ~/emsdk/emsdk_env.sh
cd wasm/lwasm
bash build.sh
```

## Testing

```bash
node smoke_test.js
```

Expected output:
```
Return code: 0
Output size: 14 bytes
Code bytes: 864200B70400
PASS -- lwasm WASM produces correct output
```

## Usage from JavaScript

```javascript
const LwasmModule = require('./lwasm.js');

LwasmModule().then(m => {
    const assemble = m.cwrap('lwasm_assemble', 'number', ['string', 'string']);

    const source = `
         ORG  $3F00
START    LDA  #$42
         END  START
    `;

    const result = assemble(source, 'decb');
    if (result === 0) {
        const bin = m.FS.readFile('/out.bin');       // Uint8Array
        const errors = m.FS.readFile('/out.errors',  // string
                           {encoding: 'utf8'});
    }
});
```

## Usage from Python (via cocotools)

```python
from cocotools.lwasm_wasm import assemble

result = assemble("         LDA  #$42\n         END\n")
# result.binary   -- bytes
# result.errors   -- list of error dicts
# result.warnings -- list of warning dicts
```

## Output files (virtual filesystem)

- `/out.bin`    -- assembled binary (DECB, raw, or OS-9 format)
- `/out.errors` -- errors and warnings in unicorns format

## Supported formats

- `decb` -- Color BASIC DECB multirecord binary (default)
- `raw`  -- raw bytes
- `os9`  -- OS-9 module

## Version

lwtools 4.24. See FUTURE.md for 4.25 upgrade process.
