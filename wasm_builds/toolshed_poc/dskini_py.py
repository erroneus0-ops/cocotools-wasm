"""
wasm/toolshed_poc/dskini_py.py -- Python interface to dskini WASM module

Calls the WASM module via Node.js subprocess and returns the DSK image
as bytes. This is the bridge until wasmtime-py or similar is available.

Usage:
    from wasm.toolshed_poc.dskini_py import dskini_wasm
    dsk_bytes = dskini_wasm(tracks=35)
    open('blank.dsk', 'wb').write(dsk_bytes)
"""

import subprocess
import sys
import os
import tempfile

WASM_DIR = os.path.dirname(os.path.abspath(__file__))
GLUE_PATH = os.path.join(WASM_DIR, 'dskini_glue.js')

# Node.js runner script -- calls the glue and writes output to a temp file
_NODE_RUNNER = """
const {{ dskini }} = require('{glue}');

async function main() {{
    const data = await dskini({tracks});
    if (!data) {{ process.exit(1); }}
    const fs = require('fs');
    fs.writeFileSync('{output}', data);
    process.exit(0);
}}

main();
"""

def dskini_wasm(tracks=35):
    """
    Create a blank CoCo DSK image using the toolshed WASM module.
    Returns bytes of length 161280 (35-track) / 184320 (40-track) / 368640 (80-track).
    Raises RuntimeError on failure.
    """
    with tempfile.NamedTemporaryFile(suffix='.dsk', delete=False) as f:
        output_path = f.name

    runner_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.js', mode='w', delete=False) as f:
            f.write(_NODE_RUNNER.format(
                glue=GLUE_PATH.replace('\\', '/'),
                tracks=int(tracks),
                output=output_path.replace('\\', '/')
            ))
            runner_path = f.name

        result = subprocess.run(
            ['node', runner_path],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"dskini_wasm failed (exit {result.returncode}): {result.stderr}"
            )

        with open(output_path, 'rb') as f:
            return f.read()

    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)
        if runner_path and os.path.exists(runner_path):
            os.unlink(runner_path)


if __name__ == '__main__':
    tracks = int(sys.argv[1]) if len(sys.argv) > 1 else 35
    print(f"Calling dskini_wasm({tracks})...")
    data = dskini_wasm(tracks)
    print(f"Got {len(data)} bytes")

    # Spot check: track 0 sector 1 should be 0xFF
    assert data[0] == 0xFF, f"Expected 0xFF at offset 0, got {data[0]:#04x}"
    # Track 17 sector 1 should be 0x00
    track17_off = 17 * 18 * 256
    assert data[track17_off] == 0x00, f"Expected 0x00 at track17 sec1, got {data[track17_off]:#04x}"
    print("Spot checks passed.")
