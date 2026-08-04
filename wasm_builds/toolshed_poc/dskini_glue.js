// dskini_glue.js -- JavaScript interface to the dskini WASM module
//
// Usage (Node.js):
//   const { dskini } = require('./dskini_glue');
//   const dskBytes = dskini(35);  // returns Uint8Array or null on error
//
// Usage (browser):
//   <script src="dskini.js"></script>
//   <script src="dskini_glue.js"></script>
//   const dskBytes = await dskini(35);

async function loadDskiniModule() {
    // DskiniModule is the Emscripten-generated module
    // In browser: loaded via <script src="dskini.js">
    // In Node.js: const DskiniModule = require('./dskini.js');
    return await DskiniModule();
}

async function dskini(tracks) {
    const Module = await loadDskiniModule();

    // Call the exported C function
    const result = Module._dskini(tracks || 35);

    if (result !== 0) {
        console.error(`dskini failed with error code ${result}`);
        return null;
    }

    // Read the output file from the virtual filesystem
    const dskData = Module.FS.readFile('/out.dsk');
    return dskData;  // Uint8Array, 161280 bytes for 35-track disk
}

// Node.js export
if (typeof module !== 'undefined') {
    module.exports = { dskini };
}
