// smoke_test.js -- basic sanity check for lwasm WASM
//
// Assembles a simple 6809 program and verifies the output bytes.
// Run: node smoke_test.js

const LwasmModule = require('./lwasm.js');

const SOURCE = `
         ORG  $3F00
START    LDA  #$42
         STA  $0400
         END  START
`;

// Expected DECB binary output bytes (after DECB header):
// LDA #$42 = $86 $42
// STA $0400 = $B7 $04 $00
const EXPECTED_CODE = Buffer.from([0x86, 0x42, 0xB7, 0x04, 0x00]);

LwasmModule().then(m => {
    const assemble = m.cwrap('lwasm_assemble', 'number', ['string', 'string']);

    let result;
    try {
        result = assemble(SOURCE, 'decb');
    } catch(e) {
        // Emscripten throws ExitStatus when C code calls exit()
        // This is normal -- lwasm calls exit(0) on success
        if (e && e.name === 'ExitStatus') {
            result = e.status;
        } else {
            throw e;
        }
    }
    console.log('Return code:', result);

    if (result !== 0) {
        try {
            const errors = m.FS.readFile('/out.errors', {encoding: 'utf8'});
            console.error('Errors:', errors);
        } catch(e) {}
        process.exit(1);
    }

    const bin = m.FS.readFile('/out.bin');
    console.log('Output size:', bin.length, 'bytes');

    // DECB format: [0x00][len_hi][len_lo][addr_hi][addr_lo][code...]
    // Find and verify the code bytes
    let found = false;
    for (let i = 0; i < bin.length - EXPECTED_CODE.length; i++) {
        if (bin[i] === 0x00) {  // data block marker
            const blockLen = (bin[i+1] << 8) | bin[i+2];
            const code = bin.slice(i+5, i+5+blockLen);
            if (Buffer.from(code).equals(EXPECTED_CODE)) {
                console.log('Code bytes:', Buffer.from(code).toString('hex').toUpperCase());
                console.log('PASS -- lwasm WASM produces correct output');
                found = true;
                break;
            }
        }
    }

    if (!found) {
        console.error('FAIL -- expected bytes not found in output');
        console.error('Output hex:', Buffer.from(bin).toString('hex'));
        process.exit(1);
    }

    process.exit(0);
});
