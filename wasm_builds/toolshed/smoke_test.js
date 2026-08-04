// smoke_test.js -- basic sanity check for toolshed WASM
//
// Creates a blank DSK, copies a test file into it, lists the directory.
// Run: node smoke_test.js

const ToolshedModule = require('./toolshed.js');

ToolshedModule().then(m => {
    const dskini = m.cwrap('ts_dskini', 'number', ['string', 'number']);
    const copy   = m.cwrap('ts_copy',   'number', ['string', 'string', 'number', 'number']);
    const dir    = m.cwrap('ts_dir',    'number', ['string', 'string']);

    // 1. Create a blank disk
    console.log('1. dskini...');
    let rc = dskini('/test.dsk', 35);
    console.log('   rc:', rc, rc === 0 ? 'OK' : 'FAIL');
    if (rc !== 0) process.exit(1);

    // Verify DSK is 161280 bytes
    const dskData = m.FS.readFile('/test.dsk');
    console.log('   size:', dskData.length, dskData.length === 161280 ? 'OK' : 'FAIL');

    // 2. Write a test ML binary to virtual FS
    console.log('2. Writing test binary...');
    // Minimal DECB binary: LDA #$42, RTS = $86 $42 $39
    // DECB format: [0x00][0x00][0x03][0x3F][0x00][86][42][39]
    //              [0xFF][0x00][0x00][0x3F][0x00]
    const binary = new Uint8Array([
        0x00, 0x00, 0x03, 0x3F, 0x00,  // data block: 3 bytes at $3F00
        0x86, 0x42, 0x39,               // LDA #$42, RTS
        0xFF, 0x00, 0x00, 0x3F, 0x00   // EOF block, exec $3F00
    ]);
    m.FS.writeFile('/test.bin', binary);
    console.log('   written:', binary.length, 'bytes OK');

    // 3. Copy test.bin into the DSK as HELLO.BIN
    console.log('3. copy...');
    rc = copy('/test.bin', '/test.dsk,HELLO.BIN:0', 2, 0);
    console.log('   rc:', rc, rc === 0 ? 'OK' : 'FAIL');
    if (rc !== 0) process.exit(1);

    // 4. List the directory
    console.log('4. dir...');
    rc = dir('/test.dsk', '/dir.csv');
    console.log('   rc:', rc, rc === 0 ? 'OK' : 'FAIL');
    if (rc !== 0) process.exit(1);

    const dirCSV = m.FS.readFile('/dir.csv', {encoding: 'utf8'});
    console.log('   directory:');
    dirCSV.split('\n').forEach(line => {
        if (line) console.log('   ', line);
    });

    // Verify HELLO appears in directory
    if (dirCSV.includes('HELLO')) {
        console.log('   DECB PASS -- dskini + copy + dir all working');
    } else {
        console.error('\nFAIL -- HELLO not found in directory');
        process.exit(1);
    }

    // 5. CECB: create a blank cassette image
    console.log('5. cecb bulkerase...');
    const cecbBulkerase = m.cwrap('ts_cecb_bulkerase', 'number', ['string']);
    rc = cecbBulkerase('/test.cas');
    console.log('   rc:', rc, rc === 0 ? 'OK' : 'FAIL');
    if (rc !== 0) process.exit(1);

    // 6. CECB: copy the same test binary in via ts_cecb_run
    console.log('6. cecb copy (ts_cecb_run)...');
    const cecbRun = m.cwrap('ts_cecb_run', 'number', ['string']);
    rc = cecbRun('copy -2 -n -d0x3F00 -e0x3F00 /test.bin /test.cas,HELLO');
    console.log('   rc:', rc, rc === 0 ? 'OK' : 'FAIL');
    if (rc !== 0) process.exit(1);

    // 7. CECB: list the directory and verify HELLO appears
    console.log('7. cecb dir...');
    const cecbDir = m.cwrap('ts_cecb_dir', 'number', ['string', 'string']);
    rc = cecbDir('/test.cas', '/cecb_dir.txt');
    console.log('   rc:', rc, rc === 0 ? 'OK' : 'FAIL');
    if (rc !== 0) process.exit(1);

    const cecbDirOut = m.FS.readFile('/cecb_dir.txt', {encoding: 'utf8'});
    console.log('   directory:');
    cecbDirOut.split('\n').forEach(line => {
        if (line) console.log('   ', line);
    });

    if (cecbDirOut.includes('HELLO')) {
        console.log('   CECB PASS -- bulkerase + copy (ts_cecb_run) + dir all working');
    } else {
        console.error('\nFAIL -- HELLO not found in CECB directory');
        process.exit(1);
    }

    console.log('\nPASS -- toolshed WASM DECB and CECB paths both working');
    process.exit(0);
});
