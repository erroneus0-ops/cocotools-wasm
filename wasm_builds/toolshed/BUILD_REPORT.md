# toolshed WASM Build Report

**Built:** 2026-08-03 14:50 UTC
**Toolshed:** emcc_workflow/toolshed-DiskShed-v0.9.0
**WASM size:** 107198 bytes

## Smoke Test Output
```
1. dskini...
   rc: 0 OK
   size: 161280 OK
2. Writing test binary...
   written: 13 bytes OK
3. copy...
   rc: 0 OK
4. dir...
   rc: 0 OK
   directory:
    name,ext,type,ascii,first_granule,last_sector_bytes
    HELLO,BIN,2,0,34,13
   DECB PASS -- dskini + copy + dir all working
5. cecb bulkerase...
Creating WAV file: /test.cas
      Sample Rate: 22050
  Bits Per Sample: 16
   Silence Length: 0.500000

   rc: 0 OK
6. cecb copy (ts_cecb_run)...
   rc: 0 OK
7. cecb dir...
   rc: 0 OK
   directory:
    Directory of: /test.cas
      HELLO    2 ($02) B ($42)
   CECB PASS -- bulkerase + copy (ts_cecb_run) + dir all working

PASS -- toolshed WASM DECB and CECB paths both working
```
