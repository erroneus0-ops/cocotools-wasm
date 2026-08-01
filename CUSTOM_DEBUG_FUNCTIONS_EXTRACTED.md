# Custom Debug-Register Functions -- Extracted for Future Re-Introduction

Extracted 2026-08-01 from the `xroar/` custom debug-build tree (based
on a pre-1.12 XRoar snapshot), as part of reconciling our custom work
against the current official xroar-1.12.1 release before closing out
that custom build.

## Why this exists

Confirmed by direct comparison of both trees' `wasm/exported_functions`
files: xroar-1.12.1 has 22 exported WASM functions. Our custom `xroar/`
tree has all 22 of those, plus these 9 additional debug-register
accessors. None of the 9 exist anywhere in 1.12.1, in any form -- not
under a different name, not superseded by another mechanism. (One
partial exception worth noting: 1.12.1's existing `_write_snapshot`
export does write CPU registers including PC and CC into the snapshot
file format, so the *data* technically overlaps -- but only via writing
and parsing an entire snapshot file, not a direct per-register read.
Not a practical substitute for a debugger wanting cheap, instant,
per-instruction register access.)

This is different from the earlier version-reporting situation, where
Ciaran/sixxie independently built `wasm_package_version` and made our
own equivalent unnecessary. Here, nothing upstream does the same job --
these 9 functions are still genuinely unique, and the original goal
(turning them into real patch proposals for Ciaran) is still live.

## The 9 functions

All from `xroar/src/wasm/wasm.c` (implementation) and `wasm.h`
(declarations), immediately following the existing `wasm_vdrive_flush`
function, under the comment `// Debug exports -- read/write emulated
memory, get CPU registers`.

```c
uint8_t wasm_read_byte(int addr) {
	if (!xroar.machine) return 0;
	return xroar.machine->read_byte(xroar.machine, addr & 0xffff, 0);
}

void wasm_write_byte(int addr, int value) {
	if (!xroar.machine) return;
	xroar.machine->write_byte(xroar.machine, addr & 0xffff, value & 0xff);
}

uint16_t wasm_get_pc(void) {
	if (!xroar.machine) return 0;
	struct MC6809 *cpu = (struct MC6809 *)part_component_by_id_is_a(
		&xroar.machine->part, "CPU", "MC6809");
	return cpu ? cpu->reg_pc : 0;
}
uint8_t wasm_get_cc(void) {
	if (!xroar.machine) return 0;
	struct MC6809 *cpu = (struct MC6809 *)part_component_by_id_is_a(
		&xroar.machine->part, "CPU", "MC6809");
	return cpu ? cpu->reg_cc : 0;
}
uint8_t wasm_get_a(void) {
	if (!xroar.machine) return 0;
	struct MC6809 *cpu = (struct MC6809 *)part_component_by_id_is_a(
		&xroar.machine->part, "CPU", "MC6809");
	return cpu ? MC6809_REG_A(cpu) : 0;
}
uint8_t wasm_get_b(void) {
	if (!xroar.machine) return 0;
	struct MC6809 *cpu = (struct MC6809 *)part_component_by_id_is_a(
		&xroar.machine->part, "CPU", "MC6809");
	return cpu ? MC6809_REG_B(cpu) : 0;
}
uint16_t wasm_get_x(void) {
	if (!xroar.machine) return 0;
	struct MC6809 *cpu = (struct MC6809 *)part_component_by_id_is_a(
		&xroar.machine->part, "CPU", "MC6809");
	return cpu ? cpu->reg_x : 0;
}
uint16_t wasm_get_y(void) {
	if (!xroar.machine) return 0;
	struct MC6809 *cpu = (struct MC6809 *)part_component_by_id_is_a(
		&xroar.machine->part, "CPU", "MC6809");
	return cpu ? cpu->reg_y : 0;
}
uint16_t wasm_get_s(void) {
	if (!xroar.machine) return 0;
	struct MC6809 *cpu = (struct MC6809 *)part_component_by_id_is_a(
		&xroar.machine->part, "CPU", "MC6809");
	return cpu ? cpu->reg_s : 0;
}
```

Header declarations (`wasm.h`, immediately following the existing
`wasm_vdrive_flush` declaration):

```c
uint8_t wasm_read_byte(int addr);
void wasm_write_byte(int addr, int value);
uint16_t wasm_get_pc(void);
uint8_t wasm_get_cc(void);
uint8_t wasm_get_a(void);
uint8_t wasm_get_b(void);
uint16_t wasm_get_x(void);
uint16_t wasm_get_y(void);
uint16_t wasm_get_s(void);
```

## What's needed for a rebase onto current XRoar

1. Add all 9 declarations to the current `src/wasm/wasm.h`.
2. Add all 9 implementations to the current `src/wasm/wasm.c`. Verify
   `part_component_by_id_is_a`, `MC6809_REG_A`/`MC6809_REG_B` macros,
   and the `MC6809` struct's register field names (`reg_pc`, `reg_cc`,
   `reg_x`, `reg_y`, `reg_s`) still exist unchanged in the current
   codebase -- this tree predates 1.12.1, so internal APIs could have
   shifted even though the WASM-facing exports haven't.
3. Add all 9 names (with leading underscore, e.g. `'_wasm_get_pc'`) to
   `src/wasm/exported_functions`, alongside the existing 22.
4. Rebuild via emcc, verify the resulting `.wasm` actually exports all
   31 functions (22 stock + 9 custom).

## Status

Not re-introduced yet. This file exists so the actual code doesn't need
to be re-extracted from the `xroar/` tree if that tree is later removed
or the custom-build effort is picked back up. The `xroar/` tree itself
is still the authoritative, complete source in the meantime.
