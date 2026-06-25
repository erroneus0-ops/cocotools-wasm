"""
cocotools/decb.py — CoCo DECB Disk and Binary Tools

Handles:
  - DECB .BIN format  (preamble/postamble wrapper for ML binaries)
  - CoCo JVC DSK format  (35-track, 18-sector, 256 bytes/sector)
  - Directory and FAT management

Faithfully replicates the toolshed/decb utilities in pure Python.
No external dependencies. Works anywhere Python 3.8+ runs.

DSK layout (single-sided, single-density — CoCo standard):
  35 tracks × 18 sectors × 256 bytes = 161280 bytes
  Track 17 is the directory track:
    Sector 2 = FAT (granule allocation table, 256 bytes)
    Sector 3 = directory entries (32 bytes each, 8 per sector)
  Granules: each granule = 9 sectors = 2304 bytes
    Tracks 0-16 = granules 0-33  (34 granules)
    Tracks 18-34 = granules 34-67 (34 granules)
    Total: 68 granules
"""

import os
import math

# ─────────────────────────────────────────────────────────────────────────────
# DSK geometry
# ─────────────────────────────────────────────────────────────────────────────

TRACKS   = 35
SECTORS  = 18
SECSIZE  = 256
DISKSIZE = TRACKS * SECTORS * SECSIZE   # 161280 bytes

DIR_TRACK   = 17
FAT_SECTOR  = 2    # 1-based
DIR_SECTOR  = 3    # first directory sector (1-based)

GRAN_SIZE    = 9 * SECSIZE      # 2304 bytes per granule
GRAN_TOTAL   = 68               # total granules on disk
DIR_ENTRIES_PER_SECTOR = SECSIZE // 32
MAX_DIR_SECTORS = 8          # directory sectors 3-10 on track 17
MAX_FILES    = MAX_DIR_SECTORS * DIR_ENTRIES_PER_SECTOR   # 64

# File type codes
FTYPE_BASIC = 0    # BASIC program
FTYPE_DATA  = 1    # data file
FTYPE_ML    = 2    # machine language
FTYPE_TEXT  = 3    # text file

# ASCII flag
ASCII_BIN   = 0x00
ASCII_TEXT  = 0xFF


# ─────────────────────────────────────────────────────────────────────────────
# DECB .BIN format
# ─────────────────────────────────────────────────────────────────────────────

def make_bin(code, load_addr, exec_addr=None):
    """
    Wrap machine code in DECB binary format.

    DECB binary format:
      Preamble: 0x00, len_hi, len_lo, load_addr_hi, load_addr_lo
      Data bytes
      Postamble: 0xFF, 0x00, 0x00, exec_addr_hi, exec_addr_lo

    Args:
        code      (bytes): Machine code bytes.
        load_addr (int):   Address to load code to.
        exec_addr (int):   Execution start address (default = load_addr).

    Returns:
        bytes: Complete DECB binary file.
    """
    if exec_addr is None:
        exec_addr = load_addr
    length = len(code)
    out = bytearray()
    out += bytes([
        0x00,
        (length    >> 8) & 0xFF, length    & 0xFF,
        (load_addr >> 8) & 0xFF, load_addr & 0xFF,
    ])
    out += code
    out += bytes([
        0xFF, 0x00, 0x00,
        (exec_addr >> 8) & 0xFF, exec_addr & 0xFF,
    ])
    return bytes(out)


def parse_bin(data):
    """
    Parse a DECB .BIN file.

    Returns list of (load_addr, code_bytes) segments, plus exec_addr.
    Raises ValueError on malformed input.
    """
    segments  = []
    exec_addr = None
    pos       = 0

    while pos < len(data):
        if pos + 5 > len(data):
            raise ValueError(f"truncated block at offset {pos}")
        block_type = data[pos]
        if block_type == 0xFF:
            # Postamble: 0xFF, 0x00, 0x00, exec_hi, exec_lo
            if pos + 5 > len(data):
                raise ValueError("truncated postamble")
            exec_addr = (data[pos+3] << 8) | data[pos+4]
            break
        elif block_type == 0x00:
            length    = (data[pos+1] << 8) | data[pos+2]
            load_addr = (data[pos+3] << 8) | data[pos+4]
            start     = pos + 5
            if start + length > len(data):
                raise ValueError(
                    f"block at {pos}: length {length} exceeds file size")
            segments.append((load_addr, bytes(data[start:start+length])))
            pos = start + length
        else:
            raise ValueError(f"unknown block type 0x{block_type:02X} at {pos}")

    return segments, exec_addr


# ─────────────────────────────────────────────────────────────────────────────
# BASIC tokenizer (minimal — for .BAS files, builds a runnable program)
# ─────────────────────────────────────────────────────────────────────────────

def tokenize_basic(text, load_addr=0x1E01):
    """
    Tokenize CoCo Color BASIC source text into binary format.

    This is a minimal implementation that handles the subset needed
    for the book's loader programs:
      - Line numbers
      - Keywords as ASCII (untokenized) — accepted by BASIC on entry
        but not tokenized until the interpreter re-saves the program.

    For a fully tokenized BASIC file, use the full basic.py tokenizer.

    Args:
        text      (str): BASIC source, one line per text line.
        load_addr (int): Address where BASIC program loads (default $1E01).

    Returns:
        bytes: Raw BASIC binary (without DECB wrapper).
    """
    # CoCo BASIC stores programs as linked list of lines:
    #   next_addr (2 bytes, big-endian) | line_num (2 bytes) | tokens... | 0x00
    # Final entry: 0x00 0x00 (null pointer terminates)

    lines = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        # Split line number from body
        parts = raw.split(None, 1)
        try:
            lineno = int(parts[0])
        except ValueError:
            continue   # skip non-numeric lines
        body = (parts[1] if len(parts) > 1 else '').encode('ascii') + b'\x00'
        lines.append((lineno, body))

    if not lines:
        return b'\x00\x00'

    # First pass: calculate addresses
    addr = load_addr
    line_addrs = []
    for lineno, body in lines:
        line_addrs.append(addr)
        addr += 2 + 2 + len(body)    # next_ptr + lineno + body(with null)

    # Second pass: emit
    out = bytearray()
    for i, (lineno, body) in enumerate(lines):
        if i + 1 < len(lines):
            next_addr = line_addrs[i + 1]
        else:
            next_addr = line_addrs[i] + 2 + 2 + len(body)
        out += bytes([(next_addr >> 8) & 0xFF, next_addr & 0xFF])
        out += bytes([(lineno   >> 8) & 0xFF, lineno   & 0xFF])
        out += body

    out += b'\x00\x00'    # end of program
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────────
# JVC DSK image builder
# ─────────────────────────────────────────────────────────────────────────────

def sector_offset(track, sector):
    """Byte offset in disk image for track/sector (sector is 1-based)."""
    return (track * SECTORS + (sector - 1)) * SECSIZE


def gran_to_track_sector(gran):
    """Convert granule number to (track, first_sector).  Sector is 1-based."""
    if gran < 34:                    # granules 0-33 = tracks 0-16
        track = gran // 2
        first_sector = 1 if gran % 2 == 0 else 10
    else:                            # granules 34-67 = tracks 18-34
        g = gran - 34
        track = 18 + g // 2
        first_sector = 1 if g % 2 == 0 else 10
    return track, first_sector


def _blank_disk():
    """Return a bytearray of DISKSIZE bytes, initialised to 0x00."""
    return bytearray(DISKSIZE)


def _init_fat(disk):
    """Mark all granules as free (0xFF) in the FAT."""
    fat_off = sector_offset(DIR_TRACK, FAT_SECTOR)
    for i in range(GRAN_TOTAL):
        disk[fat_off + i] = 0xFF


def _blank_dir(disk):
    """Fill directory sectors with 0xFF (empty entries)."""
    for sec in range(DIR_SECTOR, DIR_SECTOR + 8):   # sectors 3-10
        off = sector_offset(DIR_TRACK, sec)
        for i in range(SECSIZE):
            disk[off + i] = 0xFF


class DskError(Exception):
    pass


class Dsk:
    """
    In-memory CoCo JVC disk image.

    Usage:
        dsk = Dsk.blank()
        dsk.write_file('HELLO', 'BIN', Dsk.FTYPE_ML, bin_data)
        dsk.write_file('HELLO', 'BAS', Dsk.FTYPE_BASIC, bas_data)
        raw = dsk.to_bytes()
        open('HELLO.DSK', 'wb').write(raw)
    """

    FTYPE_BASIC = FTYPE_BASIC
    FTYPE_DATA  = FTYPE_DATA
    FTYPE_ML    = FTYPE_ML
    FTYPE_TEXT  = FTYPE_TEXT

    def __init__(self, image: bytearray):
        if len(image) != DISKSIZE:
            raise DskError(f"image must be {DISKSIZE} bytes, got {len(image)}")
        self._img = image

    @classmethod
    def blank(cls):
        """Create a fresh, empty formatted disk."""
        img = _blank_disk()
        _init_fat(img)
        _blank_dir(img)
        return cls(img)

    @classmethod
    def from_bytes(cls, data):
        """Load an existing DSK image."""
        return cls(bytearray(data))

    def to_bytes(self):
        return bytes(self._img)

    # ── FAT helpers ─────────────────────────────────────────────────────────

    def _fat_byte(self, gran):
        return self._img[sector_offset(DIR_TRACK, FAT_SECTOR) + gran]

    def _set_fat(self, gran, value):
        self._img[sector_offset(DIR_TRACK, FAT_SECTOR) + gran] = value

    def _alloc_granules(self, n):
        """Allocate n contiguous-ish granules.  Returns list of gran numbers."""
        free = [g for g in range(GRAN_TOTAL) if self._fat_byte(g) == 0xFF]
        if len(free) < n:
            raise DskError(f"disk full: need {n} granules, only {len(free)} free")
        chosen = free[:n]
        for i, g in enumerate(chosen[:-1]):
            self._set_fat(g, chosen[i+1])     # point to next
        return chosen

    # ── Directory helpers ────────────────────────────────────────────────────

    def _dir_entry_offset(self, slot):
        """Byte offset of directory entry slot (0-based)."""
        sector = DIR_SECTOR + slot // DIR_ENTRIES_PER_SECTOR
        if sector > DIR_SECTOR + 7:
            raise DskError("directory full")
        within = (slot % DIR_ENTRIES_PER_SECTOR) * 32
        return sector_offset(DIR_TRACK, sector) + within

    def _find_free_dir_slot(self):
        """Return index of first free (0xFF first byte) directory slot."""
        for slot in range(MAX_FILES):
            off = self._dir_entry_offset(slot)
            if self._img[off] == 0xFF:
                return slot
        raise DskError("directory full")

    def _find_file(self, name8, ext3):
        """Return dir slot index, or None if not found."""
        name8 = name8.upper().ljust(8)[:8]
        ext3  = ext3.upper().ljust(3)[:3]
        for slot in range(MAX_FILES):
            off = self._dir_entry_offset(slot)
            if self._img[off] == 0xFF:
                continue
            if self._img[off:off+8] == name8.encode() \
               and self._img[off+8:off+11] == ext3.encode():
                return slot
        return None

    # ── Public API ───────────────────────────────────────────────────────────

    def write_file(self, name, ext, ftype, data, ascii_flag=ASCII_BIN):
        """
        Write a file to the disk image.

        Args:
            name       (str):   Filename, up to 8 chars.
            ext        (str):   Extension, up to 3 chars.
            ftype      (int):   File type (FTYPE_ML, FTYPE_BASIC, etc.).
            data       (bytes): File data.
            ascii_flag (int):   ASCII_BIN or ASCII_TEXT.
        """
        # Encode name and extension
        name8 = name.upper().ljust(8)[:8].encode('ascii')
        ext3  = ext.upper().ljust(3)[:3].encode('ascii')

        # How many granules do we need?
        grans_needed = max(1, math.ceil(len(data) / GRAN_SIZE))

        # Allocate granules
        chosen = self._alloc_granules(grans_needed)

        # Write file data into granules
        pos = 0
        for g in chosen:
            track, first_sec = gran_to_track_sector(g)
            for s_offset in range(9):
                sec_off = sector_offset(track, first_sec + s_offset)
                chunk   = data[pos:pos + SECSIZE]
                self._img[sec_off:sec_off + len(chunk)] = chunk
                pos += len(chunk)
                if pos >= len(data):
                    break
            if pos >= len(data):
                break

        # Mark last granule in FAT
        last_gran   = chosen[-1]
        secs_used   = math.ceil(len(data) % GRAN_SIZE / SECSIZE) \
                      if len(data) % GRAN_SIZE else 9
        secs_used   = max(1, secs_used)
        bytes_last  = len(data) % SECSIZE or SECSIZE
        self._set_fat(last_gran, 0xC0 | secs_used)

        # Write directory entry
        slot = self._find_free_dir_slot()
        off  = self._dir_entry_offset(slot)
        entry = bytearray(32)
        entry[0:8]   = name8
        entry[8:11]  = ext3
        entry[11]    = ftype
        entry[12]    = ascii_flag
        entry[13]    = chosen[0]          # first granule
        entry[14]    = (bytes_last >> 8) & 0xFF
        entry[15]    = bytes_last & 0xFF
        self._img[off:off+32] = entry

    def list_files(self):
        """Return list of (name, ext, ftype, size_bytes) for all files."""
        files = []
        for slot in range(MAX_FILES):
            off = self._dir_entry_offset(slot)
            if self._img[off] == 0xFF:
                continue
            name  = self._img[off:off+8].decode('ascii').rstrip()
            ext   = self._img[off+8:off+11].decode('ascii').rstrip()
            ftype = self._img[off+11]
            first_gran = self._img[off+13]
            bytes_last = (self._img[off+14] << 8) | self._img[off+15]
            # Walk FAT to count granules
            g = first_gran
            ngrans = 0
            while g < GRAN_TOTAL and self._fat_byte(g) < 0xC0:
                g = self._fat_byte(g)
                ngrans += 1
                if ngrans > GRAN_TOTAL:
                    break
            # Last granule
            last_fat = self._fat_byte(g)
            secs_used = last_fat & 0x3F if (last_fat & 0xC0) == 0xC0 else 9
            size = ngrans * GRAN_SIZE + (secs_used - 1) * SECSIZE + bytes_last
            files.append((name, ext, ftype, size))
        return files

    def read_file(self, name, ext):
        """
        Read a file from the disk image.
        Returns (data: bytes, ftype: int, ascii_flag: int) or raises DskError.

        Faithful translation of _decb_read() from libdecb/libdecbread.c
        (toolshed, nitros9project, GPL).
        """
        name8 = name.upper().ljust(8)[:8]
        ext3  = ext.upper().ljust(3)[:3]
        slot  = self._find_file(name8, ext3)
        if slot is None:
            raise DskError(f"file not found: {name}.{ext}")

        off        = self._dir_entry_offset(slot)
        ftype      = self._img[off + 11]
        ascii_flag = self._img[off + 12]
        first_gran = self._img[off + 13]
        bytes_last = (self._img[off + 14] << 8) | self._img[off + 15]

        # Walk FAT chain collecting granule data
        data = bytearray()
        g = first_gran
        visited = set()

        while True:
            if g >= GRAN_TOTAL or g in visited:
                raise DskError(f"corrupt FAT chain in {name}.{ext}")
            visited.add(g)

            fat_val = self._fat_byte(g)

            # Read this granule (9 sectors = 2304 bytes)
            gran_data = self._read_granule(g)

            if fat_val >= 0xC0:
                # Last granule — trim to exact size
                # sectors_in_last = (fat_val & 0x3F) - 1  (0-indexed)
                # bytes = sectors_in_last * 256 + bytes_last
                sectors_used = (fat_val & 0x3F) - 1
                if sectors_used < 0:
                    sectors_used = 0
                exact = sectors_used * SECSIZE + bytes_last
                data.extend(gran_data[:exact])
                break
            else:
                data.extend(gran_data)
                g = fat_val

        return bytes(data), ftype, ascii_flag

    def _read_granule(self, gran):
        """Read one complete granule (9 sectors = 2304 bytes) from the image."""
        track, sector = gran_to_track_sector(gran)
        offset = sector_offset(track, sector)
        return self._img[offset:offset + GRAN_SIZE]


# ─────────────────────────────────────────────────────────────────────────────
# High-level helpers
# ─────────────────────────────────────────────────────────────────────────────

def makedsk(dsk_path, *file_specs):
    """
    Build a CoCo DSK image from a list of file specifications.

    file_specs: sequence of (path, name, ext, ftype) tuples.
      path  -- path to the source file on the host
      name  -- CoCo filename (up to 8 chars)
      ext   -- CoCo extension (up to 3 chars)
      ftype -- FTYPE_ML, FTYPE_BASIC, etc.

    Example:
        makedsk('HELLO.DSK',
                ('HELLO.BIN', 'HELLO', 'BIN', Dsk.FTYPE_ML),
                ('HELLO.BAS', 'HELLO', 'BAS', Dsk.FTYPE_BASIC))
    """
    dsk = Dsk.blank()
    for path, name, ext, ftype in file_specs:
        data = open(path, 'rb').read()
        dsk.write_file(name, ext, ftype, data)
    with open(dsk_path, 'wb') as f:
        f.write(dsk.to_bytes())


def infer_ftype(ext):
    """Guess DECB file type from extension string."""
    ext = ext.upper()
    if ext in ('BAS',):
        return FTYPE_BASIC
    if ext in ('BIN', 'ML', 'COM'):
        return FTYPE_ML
    if ext in ('DAT', 'DATA'):
        return FTYPE_DATA
    return FTYPE_TEXT
