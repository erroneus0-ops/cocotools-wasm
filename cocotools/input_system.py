"""
cocotools/input_system.py — Source line reader
Faithful Python translation of lwasm/input.c and lwasm/input.h
(William Astle, LWTools, GPL v3)

Manages a stack of input sources (files or strings) and delivers one
source line at a time to pass1.  Transparently handles:
  - Multiple input files (lw_stringlist_t input_files)
  - Included files (input_type_include) with include-path search
  - String inputs (input_type_string) used by macros and internal
    directives
  - CR/LF/CRLF/bare CR line endings

C → Python mapping:
  struct input_stack  → InputEntry (stack node)
  IS macro            → self.stack[-1] (top of list)
  lw_stack (file_dir) → self.file_dir  (list used as stack)
  fgetc / ungetc      → read one char at a time from io.BufferedReader
  lw_strdup(linebuff) → str (Python strings are immutable values)
"""

import os
import io


# ─────────────────────────────────────────────────────────────────────────────
# Input type codes  (enum input_types_e)
# ─────────────────────────────────────────────────────────────────────────────

INPUT_TYPE_FILE    = 0   # regular file, no search path
INPUT_TYPE_INCLUDE = 1   # include path search
INPUT_TYPE_STRING  = 2   # input from an in-memory string

MAX_LINE = 2048          # matches linebuff[2049] in C


# ─────────────────────────────────────────────────────────────────────────────
# InputEntry  (struct input_stack)
# ─────────────────────────────────────────────────────────────────────────────

class InputEntry:
    """
    struct input_stack {
        struct input_stack *next;
        int   type;
        void *data;        // FILE* or char* depending on type
        int   data2;       // current position for string inputs
        char *filespec;
        struct input_stack_node *stack;  // per-entry opaque stack (ignored)
    };
    Python: data is a file object (binary) or a str.
    """
    __slots__ = ('type', 'data', 'data2', 'filespec', 'pos')

    def __init__(self, type_, data, filespec):
        self.type     = type_
        self.data     = data    # open file (binary) or string
        self.data2    = 0       # string position (for INPUT_TYPE_STRING)
        self.filespec = filespec


# ─────────────────────────────────────────────────────────────────────────────
# InputSystem
# ─────────────────────────────────────────────────────────────────────────────

class InputSystem:
    """
    Manages the input stack.  Attached to AsmState as  as_.input.

    Public interface mirrors the C functions:
        input_init()          → __init__()
        input_open(s)         → open(s)
        input_openstring(n,s) → open_string(name, s)
        input_readline()      → readline()
        input_curspec()       → curspec()
        input_open_standalone → open_standalone(s)
    """

    def __init__(self, as_):
        self.as_       = as_
        self._stack    = []          # list of InputEntry, top = last
        self.file_dir  = []          # stack of current-directory strings
        self.includelist = []        # stack of filenames opened (for -depend)

    # ── Push a new entry onto the input stack ─────────────────────────────────

    def _push(self, entry):
        self._stack.append(entry)

    # ── Pop the top entry ─────────────────────────────────────────────────────

    def _pop(self):
        if self._stack:
            top = self._stack.pop()
            if top.type in (INPUT_TYPE_FILE, INPUT_TYPE_INCLUDE):
                if top.data:
                    try: top.data.close()
                    except Exception: pass
                if self.file_dir:
                    self.file_dir.pop()
            return top
        return None

    # ── Current top of stack ──────────────────────────────────────────────────

    @property
    def _top(self):
        return self._stack[-1] if self._stack else None

    # ── input_pushpath (update file_dir and includelist) ──────────────────────

    def _pushpath(self, filename):
        """
        input_pushpath(as, fn):
        Push the directory part of filename onto file_dir,
        and the full filename onto includelist.
        """
        self.includelist.append(filename)
        dn = os.path.dirname(filename) or '.'
        self.file_dir.append(dn)

    # ── input_open(as, s) ─────────────────────────────────────────────────────

    def open(self, s):
        """
        input_open(as, s):
        Open s as a file input.  s may be prefixed with 'include:' or 'file:'.
        Searches include_list for include: type if not found relative to CWD.
        """
        as_ = self.as_

        # Determine type from prefix
        input_type = INPUT_TYPE_FILE
        path       = s
        if not _is_absolute(s):
            colon = s.find(':')
            if colon > 0:
                prefix = s[:colon]
                if prefix == 'include':
                    input_type = INPUT_TYPE_INCLUDE
                    path = s[colon+1:]
                elif prefix == 'file':
                    input_type = INPUT_TYPE_FILE
                    path = s[colon+1:]

        if input_type == INPUT_TYPE_FILE:
            if path == '-':
                fh = os.fdopen(os.dup(0), 'rb')    # stdin
            else:
                try:
                    fh = open(path, 'rb')
                except OSError as e:
                    raise IOError(f"Cannot open file '{path}': {e}") from e
            self._pushpath(path)
            entry = InputEntry(INPUT_TYPE_FILE, fh, s)
            self._push(entry)

        else:  # INPUT_TYPE_INCLUDE
            # 1. Try relative to current file's directory
            cur_dir = self.file_dir[-1] if self.file_dir else '.'
            candidate = os.path.join(cur_dir, path)
            fh = _try_open(candidate)
            if fh:
                self._pushpath(candidate)
                entry = InputEntry(INPUT_TYPE_INCLUDE, fh, s)
                self._push(entry)
                return

            # 2. Try each entry in the assembler's include_list
            for inc_dir in as_.include_list:
                candidate = os.path.join(inc_dir, path)
                fh = _try_open(candidate)
                if fh:
                    self._pushpath(candidate)
                    entry = InputEntry(INPUT_TYPE_INCLUDE, fh, s)
                    self._push(entry)
                    return

            raise IOError(f"Cannot open include file '{path}'")

    # ── input_openstring(as, s, str) ──────────────────────────────────────────

    def open_string(self, name, content):
        """
        input_openstring(as, name, content):
        Push a string as an input source.  Used by the macro expander.
        """
        entry = InputEntry(INPUT_TYPE_STRING, content, name)
        self._push(entry)

    # ── input_readline(as) → str | None ──────────────────────────────────────

    def readline(self):
        """
        input_readline(as):
        Read and return the next source line (without line terminator),
        or None when all inputs are exhausted.

        Handles CR, LF, and CRLF endings.  Maximum line length 2048 chars
        (matches C linebuff[2049]).
        """
        as_ = self.as_

        while True:
            # Open the next file from the input_files list if nothing is open
            if not self._stack:
                if not as_.input_files:
                    return None
                filename = as_.input_files.pop(0)
                self.open(filename)
                continue

            top = self._top

            if top.type in (INPUT_TYPE_FILE, INPUT_TYPE_INCLUDE):
                line = self._readline_file(top)
                if line is None:
                    self._pop()
                    continue
                return line

            elif top.type == INPUT_TYPE_STRING:
                line = self._readline_string(top)
                if line is None:
                    self._stack.pop()    # string entry: no file to close
                    continue
                return line

            else:
                raise RuntimeError(f"Unknown input type {top.type}")

    def _readline_file(self, entry):
        """
        Read one line from an open binary file.
        Returns str (without EOL) or None on EOF.
        """
        buf   = []
        fh    = entry.data
        if fh is None:
            return None

        while True:
            b = fh.read(1)
            if not b:
                # EOF
                if not buf:
                    return None      # truly empty → signal to pop
                return ''.join(buf)  # last line with no EOL
            c = b[0]
            if c == 0x0D:           # CR
                # consume optional LF
                b2 = fh.read(1)
                if b2 and b2[0] != 0x0A:
                    # put it back via seek (binary file, so this is safe)
                    fh.seek(-1, 1)
                return ''.join(buf)
            elif c == 0x0A:         # LF
                b2 = fh.read(1)
                if b2 and b2[0] != 0x0D:
                    fh.seek(-1, 1)
                return ''.join(buf)
            else:
                if len(buf) < MAX_LINE:
                    buf.append(chr(c))

    def _readline_string(self, entry):
        """
        Read one line from an in-memory string.
        Returns str (without EOL) or None when exhausted.
        """
        s   = entry.data
        pos = entry.data2
        if pos >= len(s):
            return None

        buf = []
        while pos < len(s):
            c = s[pos]; pos += 1
            if c == '\r':
                if pos < len(s) and s[pos] == '\n':
                    pos += 1
                break
            elif c == '\n':
                if pos < len(s) and s[pos] == '\r':
                    pos += 1
                break
            elif c == '\0':
                break
            else:
                if len(buf) < MAX_LINE:
                    buf.append(c)
        entry.data2 = pos
        return ''.join(buf)

    # ── input_curspec(as) → str ───────────────────────────────────────────────

    def curspec(self):
        """input_curspec: return filespec of current input, or None."""
        top = self._top
        return top.filespec if top else None

    # ── input_open_standalone(as, s, rfn) ─────────────────────────────────────

    def open_standalone(self, s):
        """
        input_open_standalone(as, s):
        Open file s for non-line reading (e.g. INCLUDEBIN).
        Returns (file_handle, resolved_filename) or (None, None).
        """
        as_ = self.as_
        if _is_absolute(s):
            fh = _try_open(s)
            return (fh, s) if fh else (None, None)

        cur_dir = self.file_dir[-1] if self.file_dir else '.'
        candidate = os.path.join(cur_dir, s)
        fh = _try_open(candidate)
        if fh:
            return (fh, candidate)

        for inc_dir in as_.include_list:
            candidate = os.path.join(inc_dir, s)
            fh = _try_open(candidate)
            if fh:
                return (fh, candidate)

        return (None, None)

    # ── input_isinclude ───────────────────────────────────────────────────────

    def isinclude(self):
        """input_isinclude: True if the current input is an include file."""
        top = self._top
        return top is not None and top.type == INPUT_TYPE_INCLUDE


# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_absolute(s):
    """
    input_isabsolute(s): True if path is absolute (Unix or Windows).
    Matches the C version's WIN32 and unix checks.
    """
    if not s:
        return False
    if s[0] == '/':
        return True
    # Windows: C:\... or C:/...
    if len(s) >= 2 and s[1] == ':' and s[0].isalpha():
        return True
    return False


def _try_open(path):
    """Try to open a file in binary mode; return handle or None."""
    try:
        return open(path, 'rb')
    except OSError:
        return None
