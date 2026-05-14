# sigscan

A fast, read-only **signature / pattern scanner** for Windows x64 processes and PE modules, written in Rust.

Built for reverse engineering research, no injection, no writes, no shellcode.

```
[+] Process : Notepad.exe  (PID 22224)
[+] Module  : Notepad.exe
[+] Range   : 00007FF7CB3B0000 - 00007FF7CB6B1000  (3076 KiB)

  [MATCH]
    address : 00007FF7CB3B1123
    offset  : +0x1123
    bytes   : E8 18 A5 14 00

[+] Total matches: 1
```

---

## What is Signature Scanning?

A **signature** (or **pattern**) is a short sequence of bytes that uniquely identifies a
specific instruction or code construct inside a compiled binary. Reverse engineers use
signatures to relocate functions or data structures across binary versions, instead of 
hard-coding an address that changes with every update, you search for the surrounding
byte pattern, which is far more stable.

A typical use-case in game research:

1. Find a function of interest in a disassembler (IDA, Ghidra, Binary Ninja...)/
2. Extract a short, distinctive byte sequence from the function prologue or a unique instruction.
3. use `sigscan` to locate that sequence at runtime in the live process, giving you the current address regardless of ASLR or version changes.

---

## Wildcard Matching

Real code often contains absolute addresses or relative offsets embedded directly inside
instructions. There operand bytes change between runs (ASLR) or between versions.
**Wildcards** let you write a pattern that matches the invariant opcode bytes while
ignoring the variable operand bytes.

Syntax IDA-style hex with `??` for wildcards:

```
48 8B ?? ?? ?? 89
^^ ^^          ^^ <- exact bytes, must match precisely
      ^^ ^^ ^^    <- wildcards, match any byte
```

| Token | Meaning |
|-------|---------|
| `48`  | Match the byte `0x48` exactly |
| `??`  | Match any single byte |
| `?`   | Alias for `??` |

Internally the parser convers this into `Vec<Option<u8>>`:
- `Some(0x48)` -> exact byte
- `None`       -> wildcard

The scanner then walks the module buffer and tests the pattern at every byte position.

---

## Module-Relative Offsets

Windows loads DLLs at a **base address** chosen at runtime by ASLR,
An **absolute address** like `0x00007FF812341234` it meaningless across reboots.

A **module-relative offset** (`+0x1234`) tells you how far into the module the match
sits. To convert back to an absolute address at runtime:

```
absolute_address = module_base + relative_offset
```

`sigscan` prints both so you can choose what to record.

---

### How to Build

**Prerequisites**

- Rust stable toolchain (`rustup toolchain install stable`)
- Windows x64 target (the crate is `cfg(target_os = "windows")` guarded)

```powershell
git clone https://github.com/0x355/sigscan
cd sigscan
cargo build --release
```

The release binary ends up at `target\release\sigscan.exe`.

**Run tests** (pattern parser and scanner unit tests run on any platform):

```powershell
cargo test
```

---

## Usage

```
sigscan <TARGET> <PATTERN> [OPTIONS]
```

| Argument / Option | Description               |
|-------------------|---------------------------|
| `TARGET`          | Process name (`notepad.exe`), numeric PID, **or** path to a PE file on disk (anything containing `/`, `\`, or `:` is treated as a file path) |
| `PATTERN`         | IDA Style hex pattern, e.g. `"48 8B ?? ?? ?? 89"` |
| `-m`, `--module`  | Restrict scan to one module (e.g. `--module user32.dll`) |
| `-f`, `--first`   | Stop after the first match (per pattern when `--patterns` is used) |
| `-n`, `--count N` | Stop after N matches (per pattern when `--patterns` is used) |
| `--all-sections`  | Scan every section, not just executable ones (default scans only `IMAGE_SCN_MEM_EXECUTE`, e.g. `.text`) |
| `--patterns FILE` | Scan multiple signatures in a single pass; mutually exclusive with the positional `PATTERN` |
| `--disasm`        | Print Intel-syntax disassembly starting at each match address (uses `iced-x86`; bitness auto-detected from the target's WOW64 status) |
| `--disasm-count N`| Number of instructions to disassemble after each match (default 5) |
| `--disasm-before N`| Number of instructions to show **before** the match by stream synchronization (default 2; set to 0 to disable). The match line is marked with `>>` |
| `--json`           | Emit a single JSON object on stdout instead of the colored text report; composes with every other flag (`--first`, `--patterns`, `--disasm`, ...). Errors stay on stderr so the stream stays valid for piping. |

### File-on-disk scanning

If `TARGET` contains a path separator (`/`, `\`) or a drive-letter colon, `sigscan` reads the PE from disk instead of attaching to a live process. Bitness (`x86` vs `x64`) and the preferred `ImageBase` are taken from the PE Optional Header, so reported absolute addresses are correct *modulo* ASLR at runtime. Module-relative offsets (`+0x...`) are stable across both modes.

```
sigscan C:\Windows\System32\notepad.exe "48 89 5C 24" --first --disasm
sigscan ./packed.exe "55 8B EC" --all-sections
```

This mode also works on Linux/macOS — useful for analyzing Windows binaries from a non-Windows host. The `--module` flag is incompatible with file targets (the file is itself the single module).

### JSON output

`--json` emits a single pretty-printed JSON object describing the scan. Stdout stays clean (errors go to stderr) so the output pipes into `jq`, IDA scripts, CI checks, etc.

```json
{
  "target": {
    "kind": "file",
    "path": "C:\\Windows\\System32\\notepad.exe",
    "arch": "x64",
    "image_base": "0x140000000",
    "size_bytes": 360448
  },
  "modules": [
    {
      "name": "notepad.exe",
      "base": "0x140000000",
      "size": 360448,
      "scope": [".text", "fothk"],
      "matches": [
        {
          "pattern": "MATCH",
          "address": "0x140001830",
          "offset": "0x1830",
          "bytes": "48 89 5C 24"
        }
      ]
    }
  ],
  "total_matches": 1
}
```

- `target.kind` is `"file"` (with `path`, `arch`, `image_base`, `size_bytes`) or `"process"` (with `name`, `pid`, `arch`).
- Addresses, offsets, and bytes are hex strings (`"0x..."` and space-separated `"48 89 5C 24"`) for cross-tool portability.
- With `--disasm`, each match grows a `disasm` array of `{ ip, bytes, text, is_match }`; the `is_match: true` row marks the matched instruction.
- Patterns from `--patterns` keep their labels (`pattern` field); single-pattern scans use `"MATCH"`.

### `--patterns` file format

One signature per line. `#` starts a comment that runs to end-of-line. Blank lines are ignored. Each non-empty line is either a bare pattern or `LABEL = PATTERN`; the label is used in place of `MATCH` in the output, otherwise unlabeled patterns are named `pattern 1`, `pattern 2`, ...

```
# example signatures
Prologue       = 48 89 5C 24
NearCall       = E8 ?? ?? ?? ??
LeaRipRelative = 48 8D 0D ?? ?? ?? ??
48 8B 05 ?? ?? ?? ??    # unlabeled
```

---

## Limitations

- **Live process scanning is Windows-only.** The Toolhelp32 / ReadProcessMemory APIs are Windows specific. File-on-disk scanning works on any OS (Linux/macOS/Windows). Pattern parser, PE parser, scanner, and disassembler unit tests run on all platforms in CI.
- **Read-only** `sigscan` never writes to the target process. It opens handles only with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`.
- **No kernel-mode scanning.** Only usermode pages accessible via `ReadProcessMemory` are scanned.
- **Protected processes (PPL).** Anticheat software and some OS processes (`csrss.exe`, `smss.exe`) use kernel-enforced protection levels that prevent `OpenProcess` from succeeding even as Administrator.
- **Obfuscated / packed modules** If a module's in memory layout differs from its on disk PE (e.g. custom loaders, runtime packing), the reported module size may be inaccurate.
- **Performance** Scanning uses Aho-Corasick on the longest literal run of each pattern as a multi-byte anchor; full-pattern verification (wildcards included) runs only at candidate positions. Multi-pattern scans walk the data once for all signatures. Practical complexity is O(n + matches * m). For very large modules (> 200 MB), consider reducing scope with `--module`.
- **WOW64 (32-bit) processes** are supported: their 32-bit modules are enumerated via `TH32CS_SNAPMODULE32` and the process architecture is shown in the header.

---

## TODO

Planned improvements, roughly in order of impact:

- [x] **SIMD-accelerated first-byte search.** Replace the manual byte-by-byte skip in `scanner::scan` with `memchr::memchr` to vectorize the candidate-finding loop. Typically 5-20x faster on large modules.
- [x] **PE-aware scanning.** Parse the PE headers and limit scanning to `IMAGE_SCN_MEM_EXECUTE` sections by default (e.g. `.text`). Reduces false positives from string/resource data and shrinks the search space. Add `--all-sections` to opt back into the current behavior.
- [x] **Multi-pattern scan in a single pass.** Accept `--patterns sigs.txt` (one pattern per line, with optional labels) so multiple signatures can be located without re-enumerating modules and re-reading memory N times.
- [x] **`--json` output mode.** Single pretty-printed JSON object on stdout (errors stay on stderr); composes with `--disasm`, `--patterns`, `--first`. See the **JSON output** section above for the schema.
- [x] **Replace `unreachable!` in `scanner.rs` with `debug_assert!` + early return.** Today a hypothetical parser bug becomes a release-mode panic; a soft fallback is safer.
- [x] **Disassembly context at each match.** Optional `--disasm` flag that uses `iced-x86` to print the instruction at the matched address (and a few before/after) to help confirm the hit is what you expected.
- [x] **Backward disassembly context.** Extend `--disasm` to also show K instructions before the match by synchronizing on candidate stream offsets (try `match-1..match-15`, pick the deepest that lands cleanly on the match address). Useful for confirming a match sits at a function prologue boundary. *(Iterates one-instruction-back K times via `--disasm-before`; default 2.)*
- [x] **Scan PE files on disk.** Allow `sigscan <path.exe> <pattern>` to load and scan a PE without attaching to a live process, useful when the target can't run or is anti-debug heavy. *(File-mode also works on Linux/macOS — the binary no longer hard-fails on non-Windows; only live process scanning stays Windows-only.)*
- [x] **Aho-Corasick for long and multi-pattern scans.** The longest literal run of each pattern is picked as an anchor and all anchors are searched together via a single Aho-Corasick automaton; each hit is then verified against the full pattern (wildcards included) at the back-shifted candidate position. Multi-pattern mode walks the data once instead of N times; long patterns benefit from a multi-byte prefilter rather than a single-byte `memchr`.

---

## License
MIT