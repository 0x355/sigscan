# sigscan

A fast, read-only **signature / pattern scanner** for Windows x64 processes and PE modules, written in Rust.

Built for reverse engineering research, no injection, no writes, no shellcode.

```
[*] Process: [+] Process : Notepad.exe  (PID 22224)
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
| `TARGET`          | Process name (`notepad.exe`) **or** numeric PID |
| `PATTERN`         | IDA Style hex pattern, e.g. `"48 8B ?? ?? ?? 89"` |
| `-m`, `--module`  | Restrict scan to one module (e.g. `--module user32.dll`) |
| `-f`, `--first`   | Stop after the first match |
| `-n`, `--count N` | Stop after N matches  |

---

## Limitations

- **Windows x64 only.** The Toolhelp32 / ReadProcessMemory APIs are Windows specific. The pattern parser and scanner unit tests run on any platform
- **Read-only** `sigscan` never writes to the target process. It opens handles only with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`.
- **No kernel-mode scanning.** Only usermode pages accessible via `ReadProcessMemory` are scanned.
- **Protected processes (PPL).** Anticheat software and some OS processes (`csrss.exe`, `smss.exe`) use kernel-enforced protection levels that prevent `OpenProcess` from succeeding even as Administrator.
- **Obfuscated / packed modules** If a module's in memory layout differs from its on disk PE (e.g. custom loaders, runtime packing), the reported module size may be inaccurate.
- **Performance** The scanner is a straightforward 0(n * m) linear search. For very large modules (> 200 MB) and long patterns, consider reducing scope with `--module`.
- **No 32bit processes** Scanning 32 Bit (WOW64) processes from a 64 bit binary is not currently supported.

---

## License
MIT