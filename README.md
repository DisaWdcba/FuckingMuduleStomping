# Module Stomping PoC

A proof-of-concept (PoC) demonstrating **module stomping** – a technique that injects and executes shellcode inside a manually mapped legitimate DLL's memory region. This method aims to evade security solutions that monitor typical process injection patterns (e.g., `VirtualAllocEx` + `CreateRemoteThread`) by leveraging an existing (or manually loaded) module's executable memory.

> ⚠️ **Disclaimer**  
> This project is intended for **educational and research purposes only**. Misuse of this code for malicious activities is strictly prohibited and may violate laws. Use it only on systems you own or have explicit permission to test.

---

## Table of Contents
- [What is Module Stomping?](#what-is-module-stomping)
- [How It Works](#how-it-works)
- [Key Components](#key-components)
- [Build Instructions](#build-instructions)
- [Usage](#usage)
- [Technical Details](#technical-details)
- [Notes & Limitations](#notes--limitations)
- [References](#references)

---

## What is Module Stomping?

Module stomping (also known as *DLL hollowing* or *module overloading*) is a technique that writes malicious code into the memory region of a legitimate module (DLL). Instead of allocating new executable memory with `VirtualAlloc` (which can be suspicious), the attacker locates a suitable existing module, modifies its memory permissions, and overwrites a portion of it with shellcode. This can help bypass security products that monitor for anomalous memory allocations.

This PoC uses a **manually mapped** DLL (`srvcli.dll`) as the target region, then writes and executes shellcode inside it.

---

## How It Works

1. **Manual DLL Mapping**  
   The code reads `srvcli.dll` from disk, parses its PE headers, and maps it into the current process's memory manually (without using `LoadLibrary`). This gives a base address for a clean, executable image.

2. **Shellcode Decryption**  
   The embedded shellcode is encrypted with a simple XOR cipher. The key is hardcoded (`"12henry1222345??6aa+-==@asd"`). Decryption restores the original payload.

3. **Target Address Calculation**  
   A specific offset inside the mapped DLL is chosen (`0x1000 * 2 + 0xf`, i.e., `0x200F` bytes from the base). This area is assumed to be within the DLL's `.text` or another writable/executable section.

4. **Memory Protection Change**  
   The target region's protection is changed to `PAGE_READWRITE` using `NtProtectVirtualMemory`. The decrypted shellcode is then copied there using `RtlMoveMemory`.

5. **Execution**  
   A new thread is created with `NtCreateThreadEx` pointing to the copied shellcode. The thread executes the payload, and the main thread waits for it to finish using `NtWaitForSingleObject`.

> **Note:** The `DecryptAES` function is present but **not used** – the actual decryption is a simple XOR loop. The AES routine may be a leftover or placeholder.

---

## Key Components

- **`ManualMapDLL`**  
  A custom PE loader that maps a DLL into the current process without calling `LoadLibrary`. Handles section mapping, base relocations, and import resolution.

- **XOR Decryption Loop**  
  The embedded shellcode is decrypted byte-by-byte using a hardcoded key.

- **Native API Usage**  
  Direct calls to `NtProtectVirtualMemory`, `NtCreateThreadEx`, and `NtWaitForSingleObject` (from `ntdll.dll`) to perform memory operations and thread creation with minimal user-mode API visibility.

- **Target DLL**  
  `C:\Windows\system32\srvcli.dll` is used as the "stomp" target. Any other DLL can be specified by modifying the `slib` variable.

---

## Build Instructions

### Prerequisites
- Visual Studio (2019 or later) with **Desktop development with C++** workload.
- Windows SDK (included with Visual Studio).

### Steps
1. Clone this repository.
2. Open the project in Visual Studio.
3. Ensure the solution is configured for **x64** (the code is 64‑bit).
4. Build the project (`Ctrl+Shift+B`).

The executable will be generated (e.g., `ModuleStomping.exe`).

### Dependencies
- `ntdll.lib` – linked explicitly for NT functions.
- `crypt32.lib` – linked for the (unused) AES decryption routine.

---

## Usage

Run the compiled executable from an elevated command prompt (administrator privileges may be required for certain memory operations).

```cmd
ModuleStomping.exe
```

If everything works, the shellcode will be executed inside the mapped `srvcli.dll` region. The program will pause with `getchar()` before launching the thread – press **Enter** to continue.

### Customizing the Payload
1. Replace the `encryptedShellcode` array with your own encrypted payload (XOR with the same key).
2. Modify the XOR key if desired.
3. Change the target DLL or offset if needed.

---

## Technical Details

| Component            | Description                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------|
| **Manual Mapping**   | Parses PE headers, allocates memory at preferred or arbitrary base, copies sections, applies relocations, resolves imports, and sets section protections. |
| **Memory Protection**| Uses `NtProtectVirtualMemory` to temporarily mark the target region as writable, then restores original permissions. |
| **Thread Creation**  | `NtCreateThreadEx` is used (undocumented) to spawn the shellcode thread.                      |
| **Target Region**    | `(PBYTE)addr + 0x1000 * 2 + 0xf` – offset `0x200F` into the DLL. This must land inside an executable section (e.g., `.text`). The exact offset may need adjustment if the section layout changes. |
| **XOR Key**          | `12henry1222345??6aa+-==@asd` (length 29). The decryption loop uses `key[i % keylength]`.    |
| **Shellcode**        | The provided encrypted shellcode is a placeholder (likely a `MessageBox` or similar). Replace it with your own. |

---

## Notes & Limitations

- **Only 64‑bit**: The code is built for x64 architecture (relocation handling uses `IMAGE_REL_BASED_DIR64`).  
- **Hardcoded Path**: `C:\Windows\system32\srvcli.dll` – change if the DLL is missing or you want a different target.  
- **Offset Dependency**: The offset `0x200F` may need to be recalculated if the DLL's section layout changes. Use a PE viewer (e.g., `dumpbin` or `CFF Explorer`) to find a safe location within an executable section.  
- **No Error Recovery**: The code lacks extensive error handling; failures will cause the program to exit.  
- **Antivirus Detection**: This technique is known and may be flagged by modern EDR/AV solutions. Use in controlled environments only.  
- **AES Function**: `DecryptAES` is included but never called. It can be removed or adapted for stronger encryption.

---



This project is provided under the Apache 2.0 License – see the [LICENSE](LICENSE) file for details.

---

**Use responsibly.**
