/*
 * Memory Scanner Example
 * Demonstrates using syscalls to scan process memory
 */

#include "../syscalls.h"
#include <stdio.h>
#include <vector>

struct MemoryRegion {
    PVOID baseAddress;
    SIZE_T size;
    ULONG protection;
    ULONG state;
    ULONG type;
};

std::vector<MemoryRegion> EnumerateMemoryRegions(HANDLE hProcess) {
    std::vector<MemoryRegion> regions;
    PVOID address = nullptr;

    while (true) {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        SIZE_T returnLength = 0;

        NTSTATUS status = g_Syscalls->NtQueryVirtualMemory(
            hProcess,
            address,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returnLength
        );

        if (!NT_SUCCESS(status)) {
            break;
        }

        if (mbi.State == MEM_COMMIT) {
            MemoryRegion region;
            region.baseAddress = mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;
            regions.push_back(region);
        }

        address = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    return regions;
}

bool ScanMemoryForPattern(HANDLE hProcess, PVOID address, SIZE_T size, const BYTE* pattern, SIZE_T patternSize) {
    BYTE* buffer = new BYTE[size];
    SIZE_T bytesRead = 0;

    NTSTATUS status = g_Syscalls->NtReadVirtualMemory(
        hProcess,
        address,
        buffer,
        size,
        &bytesRead
    );

    if (!NT_SUCCESS(status)) {
        delete[] buffer;
        return false;
    }

    bool found = false;
    for (SIZE_T i = 0; i < bytesRead - patternSize; i++) {
        if (memcmp(buffer + i, pattern, patternSize) == 0) {
            printf("[+] Pattern found at: 0x%p (offset: 0x%zX)\n", (BYTE*)address + i, i);
            found = true;
        }
    }

    delete[] buffer;
    return found;
}

int main() {
    printf("\n[*] Memory Scanner Example\n\n");

    // Initialize syscall library
    g_Syscalls = new SyscallLibrary();
    if (!g_Syscalls->Initialize()) {
        printf("[-] Failed to initialize\n");
        return 1;
    }

    // Open current process
    HANDLE hProcess = GetCurrentProcess();

    // Enumerate memory regions
    printf("[*] Enumerating memory regions...\n");
    auto regions = EnumerateMemoryRegions(hProcess);
    printf("[+] Found %zu memory regions\n\n", regions.size());

    // Display regions
    int count = 0;
    for (const auto& region : regions) {
        printf("  [%d] Base: 0x%p | Size: 0x%zX | Protect: 0x%X\n",
            count++,
            region.baseAddress,
            region.size,
            region.protection
        );

        if (count >= 10) {
            printf("  ...\n");
            break;
        }
    }

    // Scan for pattern
    printf("\n[*] Scanning for pattern...\n");
    BYTE pattern[] = { 0x4D, 0x5A }; // MZ header
    
    int foundCount = 0;
    for (const auto& region : regions) {
        if (region.protection & PAGE_EXECUTE_READ || region.protection & PAGE_READONLY) {
            if (ScanMemoryForPattern(hProcess, region.baseAddress, region.size, pattern, sizeof(pattern))) {
                foundCount++;
            }
        }
    }

    printf("\n[+] Found pattern in %d regions\n", foundCount);

    delete g_Syscalls;
    return 0;
}
