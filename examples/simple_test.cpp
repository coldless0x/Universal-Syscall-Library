/*
 * Simple Test Example
 * Quick test to verify syscall library is working
 */

#include "../syscalls.h"
#include <stdio.h>

int main() {
    printf("\n[*] Simple Syscall Test\n\n");

    // Initialize
    g_Syscalls = new SyscallLibrary();
    if (!g_Syscalls->Initialize()) {
        printf("[-] Failed to initialize\n");
        return 1;
    }
    printf("[+] Library initialized\n");

    // Test 1: Allocate memory
    printf("\n[*] Test 1: Memory allocation\n");
    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 0x1000;

    NTSTATUS status = g_Syscalls->NtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NT_SUCCESS(status)) {
        printf("[+] Allocated at: 0x%p\n", baseAddress);

        // Test 2: Write memory
        printf("\n[*] Test 2: Memory write\n");
        char testData[] = "Hello from syscall!";
        SIZE_T written = 0;

        status = g_Syscalls->NtWriteVirtualMemory(
            hProcess,
            baseAddress,
            testData,
            sizeof(testData),
            &written
        );

        if (NT_SUCCESS(status)) {
            printf("[+] Written %zu bytes\n", written);

            // Test 3: Read memory
            printf("\n[*] Test 3: Memory read\n");
            char readBuffer[256] = { 0 };
            SIZE_T read = 0;

            status = g_Syscalls->NtReadVirtualMemory(
                hProcess,
                baseAddress,
                readBuffer,
                sizeof(testData),
                &read
            );

            if (NT_SUCCESS(status)) {
                printf("[+] Read %zu bytes: \"%s\"\n", read, readBuffer);
            } else {
                printf("[-] Read failed: 0x%X\n", status);
            }
        } else {
            printf("[-] Write failed: 0x%X\n", status);
        }

        // Test 4: Free memory
        printf("\n[*] Test 4: Memory free\n");
        regionSize = 0;
        status = g_Syscalls->NtFreeVirtualMemory(
            hProcess,
            &baseAddress,
            &regionSize,
            MEM_RELEASE
        );

        if (NT_SUCCESS(status)) {
            printf("[+] Memory freed\n");
        } else {
            printf("[-] Free failed: 0x%X\n", status);
        }
    } else {
        printf("[-] Allocation failed: 0x%X\n", status);
    }

    // Test 5: Get syscall number
    printf("\n[*] Test 5: Syscall numbers\n");
    DWORD ssn = g_Syscalls->GetSyscallNumber("NtReadVirtualMemory");
    printf("[+] NtReadVirtualMemory SSN: 0x%04X (%d)\n", ssn, ssn);

    printf("\n[+] All tests completed!\n\n");

    delete g_Syscalls;
    return 0;
}
