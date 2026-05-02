#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "syscalls.h"

void PrintBanner() {
    printf("\n");
    printf("  Universal Syscall Library\n");
    printf("  Direct syscall execution - EDR/AV bypass\n");
    printf("\n");
}

void PrintMenu() {
    printf("  1. Test memory operations\n");
    printf("  2. Test process operations\n");
    printf("  3. Test thread operations\n");
    printf("  4. Show syscall numbers\n");
    printf("  5. Exit\n");
    printf("\n  > ");
}

void TestMemoryOperations() {
    printf("\n[*] Testing memory operations\n");

    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 0x1000;

    // Allocate
    NTSTATUS status = g_Syscalls->NtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NT_SUCCESS(status)) {
        printf("[+] Allocated memory at 0x%p\n", baseAddress);

        // Write
        char testData[] = "Syscall test data";
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

            // Read
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
                printf("[+] Read %zu bytes: %s\n", read, readBuffer);
            }
        }

        // Protect
        ULONG oldProtect = 0;
        SIZE_T protectSize = regionSize;
        PVOID protectAddr = baseAddress;
        status = g_Syscalls->NtProtectVirtualMemory(
            hProcess,
            &protectAddr,
            &protectSize,
            PAGE_EXECUTE_READ,
            &oldProtect
        );

        if (NT_SUCCESS(status)) {
            printf("[+] Changed protection (old: 0x%X)\n", oldProtect);
        }

        // Free
        regionSize = 0;
        status = g_Syscalls->NtFreeVirtualMemory(
            hProcess,
            &baseAddress,
            &regionSize,
            MEM_RELEASE
        );

        if (NT_SUCCESS(status)) {
            printf("[+] Memory freed\n");
        }
    } else {
        printf("[-] Failed to allocate memory (0x%X)\n", status);
    }

    printf("\n");
}

void TestProcessOperations() {
    printf("\n[*] Testing process operations\n");

    // Open current process
    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)GetCurrentProcessId();

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = g_Syscalls->NtOpenProcess(
        &hProcess,
        PROCESS_QUERY_INFORMATION,
        &objAttr,
        &clientId
    );

    if (NT_SUCCESS(status)) {
        printf("[+] Opened process (PID: %d)\n", GetCurrentProcessId());

        // Query process information
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        ULONG returnLength = 0;
        status = g_Syscalls->NtQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            &returnLength
        );

        if (NT_SUCCESS(status)) {
            printf("[+] PEB address: 0x%p\n", pbi.PebBaseAddress);
        }

        g_Syscalls->NtClose(hProcess);
    } else {
        printf("[-] Failed to open process (0x%X)\n", status);
    }

    printf("\n");
}

void TestThreadOperations() {
    printf("\n[*] Testing thread operations\n");

    // Open current thread
    HANDLE hThread = nullptr;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    CLIENT_ID clientId = { 0 };
    clientId.UniqueThread = (HANDLE)GetCurrentThreadId();

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = g_Syscalls->NtOpenThread(
        &hThread,
        THREAD_QUERY_INFORMATION,
        &objAttr,
        &clientId
    );

    if (NT_SUCCESS(status)) {
        printf("[+] Opened thread (TID: %d)\n", GetCurrentThreadId());

        // Query thread information
        THREAD_BASIC_INFORMATION tbi = { 0 };
        ULONG returnLength = 0;
        status = g_Syscalls->NtQueryInformationThread(
            hThread,
            (THREADINFOCLASS)0, // ThreadBasicInformation
            &tbi,
            sizeof(tbi),
            &returnLength
        );

        if (NT_SUCCESS(status)) {
            printf("[+] TEB address: 0x%p\n", tbi.TebBaseAddress);
        }

        g_Syscalls->NtClose(hThread);
    } else {
        printf("[-] Failed to open thread (0x%X)\n", status);
    }

    printf("\n");
}

void ShowSyscallNumbers() {
    printf("\n[*] Syscall numbers (current Windows version)\n\n");

    const char* functions[] = {
        "NtAllocateVirtualMemory",
        "NtFreeVirtualMemory",
        "NtProtectVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtQueryVirtualMemory",
        "NtOpenProcess",
        "NtTerminateProcess",
        "NtSuspendProcess",
        "NtResumeProcess",
        "NtQueryInformationProcess",
        "NtCreateThreadEx",
        "NtOpenThread",
        "NtSuspendThread",
        "NtResumeThread",
        "NtTerminateThread",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtQueryInformationThread",
        "NtCreateFile",
        "NtReadFile",
        "NtWriteFile",
        "NtClose",
        "NtQuerySystemInformation",
        "NtDelayExecution"
    };

    for (int i = 0; i < sizeof(functions) / sizeof(functions[0]); i++) {
        DWORD ssn = g_Syscalls->GetSyscallNumber(functions[i]);
        if (ssn != 0xFFFFFFFF) {
            printf("  %-30s SSN: 0x%04X (%d)\n", functions[i], ssn, ssn);
        } else {
            printf("  %-30s SSN: FAILED\n", functions[i]);
        }
    }

    printf("\n");
}

int main() {
    SetConsoleTitleA("Universal Syscall Library");

    PrintBanner();

    // Initialize syscall library
    g_Syscalls = new SyscallLibrary();
    if (!g_Syscalls->Initialize()) {
        printf("[-] Failed to initialize syscall library\n");
        printf("\n  Press any key to exit...");
        getchar();
        return 1;
    }

    printf("[+] Syscall library initialized\n");
    printf("[+] All syscalls resolved successfully\n\n");

    while (true) {
        PrintMenu();

        int choice = getchar();
        while (getchar() != '\n'); // Clear buffer

        switch (choice) {
        case '1':
            TestMemoryOperations();
            break;

        case '2':
            TestProcessOperations();
            break;

        case '3':
            TestThreadOperations();
            break;

        case '4':
            ShowSyscallNumbers();
            break;

        case '5':
            delete g_Syscalls;
            return 0;

        default:
            break;
        }
    }

    return 0;
}
