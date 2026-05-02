#include "syscalls.h"
#include <stdio.h>

#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)

SyscallLibrary* g_Syscalls = nullptr;

SyscallLibrary::SyscallLibrary() : m_initialized(false), m_ntdll(nullptr) {
    memset(&m_NtAllocateVirtualMemory, 0, sizeof(SYSCALL_ENTRY));
}

// Helper to create syscall stub dynamically
template<typename Func>
Func CreateSyscallStub(DWORD ssn) {
    static BYTE stub[32];
    BYTE code[] = {
        0x4C, 0x8B, 0xD1,             // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, ssn (will be patched)
        0x0F, 0x05,                   // syscall
        0xC3                          // ret
    };
    
    memcpy(stub, code, sizeof(code));
    *(DWORD*)(stub + 4) = (DWORD)ssn;
    
    DWORD oldProtect;
    VirtualProtect(stub, sizeof(stub), PAGE_EXECUTE_READWRITE, &oldProtect);
    
    return (Func)(void*)stub;
}

SyscallLibrary::~SyscallLibrary() {
}

bool SyscallLibrary::Initialize() {
    m_ntdll = GetModuleHandleA("ntdll.dll");
    if (!m_ntdll) {
        return false;
    }

    // Resolve critical syscalls (must succeed)
    bool success = true;
    success &= ResolveSyscall("NtAllocateVirtualMemory", &m_NtAllocateVirtualMemory);
    success &= ResolveSyscall("NtFreeVirtualMemory", &m_NtFreeVirtualMemory);
    success &= ResolveSyscall("NtProtectVirtualMemory", &m_NtProtectVirtualMemory);
    success &= ResolveSyscall("NtReadVirtualMemory", &m_NtReadVirtualMemory);
    success &= ResolveSyscall("NtWriteVirtualMemory", &m_NtWriteVirtualMemory);
    success &= ResolveSyscall("NtQueryVirtualMemory", &m_NtQueryVirtualMemory);
    success &= ResolveSyscall("NtOpenProcess", &m_NtOpenProcess);
    success &= ResolveSyscall("NtQueryInformationProcess", &m_NtQueryInformationProcess);
    success &= ResolveSyscall("NtCreateThreadEx", &m_NtCreateThreadEx);
    success &= ResolveSyscall("NtOpenThread", &m_NtOpenThread);
    success &= ResolveSyscall("NtClose", &m_NtClose);

    if (!success) {
        return false;
    }

    // Resolve optional syscalls (can fail)
    ResolveSyscall("NtTerminateProcess", &m_NtTerminateProcess);
    ResolveSyscall("NtSuspendProcess", &m_NtSuspendProcess);
    ResolveSyscall("NtResumeProcess", &m_NtResumeProcess);
    ResolveSyscall("NtSuspendThread", &m_NtSuspendThread);
    ResolveSyscall("NtResumeThread", &m_NtResumeThread);
    ResolveSyscall("NtTerminateThread", &m_NtTerminateThread);
    ResolveSyscall("NtGetContextThread", &m_NtGetContextThread);
    ResolveSyscall("NtSetContextThread", &m_NtSetContextThread);
    ResolveSyscall("NtQueryInformationThread", &m_NtQueryInformationThread);
    ResolveSyscall("NtCreateFile", &m_NtCreateFile);
    ResolveSyscall("NtReadFile", &m_NtReadFile);
    ResolveSyscall("NtWriteFile", &m_NtWriteFile);
    ResolveSyscall("NtQuerySystemInformation", &m_NtQuerySystemInformation);
    ResolveSyscall("NtDelayExecution", &m_NtDelayExecution);

    m_initialized = true;
    return true;
}

bool SyscallLibrary::ResolveSyscall(const char* functionName, PSYSCALL_ENTRY entry) {
    PVOID functionAddress = GetProcAddress(m_ntdll, functionName);
    if (!functionAddress) {
        return false;
    }

    entry->ssn = ExtractSyscallNumber(functionAddress);
    entry->address = FindSyscallInstruction(functionAddress);

    if (entry->ssn == 0xFFFFFFFF || !entry->address) {
        return false;
    }

    return true;
}

DWORD SyscallLibrary::ExtractSyscallNumber(PVOID functionAddress) {
    BYTE* bytes = (BYTE*)functionAddress;

    // Pattern 1: mov r10, rcx; mov eax, <SSN>
    // 4C 8B D1 B8 [SSN] 00 00 00
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
        return *(DWORD*)(bytes + 4);
    }

    // Pattern 2: mov eax, <SSN> (some functions start directly with this)
    // B8 [SSN] 00 00 00
    if (bytes[0] == 0xB8) {
        return *(DWORD*)(bytes + 1);
    }

    // Pattern 3: Check first 32 bytes for mov eax pattern
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0xB8 && bytes[i + 5] == 0x00 && bytes[i + 6] == 0x00) {
            DWORD ssn = *(DWORD*)(bytes + i + 1);
            if (ssn < 0x1000) { // Sanity check
                return ssn;
            }
        }
    }

    // Check if hooked (jmp instruction)
    if (bytes[0] == 0xE9 || bytes[0] == 0xEB || bytes[0] == 0xFF) {
        return 0xFFFFFFFF;
    }

    return 0xFFFFFFFF;
}

PVOID SyscallLibrary::FindSyscallInstruction(PVOID functionAddress) {
    BYTE* bytes = (BYTE*)functionAddress;

    // Search for syscall instruction (0F 05) within first 50 bytes
    for (int i = 0; i < 50; i++) {
        if (bytes[i] == 0x0F && bytes[i + 1] == 0x05) {
            return &bytes[i];
        }
    }

    return nullptr;
}

DWORD SyscallLibrary::GetSyscallNumber(const char* functionName) {
    PVOID functionAddress = GetProcAddress(m_ntdll, functionName);
    if (!functionAddress) {
        return 0xFFFFFFFF;
    }

    return ExtractSyscallNumber(functionAddress);
}

// Memory operations
NTSTATUS SyscallLibrary::NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    auto syscall = CreateSyscallStub<Func>(m_NtAllocateVirtualMemory.ssn);
    return syscall(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS SyscallLibrary::NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PVOID*, PSIZE_T, ULONG);
    auto syscall = CreateSyscallStub<Func>(m_NtFreeVirtualMemory.ssn);
    return syscall(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS SyscallLibrary::NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    auto syscall = CreateSyscallStub<Func>(m_NtProtectVirtualMemory.ssn);
    return syscall(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS SyscallLibrary::NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    auto syscall = CreateSyscallStub<Func>(m_NtReadVirtualMemory.ssn);
    return syscall(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

NTSTATUS SyscallLibrary::NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    auto syscall = CreateSyscallStub<Func>(m_NtWriteVirtualMemory.ssn);
    return syscall(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS SyscallLibrary::NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
    auto syscall = CreateSyscallStub<Func>(m_NtQueryVirtualMemory.ssn);
    return syscall(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

// Process operations
NTSTATUS SyscallLibrary::NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    typedef NTSTATUS(NTAPI* Func)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    auto syscall = CreateSyscallStub<Func>(m_NtOpenProcess.ssn);
    return syscall(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS SyscallLibrary::NtTerminateProcess(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, NTSTATUS);
    auto syscall = CreateSyscallStub<Func>(m_NtTerminateProcess.ssn);
    return syscall(ProcessHandle, ExitStatus);
}

NTSTATUS SyscallLibrary::NtSuspendProcess(
    HANDLE ProcessHandle
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE);
    auto syscall = CreateSyscallStub<Func>(m_NtSuspendProcess.ssn);
    return syscall(ProcessHandle);
}

NTSTATUS SyscallLibrary::NtResumeProcess(
    HANDLE ProcessHandle
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE);
    auto syscall = CreateSyscallStub<Func>(m_NtResumeProcess.ssn);
    return syscall(ProcessHandle);
}

NTSTATUS SyscallLibrary::NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto syscall = CreateSyscallStub<Func>(m_NtQueryInformationProcess.ssn);
    return syscall(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

// Thread operations
NTSTATUS SyscallLibrary::NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
) {
    typedef NTSTATUS(NTAPI* Func)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
    auto syscall = CreateSyscallStub<Func>(m_NtCreateThreadEx.ssn);
    return syscall(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS SyscallLibrary::NtOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    typedef NTSTATUS(NTAPI* Func)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    auto syscall = CreateSyscallStub<Func>(m_NtOpenThread.ssn);
    return syscall(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS SyscallLibrary::NtSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PULONG);
    auto syscall = CreateSyscallStub<Func>(m_NtSuspendThread.ssn);
    return syscall(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS SyscallLibrary::NtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PULONG);
    auto syscall = CreateSyscallStub<Func>(m_NtResumeThread.ssn);
    return syscall(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS SyscallLibrary::NtTerminateThread(
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, NTSTATUS);
    auto syscall = CreateSyscallStub<Func>(m_NtTerminateThread.ssn);
    return syscall(ThreadHandle, ExitStatus);
}

NTSTATUS SyscallLibrary::NtGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PCONTEXT);
    auto syscall = CreateSyscallStub<Func>(m_NtGetContextThread.ssn);
    return syscall(ThreadHandle, ThreadContext);
}

NTSTATUS SyscallLibrary::NtSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, PCONTEXT);
    auto syscall = CreateSyscallStub<Func>(m_NtSetContextThread.ssn);
    return syscall(ThreadHandle, ThreadContext);
}

NTSTATUS SyscallLibrary::NtQueryInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    auto syscall = CreateSyscallStub<Func>(m_NtQueryInformationThread.ssn);
    return syscall(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

// File operations - simplified (optional)
NTSTATUS SyscallLibrary::NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    return STATUS_NOT_IMPLEMENTED; // Optional - not critical
}

NTSTATUS SyscallLibrary::NtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    return STATUS_NOT_IMPLEMENTED; // Optional
}

NTSTATUS SyscallLibrary::NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    return STATUS_NOT_IMPLEMENTED; // Optional
}

NTSTATUS SyscallLibrary::NtClose(
    HANDLE Handle
) {
    typedef NTSTATUS(NTAPI* Func)(HANDLE);
    auto syscall = CreateSyscallStub<Func>(m_NtClose.ssn);
    return syscall(Handle);
}

// System operations
NTSTATUS SyscallLibrary::NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    typedef NTSTATUS(NTAPI* Func)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    auto syscall = CreateSyscallStub<Func>(m_NtQuerySystemInformation.ssn);
    return syscall(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS SyscallLibrary::NtDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
) {
    typedef NTSTATUS(NTAPI* Func)(BOOLEAN, PLARGE_INTEGER);
    auto syscall = CreateSyscallStub<Func>(m_NtDelayExecution.ssn);
    return syscall(Alertable, DelayInterval);
}

