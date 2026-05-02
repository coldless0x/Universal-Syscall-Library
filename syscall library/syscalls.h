#pragma once
#include <Windows.h>
#include <winternl.h>

typedef CLIENT_ID* PCLIENT_ID;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0,
    MemoryWorkingSetInformation = 1,
    MemoryMappedFilenameInformation = 2,
    MemoryRegionInformation = 3,
    MemoryWorkingSetExInformation = 4,
    MemorySharedCommitInformation = 5,
    MemoryImageInformation = 6,
    MemoryRegionInformationEx = 7,
    MemoryPrivilegedBasicInformation = 8,
    MemoryEnclaveImageInformation = 9,
    MemoryBasicInformationCapped = 10
} MEMORY_INFORMATION_CLASS;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

// Syscall structure
typedef struct _SYSCALL_ENTRY {
    DWORD ssn;           // System Service Number
    PVOID address;       // Syscall instruction address
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// Syscall Library Class
class SyscallLibrary {
public:
    SyscallLibrary();
    ~SyscallLibrary();

    // Initialize library
    bool Initialize();

    // Memory operations
    NTSTATUS NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    NTSTATUS NtFreeVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );

    NTSTATUS NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    NTSTATUS NtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesRead
    );

    NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS NtQueryVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        MEMORY_INFORMATION_CLASS MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
    );

    // Process operations
    NTSTATUS NtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS NtTerminateProcess(
        HANDLE ProcessHandle,
        NTSTATUS ExitStatus
    );

    NTSTATUS NtSuspendProcess(
        HANDLE ProcessHandle
    );

    NTSTATUS NtResumeProcess(
        HANDLE ProcessHandle
    );

    NTSTATUS NtQueryInformationProcess(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    // Thread operations
    NTSTATUS NtCreateThreadEx(
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
    );

    NTSTATUS NtOpenThread(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS NtSuspendThread(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount
    );

    NTSTATUS NtResumeThread(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount
    );

    NTSTATUS NtTerminateThread(
        HANDLE ThreadHandle,
        NTSTATUS ExitStatus
    );

    NTSTATUS NtGetContextThread(
        HANDLE ThreadHandle,
        PCONTEXT ThreadContext
    );

    NTSTATUS NtSetContextThread(
        HANDLE ThreadHandle,
        PCONTEXT ThreadContext
    );

    NTSTATUS NtQueryInformationThread(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );

    // File operations
    NTSTATUS NtCreateFile(
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
    );

    NTSTATUS NtReadFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID Buffer,
        ULONG Length,
        PLARGE_INTEGER ByteOffset,
        PULONG Key
    );

    NTSTATUS NtWriteFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID Buffer,
        ULONG Length,
        PLARGE_INTEGER ByteOffset,
        PULONG Key
    );

    NTSTATUS NtClose(
        HANDLE Handle
    );

    // System operations
    NTSTATUS NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    NTSTATUS NtDelayExecution(
        BOOLEAN Alertable,
        PLARGE_INTEGER DelayInterval
    );

    // Utility
    bool IsInitialized() const { return m_initialized; }
    DWORD GetSyscallNumber(const char* functionName);

private:
    bool m_initialized;
    HMODULE m_ntdll;

    // Syscall entries
    SYSCALL_ENTRY m_NtAllocateVirtualMemory;
    SYSCALL_ENTRY m_NtFreeVirtualMemory;
    SYSCALL_ENTRY m_NtProtectVirtualMemory;
    SYSCALL_ENTRY m_NtReadVirtualMemory;
    SYSCALL_ENTRY m_NtWriteVirtualMemory;
    SYSCALL_ENTRY m_NtQueryVirtualMemory;
    SYSCALL_ENTRY m_NtOpenProcess;
    SYSCALL_ENTRY m_NtTerminateProcess;
    SYSCALL_ENTRY m_NtSuspendProcess;
    SYSCALL_ENTRY m_NtResumeProcess;
    SYSCALL_ENTRY m_NtQueryInformationProcess;
    SYSCALL_ENTRY m_NtCreateThreadEx;
    SYSCALL_ENTRY m_NtOpenThread;
    SYSCALL_ENTRY m_NtSuspendThread;
    SYSCALL_ENTRY m_NtResumeThread;
    SYSCALL_ENTRY m_NtTerminateThread;
    SYSCALL_ENTRY m_NtGetContextThread;
    SYSCALL_ENTRY m_NtSetContextThread;
    SYSCALL_ENTRY m_NtQueryInformationThread;
    SYSCALL_ENTRY m_NtCreateFile;
    SYSCALL_ENTRY m_NtReadFile;
    SYSCALL_ENTRY m_NtWriteFile;
    SYSCALL_ENTRY m_NtClose;
    SYSCALL_ENTRY m_NtQuerySystemInformation;
    SYSCALL_ENTRY m_NtDelayExecution;

    // Helper functions
    bool ResolveSyscall(const char* functionName, PSYSCALL_ENTRY entry);
    DWORD ExtractSyscallNumber(PVOID functionAddress);
    PVOID FindSyscallInstruction(PVOID functionAddress);
};

// Global instance
extern SyscallLibrary* g_Syscalls;
