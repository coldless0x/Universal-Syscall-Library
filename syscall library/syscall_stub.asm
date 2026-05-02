; syscall_stub.asm - x64 direct syscall stub (MASM)
; C: extern "C" NTSTATUS SysCall(DWORD ssn, ...);
; RCX = ssn, RDX/R8/R9 + stack = Nt* arguments

_TEXT SEGMENT

PUBLIC SyscallStub

SyscallStub PROC
    mov r10, rdx
    mov eax, ecx
    syscall
    ret
SyscallStub ENDP

; "SysCall" is a MASM reserved word; C++ links to this alias.
ALIAS <SysCall> = <SyscallStub>

_TEXT ENDS

END
