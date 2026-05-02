# Syscall Library

Biblioteca C++ para Windows x64 que invoca rotinas `Nt*` do kernel através da instrução `syscall`, sem passar pelos exportados habituais de `ntdll.dll` no caminho de execução normal. O objetivo é trabalhar com **números de serviço (SSN)** e **disciplina de chamada** alinhados ao que o sistema espera, útil em pesquisa de baixo nível, instrumentação e cenários onde hooks em usermode são relevantes.

Isto não é um produto de segurança nem uma garantia de evasão; comportamento concreto depende da versão do Windows, patch level e de políticas do ambiente.

## O que a biblioteca faz

1. **Carrega metadados a partir do `ntdll` real**  
   Para cada função suportada, obtém o endereço via `GetProcAddress`, extrai o SSN a partir do prólogo (padrões `mov r10, rcx; mov eax, imm32` ou variantes próximas) e localiza a sequência `syscall` (`0F 05`) nos primeiros bytes da rotina.

2. **Executa a chamada como syscall direto**  
   Gera um stub mínimo em memória executável: copia o argumento de syscall para `eax`, mantém a convenção x64 da kernel (`r10` ← primeiro argumento user), emite `syscall` e `ret`. Cada wrapper público da classe instancia esse caminho com o SSN já resolvido na inicialização.

3. **Separa resolução “obrigatória” e “opcional”**  
   `Initialize()` falha se qualquer rotina considerada crítica não puder ser resolvida (memória, processo base, thread base, `NtClose`). Outras entradas podem falhar silenciosamente e ficar indisponíveis em runtime.

## Requisitos

- Windows 10/11 ou Windows Server equivalente, **apenas x64**.
- Visual Studio 2019 ou superior com workload **Desktop development with C++**.
- **MASM** habilitado (o projeto importa `masm.props` / `masm.targets`).

O ficheiro de projeto referencia toolset **v143** (VS 2022). Se usares outra versão, ajusta `PlatformToolset` em `syscall library/syscall-library.vcxproj`.

## Estrutura do repositório

| Caminho | Descrição |
|--------|-----------|
| `syscall library/syscalls.h` | Declarações da classe `SyscallLibrary`, tipos auxiliares e instância global `g_Syscalls`. |
| `syscall library/syscalls.cpp` | Resolução de SSN, stubs e implementação dos wrappers `Nt*`. |
| `syscall library/syscall_stub.asm` | Stub MASM alternativo (`SyscallStub` / `SysCall`); o fluxo principal em C++ usa stub gerado em memória. |
| `syscall library/main.cpp` | Aplicação de consola interativa que exercita memória, processo, thread e listagem de SSN. |
| `examples/simple_test.cpp` | Teste mínimo: alocar, escrever, ler, libertar memória e consultar um SSN. |
| `examples/process_injector.cpp` | Exemplo avançado (injeção); código de referência, não incluído na build por defeito. |
| `examples/memory_scanner.cpp` | Exemplo complementar, também excluído da build por defeito. |

## Compilar e correr

1. Abre `syscall library/syscall-library.vcxproj` no Visual Studio.
2. Seleciona configuração **Release** ou **Debug** e plataforma **x64**.
3. Compila (F7). O destino de saída segue `OutDir` definido no `.vcxproj` (por defeito sob `$(SolutionDir)$(Platform)\$(Configuration)\...`).

Para integrar noutro projeto estático ou DLL, adiciona `syscalls.cpp`, `syscalls.h` e, se quiseres o stub ASM, `syscall_stub.asm` com as mesmas definições de MASM.

## Uso mínimo

```cpp
#include "syscalls.h"

int wmain() {
    g_Syscalls = new SyscallLibrary();
    if (!g_Syscalls->Initialize()) {
        return 1;
    }

    PVOID base = nullptr;
    SIZE_T size = 0x1000;
    NTSTATUS st = g_Syscalls->NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &base,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (NT_SUCCESS(st)) {
        // ...
    }

    delete g_Syscalls;
    return 0;
}
```

Consulta `syscalls.h` para a lista completa de métodos expostos. `GetSyscallNumber("NtReadVirtualMemory")` devolve o SSN atual para depuração ou ferramentas externas; `0xFFFFFFFF` indica falha ou prologue não reconhecível (por exemplo, hook agressivo no início da função).

## Limitações e detalhes de implementação

- **Arquitetura:** só x64; x86 e ARM64 não estão cobertos por este código.
- **Ficheiros:** `NtCreateFile`, `NtReadFile` e `NtWriteFile` estão declarados mas **devolvem `STATUS_NOT_IMPLEMENTED`** no `.cpp`; a resolução na `Initialize()` serve sobretudo para introspecção de SSN, não para I/O completo via estes wrappers.
- **Variação entre builds do Windows:** SSN mudam entre versões; a abordagem dinâmica a partir do `ntdll` carregado evita hardcode, mas assume que o prologue continua analisável. Atualizações do sistema ou software que altere o início das exportações podem exigir ajuste dos parsers em `ExtractSyscallNumber` / `FindSyscallInstruction`.
- **Stub partilhado:** `CreateSyscallStub` usa um buffer estático único por instanciação de template; para código **multithread** que invoque vários `Nt*` em paralelo, o desenho atual pode precisar de stubs por thread ou por chamada — avalia o teu cenário antes de produção.

## Aviso legal e ética

Funcionalidades de baixo nível sobre processos e memória são frequentemente usadas em malware. Usa este código apenas em sistemas que possuis, com autorização explícita, ou em ambientes isolados de laboratório. O autor e os contribuidores não se responsabilizam por uso indevido.

## Licença

Se existir um ficheiro `LICENSE` na raiz do projeto, prevalece o texto desse ficheiro. Caso contrário, assume-se que os termos serão definidos pelo detentor do repositório.
