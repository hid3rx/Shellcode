#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma section(".shc",read,execute)
#pragma comment(linker, "/section:.shc,RWE")

#pragma data_seg(".dat")
#pragma comment(linker, "/merge:.dat=.shc")

#pragma const_seg(".rdat")
#pragma comment(linker, "/merge:.rdat=.shc")


/*
* Shellcode生成注意事项：
*
* 1. 生成的OBJ文件后应检查是否存在MOVAPS、MOVDQA等内存对齐的指令，这种指令通常伴随SSE指令出现，在内存不对齐的情况下执行此类指令一定会出现异常
* 2. 生成的OBJ文件后应检查入口函数开头是否有 MOV [RSP+8], RBX 这种指令，这种指令会帧栈内的数据进行操作，可能会导致Shellcode的头几个字节被修改
* 3. 生成的Shellcode开头一般会是字符串数据，可以在Shellcode开头添加 JMP $+0x30 指令实现直接跳转
*
*/


/*
* 函数声明
*/

PPEB GetCurrentPeb();
HMODULE GetKernel32Base();
DWORD HashKey(CHAR* key);
VOID Shellcode();
PVOID GetProcAddrByHash(HMODULE Module, DWORD Hash);

/*
* 函数哈希
*/

#define HASH_LoadLibraryA 0x071d2c76
#define HASH_MessageBoxA 0x4ce54ccf

/*
* Shellcode 实现
*/

__declspec(code_seg(".shc")) __declspec(noalias) VOID Shellcode()
{
    // Kernel32.dll
    typedef HMODULE(WINAPI* pfnLoadLibraryA)(_In_ LPCSTR lpLibFileName);

    // User32.dll
    typedef int (WINAPI* pfnMessageBoxA)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCSTR lpText,
        _In_opt_ LPCSTR lpCaption,
        _In_ UINT uType);

    // 获取 Kernel32.dll 模块
    HMODULE Kernel32 = GetKernel32Base();

    // 获取 Kernel32.dll 函数
    pfnLoadLibraryA LoadLibraryA = (pfnLoadLibraryA)GetProcAddrByHash(Kernel32, HASH_LoadLibraryA);

    // 载入 User32.dll 模块
    HMODULE User32 = LoadLibraryA("User32.dll");

    // 获取 User32.dll 函数
    pfnMessageBoxA MessageBoxA = (pfnMessageBoxA)GetProcAddrByHash(User32, HASH_MessageBoxA);

    // 弹框
    MessageBoxA(NULL, "Hello", "Message", MB_OK);
}

__declspec(code_seg(".shc")) __declspec(noalias) PVOID GetProcAddrByHash(HMODULE Module, DWORD Hash)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)Module + DosHeader->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY Export = (PIMAGE_EXPORT_DIRECTORY)((UINT_PTR)Module + NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* AddressOfNames = (DWORD*)((UINT_PTR)Module + Export->AddressOfNames);
    DWORD* AddressOfFunctions = (DWORD*)((UINT_PTR)Module + Export->AddressOfFunctions);

    DWORD Ordinal;
    for (Ordinal = 0; Ordinal < Export->NumberOfNames; Ordinal++) {
        CHAR* Name = (CHAR*)((UINT_PTR)Module + AddressOfNames[Ordinal]);
        if (HashKey(Name) == Hash)
            break;
    }

    if (Ordinal != Export->NumberOfNames) {
        WORD Index = ((WORD*)((UINT_PTR)Module + Export->AddressOfNameOrdinals))[Ordinal];
        PVOID Function = (PVOID)((UINT_PTR)Module + AddressOfFunctions[Index]);
        return Function;
    }

    return NULL;
}

/*
* 内联函数
*/

__forceinline PPEB GetCurrentPeb()
{
#ifdef _WIN64 // x64
    PTEB Teb = (PTEB)__readgsqword(offsetof(NT_TIB, Self));
#else // x86
    PTEB Teb = (PTEB)__readfsdword(offsetof(NT_TIB, Self));
#endif
    return Teb->ProcessEnvironmentBlock;
}

__forceinline HMODULE GetKernel32Base()
{
    PPEB Peb = GetCurrentPeb();
    PLIST_ENTRY ListHead = Peb->Ldr->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY CurrEntry = ListHead;

    do {
        PLDR_DATA_TABLE_ENTRY Ldr = CONTAINING_RECORD(CurrEntry->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if ((Ldr->FullDllName.Buffer[20] == L'k' || Ldr->FullDllName.Buffer[20] == L'K') &&
            (Ldr->FullDllName.Buffer[26] == L'3') && (Ldr->FullDllName.Buffer[27] == L'2'))
            return (HMODULE)Ldr->DllBase;

        CurrEntry = CurrEntry->Flink;

    } while (CurrEntry != ListHead);

    return NULL;
}

__forceinline DWORD HashKey(CHAR* key)
{
    DWORD Hash = 0;
    while (*key) {
        Hash = (Hash << 5) + Hash + *key++;
    }
    return Hash;
}

/*
* 导出Shellcode
*/

int main() {
    Shellcode();
    return 0;
}
