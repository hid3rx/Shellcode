#include <stdio.h>
#include <stddef.h>
#include <Windows.h>
#include <Winternl.h>

/*
* 引用的函数声明
*/

#define HASH_LoadLibraryA	0x071d2c76
#define HASH_MessageBoxA	0x4ce54ccf

// Kernel32.dll
typedef HMODULE(WINAPI* pfnLoadLibraryA)(_In_ LPCSTR lpLibFileName);

// User32.dll
typedef int (WINAPI* pfnMessageBoxA)(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType);

/*
* 获取Kernel32基址
*/

__forceinline HMODULE GetKernel32Base()
{
#ifdef _WIN64 // x64
    PTEB Teb = (PTEB)__readgsqword(offsetof(NT_TIB, Self));
#else // x86
    PTEB Teb = (PTEB)__readfsdword(offsetof(NT_TIB, Self));
#endif

    PPEB Peb = Teb->ProcessEnvironmentBlock;
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

/*
* Hash算法
*/

__forceinline DWORD HashKey(CHAR* key)
{
    DWORD Hash = 0;
    while (*key) {
        Hash = (Hash << 5) + Hash + *key++;
    }
    return Hash;
}

/*
* 通过Hash获取函数地址
*/

__forceinline PVOID GetProcAddrByHash(HMODULE Module, DWORD Hash)
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
* Shellcode 实现
*/

__attribute__((section(".shc"))) VOID Shellcode()
{
    __attribute__((section(".str"))) const static char dll[] = "User32.dll";
    __attribute__((section(".str"))) const static char title[] = "Hello";
    __attribute__((section(".str"))) const static char context[] = "Message";

    // 获取 Kernel32.dll 模块
    HMODULE Kernel32 = GetKernel32Base();

    // 获取 Kernel32.dll 函数
    pfnLoadLibraryA LoadLibraryA = (pfnLoadLibraryA)GetProcAddrByHash(Kernel32, HASH_LoadLibraryA);

    // 载入 User32.dll 模块
    HMODULE User32 = LoadLibraryA(dll);

    // 获取 User32.dll 函数
    pfnMessageBoxA MessageBoxA = (pfnMessageBoxA)GetProcAddrByHash(User32, HASH_MessageBoxA);

    // 弹框
    MessageBoxA(NULL, title, context, MB_OK);
}
