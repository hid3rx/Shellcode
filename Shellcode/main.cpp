#include <Windows.h>
#include <winternl.h>

/*
* 函数哈希
*/

#define HASH_LoadLibraryA 0x071d2c76
#define HASH_GetProcAddress 0xc2cbc15a

/*
* 内联函数
*/

__forceinline PPEB GetCurrentPeb() {

#ifdef _WIN64 // x64
    PTEB Teb = (PTEB)__readgsqword(offsetof(NT_TIB, Self));
#else // x86
    PTEB Teb = (PTEB)__readfsdword(offsetof(NT_TIB, Self));
#endif
    return Teb->ProcessEnvironmentBlock;
}

__forceinline HMODULE GetKernel32Base() {

    PPEB Peb = GetCurrentPeb();
    PLIST_ENTRY ListHead = Peb->Ldr->InMemoryOrderModuleList.Flink;
    PLIST_ENTRY CurrEntry = ListHead;

    do {
        PLDR_DATA_TABLE_ENTRY Ldr = CONTAINING_RECORD(CurrEntry->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if ((Ldr->FullDllName.Buffer[20] == L'k' || Ldr->FullDllName.Buffer[20] == L'K') &&
            (Ldr->FullDllName.Buffer[21] == L'e' || Ldr->FullDllName.Buffer[21] == L'E') &&
            (Ldr->FullDllName.Buffer[22] == L'r' || Ldr->FullDllName.Buffer[22] == L'R') &&
            (Ldr->FullDllName.Buffer[23] == L'n' || Ldr->FullDllName.Buffer[23] == L'N') &&
            (Ldr->FullDllName.Buffer[24] == L'e' || Ldr->FullDllName.Buffer[24] == L'E') &&
            (Ldr->FullDllName.Buffer[25] == L'l' || Ldr->FullDllName.Buffer[25] == L'L') &&
            (Ldr->FullDllName.Buffer[26] == L'3') && (Ldr->FullDllName.Buffer[27] == L'2'))
            return (HMODULE)Ldr->DllBase;

        CurrEntry = CurrEntry->Flink;

    } while (CurrEntry != ListHead);

    return NULL;
}

__forceinline DWORD HashKey(CHAR* key) {

    DWORD Hash = 0;
    while (*key) {
        Hash = (Hash << 5) + Hash + *key++;
    }
    return Hash;
}

/*
* 函数声明
*/

VOID Shellcode();
PVOID GetProcAddrByHash(HMODULE Module, DWORD Hash);

/*
* Shellcode 实现
*/

#pragma code_seg(push, ".text$00")
VOID Shellcode() {

    //
    // 函数声明
    //
    typedef HMODULE(WINAPI* pfnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
    typedef FARPROC(WINAPI* pfnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
    typedef VOID(WINAPI* pfnExitThread)(_In_ DWORD dwExitCode);

    typedef int (WINAPI* pfnMessageBoxA)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCSTR lpText,
        _In_opt_ LPCSTR lpCaption,
        _In_ UINT uType);

    //
    // 变量声明
    //
    HMODULE Kernel32;
    pfnLoadLibraryA LoadLibraryA;
    pfnGetProcAddress GetProcAddress;

    //
    // 主体
    //
    Kernel32 = GetKernel32Base();

    LoadLibraryA = (pfnLoadLibraryA)GetProcAddrByHash(Kernel32, HASH_LoadLibraryA);
    GetProcAddress = (pfnGetProcAddress)GetProcAddrByHash(Kernel32, HASH_GetProcAddress);

    // 获取 ExitThread 函数
    pfnExitThread ExitThread = (pfnExitThread)GetProcAddress(Kernel32, "ExitThread");

    // 载入 User32.dll 模块
    HMODULE User32 = LoadLibraryA("User32.dll");
    if (User32 == NULL) {
        ExitThread(0);
        return;
    }

    // 获取 MessageBoxA 函数
    pfnMessageBoxA MessageBoxA = (pfnMessageBoxA)GetProcAddress(User32, "MessageBoxA");
    if (MessageBoxA == NULL) {
        ExitThread(0);
        return;
    }

    // 弹框
    MessageBoxA(NULL, "Hello", "Message", MB_OK);

    // 退出线程
    ExitThread(0);
}
#pragma code_seg(pop)

#pragma code_seg(push, ".text$01")
PVOID GetProcAddrByHash(HMODULE Module, DWORD Hash) {

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
#pragma code_seg(pop)
