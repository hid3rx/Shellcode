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
* Shellcode����ע�����
*
* 1. ���ɵ�OBJ�ļ���Ӧ����Ƿ����MOVAPS��MOVDQA���ڴ�����ָ�����ָ��ͨ������SSEָ����֣����ڴ治����������ִ�д���ָ��һ��������쳣
* 2. ���ɵ�OBJ�ļ���Ӧ�����ں�����ͷ�Ƿ��� MOV [RSP+8], RBX ����ָ�����ָ���֡ջ�ڵ����ݽ��в��������ܻᵼ��Shellcode��ͷ�����ֽڱ��޸�
* 3. ���ɵ�Shellcode��ͷһ������ַ������ݣ�������Shellcode��ͷ��� JMP $+0x30 ָ��ʵ��ֱ����ת
*
*/


/*
* ��������
*/

PPEB GetCurrentPeb();
HMODULE GetKernel32Base();
DWORD HashKey(CHAR* key);
VOID Shellcode();
PVOID GetProcAddrByHash(HMODULE Module, DWORD Hash);

/*
* ������ϣ
*/

#define HASH_LoadLibraryA 0x071d2c76
#define HASH_MessageBoxA 0x4ce54ccf

/*
* Shellcode ʵ��
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

    // ��ȡ Kernel32.dll ģ��
    HMODULE Kernel32 = GetKernel32Base();

    // ��ȡ Kernel32.dll ����
    pfnLoadLibraryA LoadLibraryA = (pfnLoadLibraryA)GetProcAddrByHash(Kernel32, HASH_LoadLibraryA);

    // ���� User32.dll ģ��
    HMODULE User32 = LoadLibraryA("User32.dll");

    // ��ȡ User32.dll ����
    pfnMessageBoxA MessageBoxA = (pfnMessageBoxA)GetProcAddrByHash(User32, HASH_MessageBoxA);

    // ����
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
* ��������
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
* ����Shellcode
*/

int main() {
    Shellcode();
    return 0;
}
