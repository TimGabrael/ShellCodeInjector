#include <iostream>
#include <Windows.h>
#include <fstream>
#include <sstream>
#include <tlhelp32.h>

#define F_REG_DEF(reg) float reg##_0; float reg##_1; float reg##_2; float reg##_3
struct FLOAT_REGISTERS
{
	F_REG_DEF(xmm0);
	F_REG_DEF(xmm1);
	F_REG_DEF(xmm2);
	F_REG_DEF(xmm3);
	F_REG_DEF(xmm4);
	F_REG_DEF(xmm5);
	F_REG_DEF(xmm6);
	F_REG_DEF(xmm7);
	F_REG_DEF(xmm8);
	F_REG_DEF(xmm9);
	F_REG_DEF(xmm10);
	F_REG_DEF(xmm11);
	F_REG_DEF(xmm12);
	F_REG_DEF(xmm13);
	F_REG_DEF(xmm14);
	F_REG_DEF(xmm15);
};
struct CPU_STATE
{
	void* rax;
	void* rbx;
	void* rcx;
	void* rdx;
	void* rsi;
	void* rdi;
	void* rbp;
	void* rsp;
	void* r8;
	void* r9;
	void* r10;
	void* r11;
	void* r12;
	void* r13;
	void* r14;
	void* r15;
	FLOAT_REGISTERS f_regs;
	void* flags;
};

// GetModuleHandle(L"KERNELBASE.dll");
unsigned char _code_raw[] = {
	 0x4B, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x6C, 0x00,
	 0x42, 0x00, 0x61, 0x00, 0x73, 0x00, 0x65, 0x00, 0x2E, 0x00, 0x64, 0x00,
	 0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0xEF, 0xAA, 0x94, 0x63, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00,
	 0xA0, 0x00, 0x00, 0x00, 0x68, 0x10, 0x00, 0x00, 0x68, 0x04, 0x00, 0x00,
	 0x18, 0x00, 0x00, 0x00, 0x02, 0x80, 0x02, 0x80, 0x54, 0x10, 0x00, 0x00,
	 0x04, 0x00, 0x00, 0x00, 0x58, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
	 0x1B, 0x11, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
	 0x10, 0x11, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x10, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x2E, 0x72, 0x64, 0x61,
	 0x74, 0x61, 0x00, 0x00, 0x3C, 0x10, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00,
	 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x24, 0x76, 0x6F, 0x6C, 0x74, 0x6D,
	 0x64, 0x00, 0x00, 0x00, 0x68, 0x10, 0x00, 0x00, 0xA8, 0x00, 0x00, 0x00,
	 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x24, 0x7A, 0x7A, 0x7A, 0x64, 0x62,
	 0x67, 0x00, 0x00, 0x00, 0x10, 0x11, 0x00, 0x00, 0xD4, 0x00, 0x00, 0x00,
	 0x2E, 0x74, 0x65, 0x78, 0x74, 0x24, 0x6D, 0x6E, 0x00, 0x00, 0x00, 0x00,
	 0xE4, 0x11, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x2E, 0x78, 0x64, 0x61,
	 0x74, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00,
	 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
	 0x60, 0x00, 0x00, 0x00, 0x2E, 0x72, 0x73, 0x72, 0x63, 0x24, 0x30, 0x31,
	 0x00, 0x00, 0x00, 0x00, 0x60, 0x30, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00,
	 0x2E, 0x72, 0x73, 0x72, 0x63, 0x24, 0x30, 0x32, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x6C, 0x24,
	 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x65, 0x48, 0x8B, 0x04, 0x25,
	 0x60, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x2D, 0xD5, 0xFE, 0xFF, 0xFF, 0x40,
	 0xB7, 0x01, 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x8B, 0x48, 0x18, 0x4C,
	 0x8B, 0x59, 0x28, 0x49, 0x8B, 0xF3, 0x66, 0x90, 0x4C, 0x3B, 0xDE, 0x75,
	 0x05, 0x40, 0x84, 0xFF, 0x74, 0x70, 0x40, 0x32, 0xFF, 0x49, 0x8D, 0x43,
	 0x20, 0x48, 0x85, 0xC0, 0x74, 0x5E, 0x48, 0x8B, 0x18, 0x48, 0x85, 0xDB,
	 0x74, 0x56, 0x49, 0x8B, 0x43, 0x50, 0x48, 0x85, 0xC0, 0x74, 0x4D, 0x48,
	 0x3B, 0xC5, 0x74, 0x61, 0x4C, 0x8B, 0xCD, 0x90, 0x44, 0x0F, 0xB7, 0x00,
	 0x45, 0x0F, 0xB7, 0x11, 0x66, 0x45, 0x3B, 0xC2, 0x74, 0x26, 0x41, 0x8D,
	 0x50, 0xBF, 0x41, 0x8D, 0x48, 0xE0, 0x66, 0x41, 0x83, 0xC0, 0x20, 0x66,
	 0x83, 0xFA, 0x1F, 0x66, 0x44, 0x0F, 0x47, 0xC1, 0x66, 0x45, 0x3B, 0xC2,
	 0x75, 0x1A, 0x48, 0x83, 0xC0, 0x02, 0x49, 0x83, 0xC1, 0x02, 0xEB, 0xCC,
	 0x66, 0x45, 0x85, 0xC0, 0x74, 0x23, 0x48, 0x83, 0xC0, 0x02, 0x49, 0x83,
	 0xC1, 0x02, 0xEB, 0xBC, 0x4D, 0x8B, 0x5B, 0x08, 0xEB, 0x86, 0x33, 0xC0,
	 0x48, 0x8B, 0x5C, 0x24, 0x10, 0x48, 0x8B, 0x6C, 0x24, 0x18, 0x48, 0x8B,
	 0x74, 0x24, 0x20, 0x5F, 0xC3, 0x48, 0x8B, 0x6C, 0x24, 0x18, 0x48, 0x8B,
	 0xC3, 0x48, 0x8B, 0x5C, 0x24, 0x10, 0x48, 0x8B, 0x74, 0x24, 0x20, 0x5F,
	 0xC3, 0xCC, 0xCC, 0xCC, 0x01, 0x23, 0x07, 0x00, 0x23, 0x34, 0x02, 0x00,
	 0x0B, 0x64, 0x04, 0x00, 0x0B, 0x54, 0x03, 0x00, 0x0B, 0x70, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x00, 0x00,
	 0xE1, 0x11, 0x00, 0x00, 0xE4, 0x11,
};
typedef CPU_STATE* (_stdcall*PFUNC)(CPU_STATE* state);

PFUNC MapFunction(const char* fileName, const char* functionName)
{
	std::string dllFile = std::string(fileName) + ".dll";
	std::string mapFile = std::string(fileName) + ".map";
	FILE* f = NULL;
	errno_t err = fopen_s(&f, dllFile.c_str(), "rb");
	if (!f || err) return nullptr;

	IMAGE_DOS_HEADER dosHeader = { 0 };
	fread(&dosHeader, sizeof(dosHeader), 1, f);
	fseek(f, dosHeader.e_lfanew, SEEK_SET);
	
	IMAGE_NT_HEADERS ntHeader = { 0 };
	fread(&ntHeader, sizeof(ntHeader), 1, f);

	IMAGE_SECTION_HEADER secHeader = { 0 };

	for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++)
	{
		fread(&secHeader, sizeof secHeader, 1, f);
		if (strncmp((const char*)secHeader.Name, ".text", 8) == 0)
		{
			uint8_t* raw_data = new uint8_t[secHeader.SizeOfRawData];
			fseek(f, secHeader.PointerToRawData, SEEK_SET);
			fread(raw_data, secHeader.SizeOfRawData, 1, f);
			fclose(f);

			DWORD old_flag;
			VirtualProtect(raw_data, secHeader.SizeOfRawData, PAGE_EXECUTE_READWRITE, &old_flag);

			std::ifstream stream(mapFile.c_str());
			if (!stream.is_open()) return nullptr;

			std::string prevElement;
			std::string element;
			uintptr_t base = 0x0;
			uintptr_t code_start = 0;
			while (stream >> element)
			{
				if (!base)
				{
					if (element == "Start")
					{
						std::stringstream ss;
						ss << prevElement;
						ss >> std::hex >> base;
					}
				}
				else if (!code_start)
				{
					if (prevElement == functionName)
					{
						std::stringstream ss;
						ss << element;
						ss >> std::hex >> code_start;
					}
				}
				else break;
				prevElement = element;
			}

			uintptr_t start = code_start - base - 0x1000;
			return (PFUNC)(raw_data + start);
		}
	}

	fclose(f);

	return nullptr;
}


static constexpr size_t functionIdx = 250;
static constexpr uint8_t safe_cpu_state_on_stack[] = {
	0x50,											//					,push rax
	0x48, 0x89, 0xE0,								//					,mov rax,rsp
	0x48, 0x81, 0xEC, 0x90, 0x01, 0x00, 0x00,		//					,sub rsp,0x190
	0x83, 0xE4, 0xF7,								//					,and esp,~8
	0x48, 0x89, 0x5C, 0x24, 0x08,					//					,mov [rsp+0x8],rbx
	0x48, 0x8B, 0x18,								//					,mov rbx,[rax]
	0x48, 0x89, 0x1C, 0x24,							//					,mov [rsp],rbx
	0x48, 0x83, 0xC0, 0x04,							//					,add rax,4
	0x48, 0x89, 0x44, 0x24, 0x38,					//					,mov [rsp+0x38],rax
	0x48, 0x89, 0xE0,								//					,mov rax,rsp
	0x48, 0x89, 0x48, 0x10,							//					,mov [rax+0x10],rcx
	0x48, 0x89, 0x50, 0x18,							//					,mov [rax+0x18],rdx
	0x48, 0x89, 0x70, 0x20,							//					,mov [rax+0x20],rsi
	0x48, 0x89, 0x78, 0x28,							//					,mov [rax+0x28],rdi
	0x48, 0x89, 0x68, 0x30,							//					,mov [rax+0x30],rbp
	0x4C, 0x89, 0x40, 0x40,							//					,mov [rax+0x40],r8
	0x4C, 0x89, 0x48, 0x48,							//					,mov [rax+0x48],r9
	0x4C, 0x89, 0x50, 0x50,							//					,mov [rax+0x50],r10
	0x4C, 0x89, 0x58, 0x58,							//					,mov [rax+0x58],r11
	0x4C, 0x89, 0x60, 0x60,							//					,mov [rax+0x60],r12
	0x4C, 0x89, 0x68, 0x68,							//					,mov [rax+0x68],r13
	0x4C, 0x89, 0x70, 0x70,							//					,mov [rax+0x70],r14
	0x4C, 0x89, 0x78, 0x78,							//					,mov [rax+0x78],r15
	0xF3,0x0F,0x7F,0x80,0x80,0x0,0x0,0x0,			//					,movdqu [rax+0x80],xmm0
	0xF3,0x0F,0x7F,0x88,0x90,0x0,0x0,0x0,			//					,movdqu [rax+0x90],xmm1
	0xF3,0x0F,0x7F,0x90,0xA0,0x0,0x0,0x0,			//					,movdqu [rax+0xA0],xmm2
	0xF3,0x0F,0x7F,0x98,0xB0,0x0,0x0,0x0,			//					,movdqu [rax+0xB0],xmm3
	0xF3,0x0F,0x7F,0xA0,0xC0,0x0,0x0,0x0,			//					,movdqu [rax+0xC0],xmm4
	0xF3,0x0F,0x7F,0xA8,0xD0,0x0,0x0,0x0,			//					,movdqu [rax+0xD0],xmm5
	0xF3,0x0F,0x7F,0xB0,0xE0,0x0,0x0,0x0,			//					,movdqu [rax+0xE0],xmm6
	0xF3,0x0F,0x7F,0xB8,0xF0,0x0,0x0,0x0,			//					,movdqu [rax+0xF0],xmm7
	0xF3,0x44,0x0F,0x7F,0x80,0x0,0x1,0x0,0x0,		//					,movdqu [rax+0x100],xmm8
	0xF3,0x44,0x0F,0x7F,0x88,0x10,0x1,0x0,0x0,		//					,movdqu [rax+0x110],xmm9
	0xF3,0x44,0x0F,0x7F,0x90,0x20,0x1,0x0,0x0,		//					,movdqu [rax+0x120],xmm10
	0xF3,0x44,0x0F,0x7F,0x98,0x30,0x1,0x0,0x0,		//					,movdqu [rax+0x130],xmm11
	0xF3,0x44,0x0F,0x7F,0xA0,0x40,0x1,0x0,0x0,		//					,movdqu [rax+0x140],xmm12
	0xF3,0x44,0x0F,0x7F,0xA8,0x50,0x1,0x0,0x0,		//					,movdqu [rax+0x150],xmm13
	0xF3,0x44,0x0F,0x7F,0xB0,0x60,0x1,0x0,0x0,		//					,movdqu [rax+0x160],xmm14
	0xF3,0x44,0x0F,0x7F,0xB8,0x70,0x1,0x0,0x0,		//					,movdqu [rax+0x170],xmm15
	0x9C,											//					,pushf
	0x59,											//					,pop rcx
	0x48, 0x89, 0x88, 0x80, 0x01, 0x00, 0x00,		//					,mov [rax+0x180],rcx
	0x48, 0x83, 0xEC, 0x20,							//					,sub rsp,0x20
	0x48, 0x89, 0xC1,								//					,mov rcx,rax

	0xFF, 0x15, 0x02, 0, 0, 0, 0xEB, 0x08, 0,0,0,0,0,0,0,0,	//					,call null

	0x48,0x8B,0x58,0x08,							//					,mov rbx,[rax+8]
	0x48,0x8B,0x48,0x10,							//					,mov rcx,[rax+0x10]
	0x48,0x8B,0x50,0x18,							//					,mov rdx,[rax+0x18]
	0x48,0x8B,0x70,0x20,							//					,mov rsi,[rax+0x20]
	0x48,0x8B,0x78,0x28,							//					,mov rdi,[rax+0x28]
	0x48,0x8B,0x68,0x30,							//					,mov rbp,[rax+0x30]
	0x48,0x8B,0x60,0x38,							//					,mov rsp,[rax+0x38]
	0x4C,0x8B,0x40,0x40,							//					,mov r8,[rax+0x40]
	0x4C,0x8B,0x48,0x48,							//					,mov r9,[rax+0x48]
	0x4C,0x8B,0x50,0x50,							//					,mov r10,[rax+0x50]
	0x4C,0x8B,0x58,0x58,							//					,mov r11,[rax+0x58]
	0x4C,0x8B,0x60,0x60,							//					,mov r12,[rax+0x60]
	0x4C,0x8B,0x68,0x68,							//					,mov r13,[rax+0x68]
	0x4C,0x8B,0x70,0x70,							//					,mov r14,[rax+0x70]
	0x4C,0x8B,0x78,0x78,							//					,mov r15,[rax+0x78]
	0xF3,0x0F,0x6F,0x80,0x80,0x00,0x00,0x00,		//					,movdqu xmm0,[rax+0x80]
	0xF3,0x0F,0x6F,0x88,0x90,0x00,0x00,0x00,		//					,movdqu xmm1,[rax+0x90]
	0xF3,0x0F,0x6F,0x90,0xA0,0x00,0x00,0x00,		//					,movdqu xmm2,[rax+0xA0]
	0xF3,0x0F,0x6F,0x98,0xB0,0x00,0x00,0x00,		//					,movdqu xmm3,[rax+0xB0]
	0xF3,0x0F,0x6F,0xA0,0xC0,0x00,0x00,0x00,		//					,movdqu xmm4,[rax+0xC0]
	0xF3,0x0F,0x6F,0xA8,0xD0,0x00,0x00,0x00,		//					,movdqu xmm5,[rax+0xD0]
	0xF3,0x0F,0x6F,0xB0,0xE0,0x00,0x00,0x00,		//					,movdqu xmm6,[rax+0xE0]
	0xF3,0x0F,0x6F,0xB8,0xF0,0x00,0x00,0x00,		//					,movdqu xmm7,[rax+0xF0]
	0xF3,0x44,0x0F,0x6F,0x80,0x00,0x01,0x00,0x00,	//					,movdqu xmm8,[rax+0x100]
	0xF3,0x44,0x0F,0x6F,0x88,0x10,0x01,0x00,0x00,	//					,movdqu xmm9,[rax+0x110]
	0xF3,0x44,0x0F,0x6F,0x90,0x20,0x01,0x00,0x00,	//					,movdqu xmm10,[rax+0x120]
	0xF3,0x44,0x0F,0x6F,0x98,0x30,0x01,0x00,0x00,	//					,movdqu xmm11,[rax+0x130]
	0xF3,0x44,0x0F,0x6F,0xA0,0x40,0x01,0x00,0x00,	//					,movdqu xmm12,[rax+0x140]
	0xF3,0x44,0x0F,0x6F,0xA8,0x50,0x01,0x00,0x00,	//					,movdqu xmm13,[rax+0x150]
	0xF3,0x44,0x0F,0x6F,0xB0,0x60,0x01,0x00,0x00,	//					,movdqu xmm14,[rax+0x160]
	0xF3,0x44,0x0F,0x6F,0xB8,0x70,0x01,0x00,0x00,	//					,movdqu xmm15,[rax+0x170]
	0x51,											//					,push rcx
	0x48,0x8B,0x88,0x80,0x01,0x00,0x00,				//					,mov rcx, [rax+0x180]
	0x51,											//					,push rcx
	0x9D,											//					,popf
	0x59,											//					,pop rcx
	0x48,0x8B,0x00,									//					,mov rax,[rax]
};
//0x90, 0x90, 0x90, 0x90,							//					,nop
//0x90, 0x90, 0x90, 0x90,							//					,nop
//0x90, 0x90, 0x90, 0x90,							//					,nop
//0x90, 0x90, 0x90, 0x90,							//					,nop
//0x90, 0x90, 0x90, 0x90,							//					,nop
//0x90, 0x90, 0x90, 0x90,							//					,nop
//0xE9, 0x00, 0x00, 0x00, 0x00,						//					,jmp -> null

struct ShellCode
{
	uint8_t* data;
	uint32_t size;
	PFUNC function;
};
ShellCode GetShellCode(const char* fileName, const char* functionName)
{
	ShellCode output{0, 0, 0};

	std::string dllFile = std::string(fileName) + ".dll";
	std::string mapFile = std::string(fileName) + ".map";
	FILE* f = NULL;
	errno_t err = fopen_s(&f, dllFile.c_str(), "rb");
	if (!f || err) return output;

	IMAGE_DOS_HEADER dosHeader = { 0 };
	fread(&dosHeader, sizeof(dosHeader), 1, f);
	fseek(f, dosHeader.e_lfanew, SEEK_SET);

	IMAGE_NT_HEADERS ntHeader = { 0 };
	fread(&ntHeader, sizeof(ntHeader), 1, f);

	IMAGE_SECTION_HEADER secHeader = { 0 };

	for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++)
	{
		fread(&secHeader, sizeof secHeader, 1, f);
		if (strncmp((const char*)secHeader.Name, ".text", 8) == 0)
		{
			output.data = new uint8_t[secHeader.SizeOfRawData];
			output.size = secHeader.SizeOfRawData;

			fseek(f, secHeader.PointerToRawData, SEEK_SET);
			fread(output.data, secHeader.SizeOfRawData, 1, f);
			fclose(f);

			std::ifstream stream(mapFile.c_str());
			if (!stream.is_open()) return output;

			std::string prevElement;
			std::string element;
			uintptr_t base = 0x0;
			uintptr_t code_start = 0;
			while (stream >> element)
			{
				if (!base)
				{
					if (element == "Start")
					{
						std::stringstream ss;
						ss << prevElement;
						ss >> std::hex >> base;
					}
				}
				else if (!code_start)
				{
					if (prevElement == functionName)
					{
						std::stringstream ss;
						ss << element;
						ss >> std::hex >> code_start;
					}
				}
				else break;
				prevElement = element;
			}

			uintptr_t start = code_start - base - 0x1000;
			output.function = (PFUNC)(output.data + start);
			return output;
		}
	}

	fclose(f);

	return output;
}

void ShellCodeHook(uintptr_t hookAddr, const ShellCode& code, int overwrite)
{
	uintptr_t trampLoc = 0;
	uintptr_t cur = hookAddr + 0x1000;
	while (!trampLoc)
	{
		uintptr_t addr = cur;
		cur = (uintptr_t)VirtualAlloc((LPVOID)addr, code.size + sizeof(safe_cpu_state_on_stack) + overwrite + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (cur) trampLoc = cur;
		else cur = addr + 0x1000;
	}
	if (!trampLoc) return;
	
	int jmpBack = (hookAddr - cur - sizeof(safe_cpu_state_on_stack) - 5);
	int jmpTo = (cur - hookAddr - 5);

	memcpy((LPVOID)trampLoc, safe_cpu_state_on_stack, sizeof(safe_cpu_state_on_stack)); trampLoc += sizeof(safe_cpu_state_on_stack);
	memcpy((LPVOID)trampLoc, (LPVOID)hookAddr, overwrite); trampLoc += overwrite;

	uint8_t data[5] = {
		0xE9, 0,0,0,0
	};
	*(int*)&data[1] = jmpBack;
	
	memcpy((LPVOID)trampLoc, data, 5); trampLoc += 5;
	memcpy((LPVOID)trampLoc, code.data, code.size);

	PFUNC* out = (PFUNC*)(cur + functionIdx);
	*out = code.function;


	DWORD old;
	VirtualProtect((LPVOID)hookAddr, overwrite, PAGE_EXECUTE_READWRITE, &old);

	*(int*)&data[1] = jmpTo;
	memcpy((LPVOID)hookAddr, data, 5);

	VirtualProtect((LPVOID)hookAddr, overwrite, old, &old);
}

bool ShellCodeHookEx(HANDLE procHandle, uintptr_t hookAddr, const ShellCode& code, int overwrite)
{
	if (procHandle == 0) return false;

	uintptr_t trampLoc = 0;
	uintptr_t cur = hookAddr + 0x1000;
	while (!trampLoc)
	{
		uintptr_t addr = cur;
		cur = (uintptr_t)VirtualAllocEx(procHandle, (LPVOID)addr, code.size + sizeof(safe_cpu_state_on_stack) + overwrite + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (cur) trampLoc = cur;
		else cur = addr + 0x1000;
	}
	if (!trampLoc) return false;

	int jmpBack = (hookAddr - cur - sizeof(safe_cpu_state_on_stack) - 5);
	int jmpTo = (cur - hookAddr - 5);

	SIZE_T numWritten = 0;
	BOOL written = WriteProcessMemory(procHandle, (LPVOID)trampLoc, safe_cpu_state_on_stack, sizeof(safe_cpu_state_on_stack), &numWritten); trampLoc += sizeof(safe_cpu_state_on_stack);
	if (!written || numWritten != sizeof(safe_cpu_state_on_stack)) return false;

	written = WriteProcessMemory(procHandle, (LPVOID)trampLoc, (LPVOID)hookAddr, overwrite, &numWritten); trampLoc += overwrite;
	if (!written || numWritten != overwrite) return false;

	uint8_t data[5] = {
		0xE9, 0,0,0,0
	};
	*(int*)&data[1] = jmpBack;

	written = WriteProcessMemory(procHandle, (LPVOID)trampLoc, data, 5, &numWritten); trampLoc += 5;
	if (!written || numWritten != 5) return false;


	written = WriteProcessMemory(procHandle, (LPVOID)trampLoc, code.data, code.size, &numWritten); trampLoc += code.size;
	if (!written || numWritten != code.size) return false;

	const uintptr_t shellCodeStart = (uintptr_t)code.function - (uintptr_t)code.data + cur + sizeof(safe_cpu_state_on_stack) + 5 + overwrite;
	written = WriteProcessMemory(procHandle, (LPVOID)(cur + functionIdx), &shellCodeStart, sizeof(uintptr_t), &numWritten);
	if (!written || numWritten != sizeof(PFUNC)) return false;



	DWORD old;
	BOOL setProtection = VirtualProtectEx(procHandle, (LPVOID)hookAddr, overwrite, PAGE_EXECUTE_READWRITE, &old);
	if (!setProtection) return false;

	*(int*)&data[1] = jmpTo;
	written = WriteProcessMemory(procHandle, (LPVOID)hookAddr, data, 5, &numWritten);
	if (!written || numWritten != 5) return false;

	VirtualProtectEx(procHandle, (LPVOID)hookAddr, overwrite, old, &old);

	return true;
}


HANDLE GetProcess(const wchar_t* exeFileName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (wcsncmp(entry.szExeFile, exeFileName, 500) == 0)
			{
				return OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}

DWORD GetProcId(const wchar_t* procName) {
	DWORD procId = 0;
	HANDLE hSnap = (CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry)) {
			do {
				if (!_wcsicmp(procEntry.szExeFile, procName)) {
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName) {
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);

		if (Module32First(hSnap, &modEntry)) {
			do {
				if (!_wcsicmp(modEntry.szModule, modName)) {
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

int main()
{
	ShellCode res = GetShellCode("ShellCode1", "_code");
	
	if (res.data && res.function && res.size > 0)
	{
		uintptr_t moduleBase = GetModuleBaseAddress(GetProcId(L"process"), L"module");

		bool worked = ShellCodeHookEx(GetProcess(L"ExeFile"), (uintptr_t)GetShellCode, res, 10);
		if (!worked)
		{
			printf("DID NOT WORK\n");
		}
	}

	system("pause");
}
