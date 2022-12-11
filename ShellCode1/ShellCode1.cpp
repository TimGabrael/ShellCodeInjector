#include <intrin.h>

typedef unsigned short USHORT;
typedef _Null_terminated_ wchar_t* NWPSTR, * LPWSTR, * PWSTR;
typedef void* PVOID;
typedef void* LPVOID;
typedef char BYTE;
typedef unsigned long ULONG;
typedef unsigned short WORD;
typedef long LONG;
typedef unsigned long DWORD;
typedef unsigned long long ULONGLONG;
typedef DWORD* PDWORD;
typedef WORD* PWORD;

#pragma comment(linker, "/merge:.rdata=.text")


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
} PEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;







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







static bool IsSameCaseInsensitive(const wchar_t* c1, const wchar_t* c2)
{
    if ((c1 && !c2) || (!c1 && c2)) return false;
    if (c1 == c2) return true;

    bool isSame = true;
    int curIdx = 0;
    while (isSame)
    {
        if (c1[curIdx] != c2[curIdx])
        {
            wchar_t otherCase = c1[curIdx];
            if (otherCase < L'a' && L'A' <= otherCase)
            {
                otherCase = otherCase + (L'a' - L'A');
            }
            else
            {
                otherCase = otherCase - (L'a' - L'A');
            }
            if (otherCase != c2[curIdx])
            {
                isSame = false;
                break;
            }
        }
        else if (c1[curIdx] == L'\00')
        {
            break;
        }
        curIdx++;
    }
    return isSame;
}

static bool StringCompare(const char* c1, const char* c2, int max)
{
    if ((c1 && !c2) || (!c1 && c2)) return false;
    if (c1 == c2) return true;

    bool isSame = true;
    int curIdx = 0;
    while (curIdx < max)
    {
        if (c1[curIdx] != c2[curIdx])
        {
            if (c1[curIdx] == '\00' || c2[curIdx] == '\00') {
                return false;
            }
            wchar_t otherCase = c1[curIdx];
            if (otherCase < 'a' && 'A' <= otherCase)
            {
                otherCase = otherCase + ('a' - 'A');
            }
            else
            {
                otherCase = otherCase - ('a' - 'A');
            }
            if (otherCase != c2[curIdx])
            {
                isSame = false;
                break;
            }
        }
        else if (c1[curIdx] == '\00')
        {
            break;
        }
        curIdx++;
    }
    return isSame;
}


static PVOID GetModuleBaseAddress(const wchar_t* dll)
{
    _PEB* peb = (_PEB*)__readgsqword(0x60);
    LIST_ENTRY* entry = peb->LoaderData->InMemoryOrderModuleList.Blink;
    LIST_ENTRY* first = entry;
    bool once = true;
    while (entry != first || once)
    {
        once = false;
        _LDR_DATA_TABLE_ENTRY* e = (_LDR_DATA_TABLE_ENTRY*)entry;
        if (e->Reserved2 && *(LPVOID*)e->Reserved2)
        {
            LPVOID baseAddr = *(LPVOID*)e->Reserved2;
            if (e->FullDllName.Buffer)
            {
                if (IsSameCaseInsensitive(e->FullDllName.Buffer, dll))
                {
                    return baseAddr;
                }
            }
            else if (!dll) return baseAddr;
        }
        entry = entry->Blink;
    }
    return nullptr;
}


static PVOID GetProcAddress(const wchar_t* dll, const char* funcName)
{
    IMAGE_DOS_HEADER* image = (IMAGE_DOS_HEADER*)GetModuleBaseAddress(dll);
    if (!image) return nullptr;

    PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)((BYTE*)image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)image + header->OptionalHeader.DataDirectory[0].VirtualAddress);

    PDWORD names = (PDWORD)((BYTE*)image + exports->AddressOfNames);
    PWORD ordinals = (PWORD)((BYTE*)image + exports->AddressOfNameOrdinals);

    PDWORD funcs = (PDWORD)((BYTE*)image + exports->AddressOfFunctions);

    for (int i = 0; i < exports->NumberOfNames; i++)
    {
        char* fName = (char*)((BYTE*)image + names[i]);
        if (StringCompare(fName, funcName, 1000))
        {
            return (PVOID)((BYTE*)image + funcs[ordinals[i]]);
        }
    }

    return nullptr;
}

static PVOID GetProcFromIndex(const wchar_t* dll, int idx)
{
    IMAGE_DOS_HEADER* image = (IMAGE_DOS_HEADER*)GetModuleBaseAddress(dll);
    if (!image) return nullptr;
    
    PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)((BYTE*)image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)image + header->OptionalHeader.DataDirectory[0].VirtualAddress);

    PDWORD funcs = (PDWORD)((BYTE*)image + exports->AddressOfFunctions);

    if(idx < exports->NumberOfFunctions && idx >= 0) return (PVOID)((BYTE*)image + funcs[idx]);
    return nullptr;
}


#define PLAYER_POSITION 0x1DF62A0
#define PLAYER_CAMERA_YAW 0x1909764
#define PLAYER_CAMERA_PITCH 0x1909784
#define PLAYER_ACTIVE_WEAPON 0x67C7EE0

// USER32.dll
#define GET_ASYNC_KEYSTATE_OFFSET 0x23EA0
#define GET_DC_OFFSET 0x26170
#define GET_FOREGROUND_WINDOW_OFFSET 0x33F70
#define GET_WINDOW_RECT_OFFSET 0x146E0

// GDI32.dll
#define DRAW_TEXT_OFFSET 0xDB50

struct RECT
{
    int left, top, right, bottom;
};

typedef PVOID(*PFGetDC)(PVOID);
typedef PVOID(*PFGetForegroundWindow)();
typedef bool(*PFGetWindowRect)(PVOID hWnd, RECT* r);
//ExtTextOutA
typedef bool (*PFDrawText)(PVOID, int,int, unsigned int, const RECT*, const char*, unsigned int, const int*);

struct GlobalData
{
    PVOID mod;
    PVOID user32;
    PVOID gdi32;
    PVOID hdc;
    PFGetDC getDC;
    PFDrawText drawText;
    PFGetForegroundWindow getForegroundWindow;
    PFGetWindowRect getWindowRect;
};

#pragma section(".text")
__declspec(allocate(".text")) volatile GlobalData globals = { 0 };



extern "C" CPU_STATE* _code(CPU_STATE* state)
{
    if (!globals.mod)
    {
        globals.mod = GetModuleBaseAddress(L"sr_hv.exe");
        globals.user32 = GetModuleBaseAddress(L"user32.dll");
        globals.gdi32 = GetModuleBaseAddress(L"GDI32.dll");

        globals.getDC = (PFGetDC)((uintptr_t)globals.user32 + GET_DC_OFFSET);
        globals.getForegroundWindow = (PFGetForegroundWindow)((uintptr_t)globals.user32 + GET_FOREGROUND_WINDOW_OFFSET);
        globals.getWindowRect = (PFGetWindowRect)((uintptr_t)globals.user32 + GET_WINDOW_RECT_OFFSET);
        globals.drawText = (PFDrawText)((uintptr_t)globals.gdi32 + DRAW_TEXT_OFFSET);


        globals.hdc = globals.getDC(NULL);


    }

    globals.drawText(globals.getDC(globals.getForegroundWindow()), 100, 100, 0, nullptr, "THIS COULD BE ANYTHING", 23, nullptr);

    uintptr_t activeWeapon = *(uintptr_t*)((uintptr_t)globals.mod + PLAYER_ACTIVE_WEAPON);
    if (activeWeapon)
    {
        int* ammo = (int*)(activeWeapon + 0x1E4);
        *ammo = 99;
    }

    return state;
}