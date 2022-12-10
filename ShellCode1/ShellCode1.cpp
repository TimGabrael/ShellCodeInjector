#include <intrin.h>

typedef unsigned short USHORT;
typedef _Null_terminated_ wchar_t* NWPSTR, * LPWSTR, * PWSTR;
typedef void* PVOID;
typedef void* LPVOID;
typedef char BYTE;
typedef unsigned long ULONG;

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




extern "C" PVOID _code()
{
    return GetModuleBaseAddress(L"KernelBase.dll");
    //return x * y + (x + y);
}