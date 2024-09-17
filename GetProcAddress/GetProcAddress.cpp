#include <windows.h>
#include <stdio.h>
#include <string.h>

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

// typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
// typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtOpenProcessTokenFn)(HANDLE, DWORD, PHANDLE);
typedef NTSTATUS(WINAPI* NtAdjustPrivilegesTokenFn)(HANDLE, BOOL, PTOKEN_PRIVILEGES_STRUCT, DWORD, PVOID, PVOID);
typedef NTSTATUS(WINAPI* NtGetNextProcessFn)(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(HANDLE, PVOID, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtCloseFn)(HANDLE);

NtOpenProcessTokenFn NtOpenProcessToken;
NtAdjustPrivilegesTokenFn NtAdjustPrivilegesToken;
NtGetNextProcessFn NtGetNextProcess;
NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
NtQueryVirtualMemory_t NtQueryVirtualMemory;
NtCloseFn NtClose;


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


HANDLE GetModuleAddress(const char* dll_name) {
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
}


int main(int argc, char* argv[]) {
    initializeFunctions();
    HANDLE hNtdll = GetModuleAddress("ntdll.dll");
    void* func_address = CustomGetProcAddress(hNtdll, "NtClose");
    printf("[+] hNtdll: \t\t\t\t\t0x%p\n", hNtdll);
    printf("[+] RESULT: \t\t\t\t\t0x%p\n", func_address);
    
    // hNtdll = (HMODULE)GetModuleAddress("ntdll.dll");
    // printf("[+] hNtdll: \t\t\t\t\t0x%p\n", hNtdll);
    

    return 0;
}
