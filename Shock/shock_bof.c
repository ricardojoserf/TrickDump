#include <windows.h>
#include "beacon.h"

// Define the NTSTATUS function signatures
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAdjustPrivilegesToken(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int cchWideChar, LPSTR, int, LPCCH,LPBOOL);

const int zero_memory = 0x00000008;

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
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PBI Addr: 0x%p.\n", pbi_addr);
    
    ULONG returnLength = 0;

    NTSTATUS ntstatus = NTDLL$NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] NTSTATUS: %d\n", ntstatus);

    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    // TO ADD: KERNEL32$HeapFree(hHeap, 0, pbi_addr);
    PVOID pebaddress = *(PVOID*)peb_pointer;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PEB Address: 0x%p\n", pebaddress);

    // Get PEB->ProcessParameters
    PVOID processparameters_pointer = (PVOID)((BYTE*)pebaddress + processparameters_offset);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] processparameters_pointer: 0x%p\n", processparameters_pointer);

    PVOID processparameters_address = ReadRemoteIntPtr(process_handle, processparameters_pointer);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] processparameters_address: 0x%p\n", processparameters_address);
    

    PVOID commandline_pointer = (PVOID)((BYTE*)processparameters_address + commandline_offset);
    PVOID commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] commandline_address: 0x%p\n", commandline_address);

    char* commandline_value = ReadRemoteWStr(process_handle, commandline_address);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] commandline_value: %s\n", commandline_value);

    // LARGE_INTEGER delay;
    // delay.QuadPart = -(1000000000 * 10000); // Convert milliseconds to 100-nanosecond intervals and make it negative for relative delay
    // NTDLL$NtDelayExecution(FALSE, &delay);

    //BeaconPrintf(CALLBACK_OUTPUT, "[+] Function end.\n");
    return commandline_value;
}


void EnableDebugPrivileges() {
    HANDLE currentProcess = KERNEL32$GetCurrentProcess();
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Current process handle:\t%d\n", currentProcess);

    HANDLE tokenHandle = NULL;

    // Open the process token
    NTSTATUS ntstatus = NTDLL$NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tokenHandle);
    if (ntstatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error calling NtOpenProcessToken. NTSTATUS: 0x%08X\n", ntstatus);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] NTSTATUS: %d\n", ntstatus);

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
    BeaconPrintf(CALLBACK_OUTPUT, "[+] NTSTATUS: %d\n", ntstatus);

    // Close the handle
    if (tokenHandle != NULL) {
        NTDLL$NtClose(tokenHandle);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Debug privileges enabled successfully.\n");
}


void go() {
    EnableDebugPrivileges();
    HANDLE currentProcess = KERNEL32$GetCurrentProcess();
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Current process handle:\t%d\n", currentProcess);
    GetProcNameFromHandle(currentProcess);
}