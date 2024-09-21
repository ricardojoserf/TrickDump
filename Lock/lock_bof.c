#include <windows.h>
#include "beacon.h"


// Functions
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlGetVersion(POSVERSIONINFOW);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);


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
        write_string_to_file(filename, json_output);
    }
}


void go() {
    char* filename = "lock.json";
    Lock(filename);
}