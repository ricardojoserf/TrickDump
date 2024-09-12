#include <stdio.h>
#include <windows.h>

// Function prototype
typedef LONG(WINAPI* RtlGetVersionPtr)(POSVERSIONINFOW);

int main() {
    char filename[] = "lock.json";

    ///////////////////////
    // RtlGetVersion
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    if (hModule == NULL) {
        printf("Error: Cannot get handle to ntdll.dll\n");
        return 1;
    }
    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hModule, "RtlGetVersion");
    if (RtlGetVersion == NULL) {
        printf("Error: Cannot get address of RtlGetVersion\n");
        return 1;
    }
    ///////////////////////

    OSVERSIONINFOW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion(&osvi) == 0) {
        FILE* file;
        errno_t err = fopen_s(&file, filename, "w");

        if (err != 0) {
            printf("Error: Cannot open file for writing\n");
            return 1;
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

    return 0;
}
