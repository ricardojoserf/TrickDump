#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlGetVersion(POSVERSIONINFOW);

void go() {
    OSVERSIONINFOW osvi;
    NTSTATUS status = NTDLL$RtlGetVersion(&osvi);
    if (status == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[{\"field0\" : \"%d\", \"field1\" : \"%d\", \"field2\" : \"%d\"}]\n", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    }
}