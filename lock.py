import json
import ctypes
from ctypes import wintypes


class OSVERSIONINFOEXW(ctypes.Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", wintypes.DWORD),
        ("dwMajorVersion", wintypes.DWORD),
        ("dwMinorVersion", wintypes.DWORD),
        ("dwBuildNumber", wintypes.DWORD),
        ("dwPlatformId", wintypes.DWORD),
        ("szCSDVersion", wintypes.WCHAR * 128),
        ("wServicePackMajor", wintypes.WORD),
        ("wServicePackMinor", wintypes.WORD),
        ("wSuiteMask", wintypes.WORD),
        ("wProductType", wintypes.BYTE),
        ("wReserved", wintypes.BYTE),
    ]


def main():
    ntdll = ctypes.WinDLL("ntdll")
    RtlGetVersion = ntdll.RtlGetVersion
    RtlGetVersion.restype = wintypes.LONG
    os_version_info = OSVERSIONINFOEXW()
    os_version_info.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
    status = RtlGetVersion(ctypes.byref(os_version_info))

    if status == 0:
        lock_info = [{
          "field0": str(os_version_info.dwMajorVersion),
          "field1": str(os_version_info.dwMinorVersion),
          "field2": str(os_version_info.dwBuildNumber)
        }]
        file_name = "lock.json"
        with open(file_name, 'w', encoding='utf-8') as f:
            json.dump(lock_info, f, ensure_ascii=False)
        print("[+] File " + file_name + " generated.")
    else:
        print("[-] Failed to get version information")


if __name__ == "__main__":
    main()