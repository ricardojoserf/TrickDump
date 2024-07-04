import json
import ctypes
from ctypes import wintypes
import argparse
from overwrite import overwrite_disk, overwrite_knowndlls, overwrite_debugproc


# Structures
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


# Functions
ntdll = ctypes.WinDLL("ntdll")
RtlGetVersion = ntdll.RtlGetVersion
RtlGetVersion.restype = wintypes.LONG
os_version_info = OSVERSIONINFOEXW()
os_version_info.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--option', required=False, default="", action='store', help='Option for library overwrite')
    parser.add_argument('-p', '--path', required=False, default="", action='store', help='Path (file in disk or program to open in debug mode)')
    my_args = parser.parse_args()
    return my_args


def main():
    # Ntdll overwrite
    args = get_args()
    option = args.option
    if option == "disk":
        path = "C:\\Windows\\System32\\ntdll.dll"
        if args.path != "":
            path = args.path
        overwrite_disk(path)
    elif option == "knowndlls":
        overwrite_knowndlls()
    elif option == "debugproc":
        path = "c:\\windows\\system32\\calc.exe"
        if args.path != "":
            path = args.path
        overwrite_debugproc(path)
    else:
        pass

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