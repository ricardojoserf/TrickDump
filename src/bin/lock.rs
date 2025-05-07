use std::{
    ffi::{c_void, OsStr},
    fs::File,
    io::Write,
    iter::once,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt,
    ptr::null_mut,
};
use clap::Parser;
use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{DWORD, ULONG},
        ntdef::{HANDLE, NTSTATUS, PVOID},
    },
    um::{
        processthreadsapi::{
            CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
        },
        winbase::DEBUG_PROCESS,
        winnt::{OSVERSIONINFOW, RTL_OSVERSIONINFOW},
    },
};


const PROCESS_BASIC_INFORMATION_CLASS: ULONG = 0;
const STATUS_ACCESS_VIOLATION: i32 = 0xC0000005u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0x8000000Du32 as i32;
const NT_SUCCESS: fn(NTSTATUS) -> bool = |status| status >= 0;
const STATUS_SUCCESS: NTSTATUS = 0;
const PROCESS_DEBUG_OBJECT_HANDLE: ULONG = 0x1e;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;


unsafe extern "system" {
    fn RtlGetVersion(lpVersionInformation: *mut RTL_OSVERSIONINFOW) -> NTSTATUS;
    fn NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: usize, NumberOfBytesRead: *mut usize) -> NTSTATUS;
    fn NtQueryInformationProcess(ProcessHandle: HANDLE, ProcessInformationClass: ULONG, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: *mut ULONG) -> NTSTATUS;
    fn NtRemoveProcessDebug(ProcessHandle: HANDLE, DebugObjectHandle: HANDLE) -> NTSTATUS;
    fn NtTerminateProcess(ProcessHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;
    fn NtClose(Handle: HANDLE) -> NTSTATUS;
    fn NtProtectVirtualMemory(ProcessHandle: HANDLE, BaseAddress: *mut *mut c_void, RegionSize: *mut SIZE_T, NewProtect: u32, OldProtect: *mut ULONG,) -> NTSTATUS;
    fn NtWriteVirtualMemory( ProcessHandle: HANDLE, BaseAddress: *mut c_void, Buffer: *const c_void, NumberOfBytesToWrite: usize, NumberOfBytesWritten: *mut usize,) -> NTSTATUS;
}


#[derive(Debug)] pub struct TextSectionInfo { pub base_of_code: DWORD, pub size_of_code: DWORD,}


fn lock(filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut osvi = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as DWORD,
        dwMajorVersion: 0,
        dwMinorVersion: 0,
        dwBuildNumber: 0,
        dwPlatformId: 0,
        szCSDVersion: [0; 128],
    };

    unsafe {
        if RtlGetVersion(&mut osvi) == 0 {
            let mut file = File::create(filename)?;
            write!(
                file,
                "[{{\"field0\":\"{}\",\"field1\":\"{}\",\"field2\":\"{}\"}}]",
                osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber
            )?;
            println!("[+] File {} generated.", filename);
        } else {
            return Err("RtlGetVersion call failed".into());
        }
    }
    Ok(())
}


unsafe fn read_remote_int_ptr(process: HANDLE, address: PVOID) -> Option<PVOID> {
    let mut buffer = [0u8; 8];
    let mut bytes_read = 0usize;
    let status = NtReadVirtualMemory(
        process,
        address,
        buffer.as_mut_ptr() as PVOID,
        buffer.len(),
        &mut bytes_read,
    );

    if status != 0 && status != STATUS_ACCESS_VIOLATION && status != STATUS_INVALID_PARAMETER {
        eprintln!(
            "[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x{:X} reading address {:p}",
            status, address
        );
        return None;
    }

    let value = *(buffer.as_ptr() as *const usize) as PVOID;
    Some(value)
}


unsafe fn read_remote_wstr(process: HANDLE, address: PVOID) -> String {
    let mut buffer = [0u8; 256];
    let mut bytes_read = 0usize;
    let status = NtReadVirtualMemory(
        process,
        address,
        buffer.as_mut_ptr() as PVOID,
        buffer.len(),
        &mut bytes_read,
    );

    if status != 0 && status != STATUS_ACCESS_VIOLATION && status != STATUS_INVALID_PARAMETER {
        eprintln!(
            "[-] Error calling NtReadVirtualMemory (ReadRemoteWStr). NTSTATUS: 0x{:X} reading address {:p}",
            status, address
        );
    }

    let mut output = Vec::new();
    for i in (0..buffer.len() - 1).step_by(2) {
        let wchar = u16::from_le_bytes([buffer[i], buffer[i + 1]]);
        if wchar == 0 {
            break;
        }
        output.push(wchar);
    }

    String::from_utf16_lossy(&output)
}


unsafe fn get_module_address(dll_name: &str) -> Option<PVOID> {
    let process_basic_information_size = 48;
    let peb_offset = 0x8;
    let ldr_offset = 0x18;
    let in_initialization_order_module_list_offset = 0x30;
    let flink_dllbase_offset = 0x20;
    let flink_buffer_offset = 0x50;

    let mut pbi_buffer = [0u8; 48];
    let mut return_length: ULONG = 0;
    let h_process: HANDLE = -1isize as HANDLE;

    let status = NtQueryInformationProcess(
        h_process,
        PROCESS_BASIC_INFORMATION_CLASS,
        pbi_buffer.as_mut_ptr() as PVOID,
        process_basic_information_size as ULONG,
        &mut return_length,
    );

    if !NT_SUCCESS(status) {
        eprintln!("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x{:08X}", status);
        return None;
    }

    let peb_address_ptr = pbi_buffer.as_ptr().add(peb_offset) as *const PVOID;
    let peb_address = read_remote_int_ptr(h_process, peb_address_ptr as PVOID)?;

    let ldr_pointer = (peb_address as usize + ldr_offset) as PVOID;
    let ldr_address = read_remote_int_ptr(h_process, ldr_pointer)?;

    let in_initialization_order_module_list = (ldr_address as usize + in_initialization_order_module_list_offset) as PVOID;
    let mut next_flink = read_remote_int_ptr(h_process, in_initialization_order_module_list)?;

    while !next_flink.is_null() {
        next_flink = (next_flink as usize - 0x10) as PVOID;

        let dll_base_ptr = (next_flink as usize + flink_dllbase_offset) as PVOID;
        let dll_base = read_remote_int_ptr(h_process, dll_base_ptr)?;

        let buffer_ptr = (next_flink as usize + flink_buffer_offset) as PVOID;
        let buffer = read_remote_int_ptr(h_process, buffer_ptr)?;
        let base_dll_name = read_remote_wstr(h_process, buffer);

        if base_dll_name.to_lowercase() == dll_name.to_lowercase() {
            return Some(dll_base);
        }

        let next_flink_ptr = (next_flink as usize + 0x10) as PVOID;
        next_flink = read_remote_int_ptr(h_process, next_flink_ptr)?;
    }

    None
}


pub unsafe fn get_text_section_info(ntdll_address: *mut u8) -> Option<TextSectionInfo> {
    let h_process =  -1isize as HANDLE;
    let mut bytes_read = 0;

    // Check MZ Signature (2 bytes)
    let mut signature_dos_header = [0u8; 2];
    if !NT_SUCCESS(NtReadVirtualMemory(
        h_process,
        ntdll_address as _,
        signature_dos_header.as_mut_ptr() as _,
        2,
        &mut bytes_read,
    )) || bytes_read != 2
    {
        eprintln!("[-] Error reading DOS header signature");
        return None;
    }

    if signature_dos_header[0] != b'M' || signature_dos_header[1] != b'Z' {
        eprintln!("[-] Incorrect DOS header signature");
        return None;
    }

    // Read e_lfanew (4 bytes) at offset 0x3C
    let mut e_lfanew = 0u32;
    if !NT_SUCCESS(NtReadVirtualMemory(
        h_process,
        ntdll_address.add(0x3C) as _,
        &mut e_lfanew as *mut _ as _,
        4,
        &mut bytes_read,
    )) || bytes_read != 4
    {
        eprintln!("[-] Error reading e_lfanew");
        return None;
    }

    // Check PE Signature (2 bytes)
    let mut signature_nt_header = [0u8; 2];
    if !NT_SUCCESS(NtReadVirtualMemory(
        h_process,
        ntdll_address.add(e_lfanew as usize) as _,
        signature_nt_header.as_mut_ptr() as _,
        2,
        &mut bytes_read,
    )) || bytes_read != 2
    {
        eprintln!("[-] Error reading NT header signature");
        return None;
    }

    if signature_nt_header[0] != b'P' || signature_nt_header[1] != b'E' {
        eprintln!("[-] Incorrect NT header signature");
        return None;
    }

    // Check Optional Headers Magic field value (2 bytes)
    let mut optional_header_magic = 0u16;
    if !NT_SUCCESS(NtReadVirtualMemory(
        h_process,
        ntdll_address.add(e_lfanew as usize + 24) as _,
        &mut optional_header_magic as *mut _ as _,
        2,
        &mut bytes_read,
    )) || bytes_read != 2
    {
        eprintln!("[-] Error reading Optional Header Magic");
        return None;
    }

    if optional_header_magic != 0x20B && optional_header_magic != 0x10B {
        eprintln!("[-] Incorrect Optional Header Magic field value");
        return None;
    }

    // Read SizeOfCode (4 bytes)
    let mut sizeofcode = 0u32;
    if !NT_SUCCESS(NtReadVirtualMemory(
        h_process,
        ntdll_address.add(e_lfanew as usize + 24 + 4) as _,
        &mut sizeofcode as *mut _ as _,
        4,
        &mut bytes_read,
    )) || bytes_read != 4
    {
        eprintln!("[-] Error reading SizeOfCode");
        return None;
    }

    // Read BaseOfCode (4 bytes)
    let mut baseofcode = 0u32;
    if !NT_SUCCESS(NtReadVirtualMemory(
        h_process,
        ntdll_address.add(e_lfanew as usize + 24 + 20) as _,
        &mut baseofcode as *mut _ as _,
        4,
        &mut bytes_read,
    )) || bytes_read != 4
    {
        eprintln!("[-] Error reading BaseOfCode");
        return None;
    }

    Some(TextSectionInfo {
        base_of_code: baseofcode,
        size_of_code: sizeofcode,
    })
}


pub unsafe fn get_ntdll_from_debug_proc(process_path: &str) -> Vec<u8> {
    let mut si: STARTUPINFOW = zeroed();
    si.cb = size_of::<STARTUPINFOW>() as DWORD;
    let mut pi: PROCESS_INFORMATION = zeroed();
    let mut debug_object_handle: HANDLE = null_mut();
    let mut return_length: ULONG = 0;

    // Convert path to wide string
    let wide_path: Vec<u16> = OsStr::new(process_path).encode_wide().chain(once(0)).collect();

    // Create suspended process with debug flag
    let success = CreateProcessW(
        wide_path.as_ptr(),
        null_mut(),
        null_mut(),
        null_mut(),
        0,
        DEBUG_PROCESS,
        null_mut(),
        null_mut(),
        &mut si,
        &mut pi,
    );

    if success == 0 {
        eprintln!("[-] CreateProcess failed");
        std::process::exit(1);
    }

    // Get local ntdll address and .text section info
    let local_ntdll_handle = match get_module_address("ntdll.dll") {
        Some(handle) => handle,
        None => {
            eprintln!("[-] Failed to locate ntdll.dll in current process");
            std::process::exit(1);
        }
    };

    let text_info = match get_text_section_info(local_ntdll_handle as *mut u8) {
        Some(info) => info,
        None => {
            eprintln!("[-] Failed to parse local ntdll");
            std::process::exit(1);
        }
    };

    let local_ntdll_text = (local_ntdll_handle as usize + text_info.base_of_code as usize) as PVOID;
    let text_size = text_info.size_of_code as usize;
    let mut ntdll_buffer = vec![0u8; text_size];
    let mut bytes_read: usize = 0;

    let status = NtReadVirtualMemory(
        pi.hProcess,
        local_ntdll_text,
        ntdll_buffer.as_mut_ptr() as PVOID,
        text_size,
        &mut bytes_read,
    );

    if !NT_SUCCESS(status) {
        eprintln!("[-] Read operation failed");
        std::process::exit(1);
    }

    // Query debug object handle
    let status = NtQueryInformationProcess(
        pi.hProcess,
        PROCESS_DEBUG_OBJECT_HANDLE,
        &mut debug_object_handle as *mut _ as PVOID,
        size_of::<HANDLE>() as ULONG,
        &mut return_length,
    );

    if !NT_SUCCESS(status) {
        eprintln!("[-] Failed to get debug object handle");
        std::process::exit(1);
    }

    // Cleanup
    let status = NtRemoveProcessDebug(pi.hProcess, debug_object_handle);
    if !NT_SUCCESS(status) {
        eprintln!("[-] Failed to remove process debug");
        std::process::exit(1);
    }

    let status = NtTerminateProcess(pi.hProcess, 0);
    if !NT_SUCCESS(status) {
        eprintln!("[-] Failed to terminate process");
        std::process::exit(1);
    }

    if !NT_SUCCESS(NtClose(pi.hProcess)) || !NT_SUCCESS(NtClose(pi.hThread)) {
        eprintln!("[-] Handle closure failed");
        std::process::exit(1);
    }

    ntdll_buffer
}


pub unsafe fn replace_ntdll_txt_section(
    unhooked_ntdll_txt: *const u8,
    local_ntdll_txt: *mut u8,
    local_ntdll_txt_size: u32,
) {
    let current_process = -1isize as HANDLE;
    let mut region_size: SIZE_T = local_ntdll_txt_size as SIZE_T;
    let mut base_address: *mut c_void = local_ntdll_txt as *mut c_void;
    let mut old_protection: ULONG = 0;


    // Change protection to PAGE_EXECUTE_WRITECOPY
    let status = NtProtectVirtualMemory(
        current_process,
        &mut base_address,
        &mut region_size,
        PAGE_EXECUTE_WRITECOPY,
        &mut old_protection,
    );
    if status != STATUS_SUCCESS {
        eprintln!("[-] Failed to change memory protection");
        std::process::exit(1);
    }

    // Copy memory from unhooked to hooked
    let mut bytes_written: usize = 0;
    let status = NtWriteVirtualMemory(
        current_process,
        local_ntdll_txt as *mut c_void,
        unhooked_ntdll_txt as *const c_void,
        local_ntdll_txt_size as usize,
        &mut bytes_written,
    );
    if status != STATUS_SUCCESS || bytes_written != local_ntdll_txt_size as usize {
        eprintln!(
            "[-] Failed to write memory: status={:#X}, written={}",
            status, bytes_written
        );
        std::process::exit(1);
    }

    // Restore original protection
    let mut region_size: SIZE_T = local_ntdll_txt_size as SIZE_T;
    let mut base_address: *mut c_void = local_ntdll_txt as *mut c_void;
    let status = NtProtectVirtualMemory(
        current_process,
        &mut base_address,
        &mut region_size,
        old_protection,
        &mut old_protection,
    );
    if status != STATUS_SUCCESS {
        eprintln!("[-] Failed to restore memory protection");
        std::process::exit(1);
    }
}


pub unsafe fn remap_library(){    
    let unhooked_ntdll_txt = get_ntdll_from_debug_proc(r"C:\Windows\System32\notepad.exe");
    
    // Get local ntdll.dll base address
    let local_ntdll_handle = match get_module_address("ntdll.dll") {
        Some(handle) => handle,
        None => {
            eprintln!("[-] Failed to get ntdll.dll base address");
            std::process::exit(1);
        }
    };

    // Get text section information
    let text_section = match get_text_section_info(local_ntdll_handle as *mut u8) {
        Some(info) => info,
        None => {
            eprintln!("[-] Failed to get text section info");
            std::process::exit(1);
        }
    };

    let local_ntdll_txt_base = text_section.base_of_code;
    let local_ntdll_txt_size = text_section.size_of_code;
    let local_ntdll_txt = (local_ntdll_handle as usize + local_ntdll_txt_base as usize) as *mut u8;
    let unhooked_ntdll_txt_ptr = unhooked_ntdll_txt.as_ptr();
    
    println!("[+] Replacing 0x{:X} bytes from 0x{:X} to 0x{:X}", local_ntdll_txt_size, unhooked_ntdll_txt_ptr as usize, local_ntdll_txt as usize);
    replace_ntdll_txt_section(unhooked_ntdll_txt_ptr, local_ntdll_txt, local_ntdll_txt_size);
}


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'r', long)]
    remap: bool,

    #[arg(short = 'j', long, default_value = "lock.json")]
    json_file: String,
}


fn main() {
    let args = Args::parse();
    unsafe {
        if args.remap {
            remap_library();
        }
        if let Err(e) = lock(&args.json_file) {
            eprintln!("Error: {}", e);
        }
    }
}