use std::fs::File;
use std::io::Write;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::NTSTATUS;
use winapi::um::winnt::OSVERSIONINFOW;
use winapi::um::winnt::RTL_OSVERSIONINFOW;

unsafe extern "system" {
    fn RtlGetVersion(lpVersionInformation: *mut RTL_OSVERSIONINFOW) -> NTSTATUS;
}

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

fn main() {
    let filename = "lock.json";
    if let Err(e) = lock(filename) {
        eprintln!("Error: {}", e);
    }
}