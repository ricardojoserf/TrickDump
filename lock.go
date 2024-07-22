package main


import (
    "os"
    "fmt"
    "flag"
    "unsafe"
    "syscall"
    "encoding/json"
    "unicode/utf16"
    "golang.org/x/sys/windows"
)

const (
    ProcessBasicInformation uintptr = 0x00
    ldr_offset uintptr = 0x18
    inInitializationOrderModuleList_offset uintptr = 0x30
    flink_dllbase_offset uintptr = 0x20
    flink_buffer_offset uintptr = 0x50
    PAGE_EXECUTE_WRITECOPY uintptr = 0x80
    SEC_IMAGE_NO_EXECUTE uintptr = 0x11000000
    offset_mappeddll uintptr = 0x1000
    SECTION_MAP_READ uintptr = 0x04
    DEBUG_PROCESS uint32 = 0x01
    processparameters_offset = 0x20
    commandline_offset = 0x68
    MAXIMUM_ALLOWED uintptr = 0x02000000
)

var (
    ntReadVirtualMemory *windows.LazyProc
    ntQueryInformationProcess *windows.LazyProc
    ntOpenSection *windows.LazyProc
    ntGetNextProcess *windows.LazyProc
    rtlGetVersion *windows.LazyProc
    VirtualProtect *windows.LazyProc
    createFile *windows.LazyProc
    createFileMapping *windows.LazyProc
    mapViewOfFile *windows.LazyProc
    DebugActiveProcessStop *windows.LazyProc
    TerminateProcess *windows.LazyProc
    CreateProcess *windows.LazyProc
)


// Structures
type RTL_OSVERSIONINFOW struct {
    DwOSVersionInfoSize uint32
    DwMajorVersion      uint32
    DwMinorVersion      uint32
    DwBuildNumber       uint32
    DwPlatformId        uint32
    SzCSDVersion        [128]uint16
}

type OSInformation struct {
    Field0	string `json:"field0"`
    Field1	string    `json:"field1"`
    Field2  string `json:"field2"`
}

type PROCESS_BASIC_INFORMATION struct {
    ExitStatus                   uint32
    PebBaseAddress               uintptr
    AffinityMask                 uintptr
    BasePriority                 int32
    UniqueProcessID              uintptr
    InheritedFromUniqueProcessID uintptr
}

type UNICODE_STRING struct {
    Length        uint16
    MaximumLength uint16
    Buffer        *uint16
}

type OBJECT_ATTRIBUTES struct {
    Length                   uint32
    RootDirectory            windows.Handle
    ObjectName               *UNICODE_STRING
    Attributes               uint32
    SecurityDescriptor       uintptr
    SecurityQualityOfService uintptr
}

type STARTUPINFO struct {
    cb            uint32
    lpReserved    *uint16
    lpDesktop     *uint16
    lpTitle       *uint16
    dwX           uint32
    dwY           uint32
    dwXSize       uint32
    dwYSize       uint32
    dwXCountChars uint32
    dwYCountChars uint32
    dwFillAttribute uint32
    dwFlags         uint32
    wShowWindow     uint16
    cbReserved2     uint16
    lpReserved2     *byte
    hStdInput       windows.Handle
    hStdOutput      windows.Handle
    hStdError       windows.Handle
}

type PROCESS_INFORMATION struct {
    hProcess    windows.Handle
    hThread     windows.Handle
    dwProcessId uint32
    dwThreadId  uint32
}


func init() {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    ntReadVirtualMemory = ntdll.NewProc("NtReadVirtualMemory")
    ntQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
    ntOpenSection = ntdll.NewProc("NtOpenSection")
    ntGetNextProcess = ntdll.NewProc("NtGetNextProcess")
    rtlGetVersion = ntdll.NewProc("RtlGetVersion")
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect = kernel32.NewProc("VirtualProtect")
    createFile = kernel32.NewProc("CreateFileA")
    createFileMapping = kernel32.NewProc("CreateFileMappingA")
    mapViewOfFile = kernel32.NewProc("MapViewOfFile")
    DebugActiveProcessStop = kernel32.NewProc("DebugActiveProcessStop")
    TerminateProcess = kernel32.NewProc("TerminateProcess")
    CreateProcess = kernel32.NewProc("CreateProcessW")
}


func utf16BytesToUTF8(utf16Bytes []byte) []byte {
    u16s := make([]uint16, len(utf16Bytes)/2)
    for i := range u16s {
        u16s[i] = uint16(utf16Bytes[i*2]) | uint16(utf16Bytes[i*2+1])<<8
    }
    return []byte(string(utf16.Decode(u16s)))
}


func read_remoteintptr(process_handle uintptr, base_address uintptr, size uintptr) uintptr {
    buffer := make([]byte, size)
    var bytesRead uintptr
    ntReadVirtualMemory.Call(uintptr(process_handle), base_address, uintptr(unsafe.Pointer(&buffer[0])), size, uintptr(unsafe.Pointer(&bytesRead)))
    read_value := *(*uintptr)(unsafe.Pointer(&buffer[0]))
    return read_value
}


func read_remoteWStr(process_handle uintptr, base_address uintptr, size uintptr) string {
    buffer := make([]byte, size)
    var bytesRead uintptr
    ntReadVirtualMemory.Call(uintptr(process_handle), base_address, uintptr(unsafe.Pointer(&buffer[0])), size, uintptr(unsafe.Pointer(&bytesRead)))
    for i := 0; i < int(bytesRead)-1; i += 1 {
        if buffer[i] == 0x00 && buffer[i+1] == 0x00 {
            return string(utf16BytesToUTF8(buffer[:i+2]))
        }
    }
    return ""
}


func GetProcNameFromHandle(proc_handle uintptr) (string){
    // NtQueryInformationProcess
    var pbi PROCESS_BASIC_INFORMATION
    var returnLength uint32
    status, _, _ := ntQueryInformationProcess.Call(uintptr(proc_handle), ProcessBasicInformation, uintptr(unsafe.Pointer(&pbi)), uintptr(uint32(unsafe.Sizeof(pbi))), uintptr(unsafe.Pointer(&returnLength)),)
    if status != 0 {
        fmt.Printf("[-] NtQueryInformationProcess failed with status: 0x%x\n", status)
        return ""
    }
    peb_addr := pbi.PebBaseAddress 

    // Get PEB->ProcessParameters
    processparameters_pointer := peb_addr + uintptr(processparameters_offset)
    processparameters_adress := read_remoteintptr(proc_handle, processparameters_pointer, 8)

    // Get ProcessParameters->CommandLine
    commandline_pointer := processparameters_adress + uintptr(commandline_offset)
    commandline_address := read_remoteintptr(proc_handle, commandline_pointer, 8)
    commandline_value := read_remoteWStr(proc_handle, commandline_address, 256)
    return commandline_value
}


func GetProcessByName(process_name string) uintptr{
    var s uintptr = 0;
    for {
        res, _, _ := ntGetNextProcess.Call(s, MAXIMUM_ALLOWED, 0, 0, uintptr(unsafe.Pointer(&s)))
        if (res != 0) {
            break
        }
        aux_proc_name := GetProcNameFromHandle(s)
        if (aux_proc_name == process_name){
            return s
        }
    }
    return 0
}


func get_local_lib_address(dll_name string) uintptr {
    // Get current process handle
    execPath, _ := os.Executable()
    process_handle := GetProcessByName(execPath)

    // NtQueryInformationProcess
    var pbi PROCESS_BASIC_INFORMATION
    var returnLength uint32
    status, _, _ := ntQueryInformationProcess.Call(uintptr(process_handle), ProcessBasicInformation, uintptr(unsafe.Pointer(&pbi)), uintptr(uint32(unsafe.Sizeof(pbi))), uintptr(unsafe.Pointer(&returnLength)),)
    if status != 0 {
        fmt.Printf("NtQueryInformationProcess failed with status: 0x%x\n", status)
        return 0
    }
    // fmt.Printf("[+] Process ID: \t%d\n", pbi.UniqueProcessID)
    // fmt.Printf("[+] PEB Base Address: \t0x%x\n", pbi.PebBaseAddress)

    // Ldr Address
    peb_baseaddress := pbi.PebBaseAddress
    ldr_pointer := peb_baseaddress + ldr_offset
    ldr_address := read_remoteintptr(process_handle, ldr_pointer, 8)
    // fmt.Printf("[+] ldr_pointer: \t0x%x\n", ldr_pointer)
    // fmt.Printf("[+] Ldr Address: \t0x%x\n", ldr_address)

    // next_flink
    InInitializationOrderModuleList:= ldr_address + inInitializationOrderModuleList_offset
    next_flink := read_remoteintptr(process_handle, InInitializationOrderModuleList, 8)
    // fmt.Printf("[+] next_flink: \t0x%x\n", next_flink)

    // Loop modules
    var dll_base uintptr = 1337
    for dll_base != 0 {
        next_flink = next_flink - 0x10
        dll_base = read_remoteintptr(process_handle, (next_flink + flink_dllbase_offset), 8)
        if (dll_base == 0){
            break    
        }
        buffer := read_remoteintptr(process_handle, (next_flink + flink_buffer_offset), 8)
        base_dll_name := read_remoteWStr(process_handle, buffer, 256)
        if (base_dll_name == dll_name){
            return dll_base
        }
        next_flink = read_remoteintptr(process_handle, (next_flink + 0x10), 8)
    }
    return 0
}


func get_section_info(base_address uintptr) (uintptr,uintptr) {
    execPath, _ := os.Executable()
    process_handle := GetProcessByName(execPath)
    if (fmt.Sprintf("%d", process_handle) == ""){ return 0,0}
    var e_lfanew_addr uintptr = base_address + 0x3C
    var e_lfanew uintptr = read_remoteintptr(process_handle, e_lfanew_addr, 4)
    var sizeofcode_addr uintptr = base_address + e_lfanew + 24 + 4
    var sizeofcode uintptr = read_remoteintptr(process_handle, sizeofcode_addr, 4)
    var baseofcode_addr uintptr  = base_address + e_lfanew + 24 + 20
    var baseofcode uintptr = read_remoteintptr(process_handle, baseofcode_addr, 4)
    return baseofcode, sizeofcode
}


func replace_ntdll_section(unhooked_ntdll_text uintptr, local_ntdll_txt uintptr, local_ntdll_txt_size uintptr){
    fmt.Printf("[+] Copying %d bytes from 0x%s to 0x%s\n", local_ntdll_txt_size, fmt.Sprintf("%x", unhooked_ntdll_text), fmt.Sprintf("%x", local_ntdll_txt))

    var oldProtect uintptr
    res, _, _ := VirtualProtect.Call(local_ntdll_txt, local_ntdll_txt_size, PAGE_EXECUTE_WRITECOPY, uintptr(unsafe.Pointer(&oldProtect)))
    if res != 1 {
        fmt.Println("Failed to change memory protection to PAGE_EXECUTE_WRITECOPY")
        return
    }
    /// fmt.Scanln()
    // Copy bytes to the address
    for i := uintptr(0); i < local_ntdll_txt_size; i++ {
        *(*byte)(unsafe.Pointer(local_ntdll_txt + i)) = *(*byte)(unsafe.Pointer(unhooked_ntdll_text + i))
    }
    /// fmt.Scanln()
    // Restore the original protection
    res, _, _ = VirtualProtect.Call(local_ntdll_txt, local_ntdll_txt_size, oldProtect, uintptr(unsafe.Pointer(&oldProtect)))
    if res != 1 {
        fmt.Println("Failed to restore the original memory protection")
        return
    }
}


func overwrite_disk(file_name string) uintptr {
    // CreateFileA
    fileNamePtr, _ := syscall.BytePtrFromString(file_name)
    file_handle, _, err := createFile.Call(uintptr(unsafe.Pointer(fileNamePtr)), windows.GENERIC_READ, windows.FILE_SHARE_READ, 0, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
    if windows.Handle(file_handle) == windows.InvalidHandle {
        fmt.Printf("Error creating file: %v\n", err)
        return 0
    }
    // fmt.Printf("[+] File handle: \t%d\n", file_handle)
    defer windows.CloseHandle(windows.Handle(file_handle))

    // CreateFileMappingA
    mapping_handle, _, err := createFileMapping.Call(file_handle, 0, (windows.PAGE_READONLY | SEC_IMAGE_NO_EXECUTE), 0, 0, 0)
    if mapping_handle == 0 {
        fmt.Printf("Error creating file mapping: %v\n", err)
        return 0
    }
    defer windows.CloseHandle(windows.Handle(mapping_handle))
    // fmt.Printf("[+] Mapping handle: \t%d\n", mapping_handle)

    // MapViewOfFile
    unhooked_ntdll, _, err := mapViewOfFile.Call(mapping_handle, windows.FILE_MAP_READ, 0, 0, 0)

    if unhooked_ntdll == 0 {
        fmt.Printf("Error mapping view of file: %v\n", err)
        return 0
    }
    // fmt.Printf("[+] Mapped Ntdll:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll))

    // CloseHandle
    windows.CloseHandle(windows.Handle(file_handle))
    windows.CloseHandle(windows.Handle(mapping_handle))

    // Add Offset
    var unhooked_ntdll_text uintptr = unhooked_ntdll + offset_mappeddll
    return unhooked_ntdll_text
}


func overwrite_knowndlls() uintptr {
    // NtOpenSection
    var s string = "\\KnownDlls\\ntdll.dll"
    us := UNICODE_STRING{}
    us.Length = uint16(len(s) * 2)
    us.MaximumLength = us.Length + 2
    us.Buffer = windows.StringToUTF16Ptr(s)
    oa := OBJECT_ATTRIBUTES{
        Length:      uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
        RootDirectory: 0,
        ObjectName: &us,
        Attributes: 0,
    }
    var section_handle windows.Handle
    status, _, _ := ntOpenSection.Call(uintptr(unsafe.Pointer(&section_handle)), SECTION_MAP_READ, uintptr(unsafe.Pointer(&oa)))
    if status != 0 {
        fmt.Printf("[-] NtOpenSection failed\n")
        os.Exit(0)
        return 0
    }
    // fmt.Printf("[+] Section handle: \t0x%x\n", section_handle)

    // MapViewOfFile
    unhooked_ntdll, _, err := mapViewOfFile.Call(uintptr(section_handle), uintptr(SECTION_MAP_READ), 0, 0, 0)
    if unhooked_ntdll == 0 {
        fmt.Printf("[-] Error mapping view of file: %v\n", err)
        os.Exit(0)
        return 0
    }

    // CloseHandle
    windows.CloseHandle(windows.Handle(section_handle))

    // Add offset
    var unhooked_ntdll_text uintptr = unhooked_ntdll + offset_mappeddll
    return unhooked_ntdll_text
}


func overwrite_debugproc(file_path string, local_ntdll_txt uintptr, local_ntdll_txt_size uintptr) uintptr {
    // CreateProcess
    var si STARTUPINFO
    var pi PROCESS_INFORMATION
    si.cb = uint32(unsafe.Sizeof(si))
    applicationName := windows.StringToUTF16Ptr(file_path)

    success, _, err := CreateProcess.Call(uintptr(unsafe.Pointer(applicationName)), 0, 0, 0, 0, uintptr(DEBUG_PROCESS), 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))   
    if (success != 1) {
        fmt.Printf("CreateProcess failed: %v\n", err)
        os.Exit(0)
    }

    // NtReadVirtualMemory: debugged_process ntdll_handle = local ntdll_handle --> debugged_process .text section ntdll_handle = local .text section ntdll_handle
    buffer := make([]byte, local_ntdll_txt_size)
    var bytesRead uintptr
    status, _, _ := ntReadVirtualMemory.Call(uintptr(pi.hProcess), local_ntdll_txt, uintptr(unsafe.Pointer(&buffer[0])), local_ntdll_txt_size, uintptr(unsafe.Pointer(&bytesRead)))
    if status != 0 {
        fmt.Printf("NtReadVirtualMemory failed with status: 0x%x\n", status)
        os.Exit(0)
    }

    // TerminateProcess + DebugActiveProcessStop
    tp_bool, _, _ := TerminateProcess.Call(uintptr(pi.hProcess), 0)
    daps_bool, _, _ := DebugActiveProcessStop.Call(uintptr(pi.dwProcessId))
    if (tp_bool != 1){
        fmt.Printf("[-] TerminateProcess failed")
        os.Exit(0)
    }
    if (daps_bool != 1){
        fmt.Printf("[-] DebugActiveProcessStop failed")
        os.Exit(0)
    }

    return uintptr(unsafe.Pointer(&buffer[0]))
}


func overwrite(optionFlag string, pathFlag string){
    var local_ntdll uintptr = get_local_lib_address("ntdll.dll")
    // fmt.Printf("[+] Local Ntdll:\t0x%s\n", fmt.Sprintf("%x", local_ntdll))
    local_ntdll_txt_addr, local_ntdll_txt_size := get_section_info(local_ntdll)
    // fmt.Printf("[+] Local Ntdll Size:\t0x%s\n", fmt.Sprintf("%x", local_ntdll_txt_size))
    // fmt.Printf("[+] Local Ntdll Addr:\t0x%s\n", fmt.Sprintf("%x", local_ntdll_txt_addr))
    var local_ntdll_txt uintptr = local_ntdll + local_ntdll_txt_addr
    // fmt.Printf("[+] Local Ntdll Text:\t0x%s\n", fmt.Sprintf("%x", local_ntdll_txt))
    var unhooked_ntdll_text uintptr = 0

    if optionFlag == "disk" {
        file_name := "C:\\Windows\\System32\\ntdll.dll"
        if pathFlag != "default" {
            file_name = pathFlag
        }
        // fmt.Printf("[+] Option \"disk\" - Getting clean version from file in disk %s\n", file_name)
        unhooked_ntdll_text = overwrite_disk(file_name)
        if (unhooked_ntdll_text != 0){
            // fmt.Printf("[+] Mapped Ntdll .Text:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll_text))
        } else {
            fmt.Printf("[-] Error getting the .text section address")
            os.Exit(0)
        }
    } else if optionFlag == "knowndlls" {
        // fmt.Println("[+] Option \"knowndlls\" - Getting clean version from KnownDlls folder")
        unhooked_ntdll_text = overwrite_knowndlls()
        if (unhooked_ntdll_text != 0){
            // fmt.Printf("[+] Mapped Ntdll .Text:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll_text))
        } else {
            fmt.Printf("[-] Error getting the .text section address")
            os.Exit(0)       
        }
    } else if optionFlag == "debugproc" {
        program_path := "c:\\Windows\\System32\\notepad.exe"
        if pathFlag != "default" {
            program_path = pathFlag
        }
        // fmt.Printf("[+] Option \"debugproc\" - Getting clean version from debugged process %s\n", program_path)
        unhooked_ntdll_text = overwrite_debugproc(program_path, local_ntdll_txt, local_ntdll_txt_size)
        if (unhooked_ntdll_text != 0){
            // fmt.Printf("[+] Mapped Ntdll .Text:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll_text))
        } else {
            fmt.Printf("[-] Error getting the .text section address")
            os.Exit(0)       
        }
    } else {
        return
    }
    replace_ntdll_section(unhooked_ntdll_text, local_ntdll_txt, local_ntdll_txt_size)
}


func main() {
    // Ntdll overwrite options
    var optionFlagStr string
    var pathFlagStr string
    flag.StringVar(&optionFlagStr, "o", "default", "Option for library overwrite: \"disk\", \"knowndlls\" or \"debugproc\"")
    flag.StringVar(&pathFlagStr,  "p", "default", "Path to ntdll file in disk (for \"disk\" option) or program to open in debug mode (\"debugproc\" option)")
    flag.Parse()
    if (optionFlagStr != "default") {
        overwrite(optionFlagStr, pathFlagStr)
    }

    var osVersionInfo RTL_OSVERSIONINFOW
    osVersionInfo.DwOSVersionInfoSize = uint32(unsafe.Sizeof(osVersionInfo))
    ret, _, err := rtlGetVersion.Call(uintptr(unsafe.Pointer(&osVersionInfo)))
    if ret != 0 {
        fmt.Printf("RtlGetVersion failed: %v\n", err)
        return
    }

    osInfo := []OSInformation{{ Field0: fmt.Sprint(osVersionInfo.DwMajorVersion) , Field1: fmt.Sprint(osVersionInfo.DwMinorVersion), Field2: fmt.Sprint(osVersionInfo.DwBuildNumber)}}

    // Write to file
    jsonData, err := json.Marshal(osInfo)
    if err != nil {
        fmt.Printf("Error marshaling to JSON: %v\n", err)
        return
    }
    file, err := os.Create("lock.json")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer file.Close()
    _, err = file.Write(jsonData)
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println("[+] File lock.json generated.")
}