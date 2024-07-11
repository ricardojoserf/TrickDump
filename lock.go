package main


import (
	"os"
	"fmt"
	"unsafe"
	"encoding/json"
	"golang.org/x/sys/windows"
)


var (
	rtlGetVersion *windows.LazyProc
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


func init() {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rtlGetVersion = ntdll.NewProc("RtlGetVersion")
}


func main() {
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