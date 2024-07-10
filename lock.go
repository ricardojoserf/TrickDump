package main


import (
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
	jsonData, err := json.Marshal(osInfo)
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v\n", err)
		return
	}
	fmt.Println(string(jsonData))
}