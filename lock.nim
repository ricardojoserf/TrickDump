import winim/lean
import json


type
  OSVERSIONINFOEX* = object
    dwOSVersionInfoSize*: DWORD
    dwMajorVersion*: DWORD
    dwMinorVersion*: DWORD
    dwBuildNumber*: DWORD
    dwPlatformId*: DWORD
    szCSDVersion*: array[128, WCHAR]  # Wide character array for CSD version
    wServicePackMajor*: WORD
    wServicePackMinor*: WORD
    wSuiteMask*: WORD
    wProductType*: BYTE
    wReserved*: BYTE

proc RtlGetVersion*(lpVersionInformation: var OSVERSIONINFOEX): NTSTATUS {.discardable, dynlib: "ntdll", importc: "RtlGetVersion".}

proc getBuildNumber*(): OSVERSIONINFOEX =
  var osVersionInfo: OSVERSIONINFOEX
  osVersionInfo.dwOSVersionInfoSize = DWORD sizeof(OSVERSIONINFOEX)
  discard RtlGetVersion(osVersionInfo)
  result = osVersionInfo

proc writeToFile*(path: string, content: string) =
  writeFile(path, content)
  echo "[+] File ", path, " generated."

proc lock*(fileName: string) =
  let osVersionInfo = getBuildNumber()
  
  # Create JSON structure
  let versionData = %*{
    "field0": $osVersionInfo.dwMajorVersion,
    "field1": $osVersionInfo.dwMinorVersion,
    "field2": $osVersionInfo.dwBuildNumber,
  }
  
  # Wrap the data in an array
  let wrapper = %*[versionData]
  
  # Write JSON to file
  writeToFile(fileName, $wrapper)

when isMainModule:
  # Get OS information and write to lock.json
  lock("lock.json")