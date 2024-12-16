require "option_parser"


@[Link("ntdll")]
lib Ntdll
  struct OSVERSIONINFOEXW
    dwOSVersionInfoSize : UInt32
    dwMajorVersion : UInt32
    dwMinorVersion : UInt32
    dwBuildNumber : UInt32
    dwPlatformId : UInt32
    szCSDVersion : UInt16[128]
    wServicePackMajor : UInt16
    wServicePackMinor : UInt16
    wSuiteMask : UInt16
    wProductType : UInt8
    wReserved : UInt8
  end

  fun RtlGetVersion(lpVersionInformation : OSVERSIONINFOEXW*) : Int32
  
  fun NtTerminateProcess(process_handle : LibC::HANDLE, exit_status : Int32) : UInt32
  fun NtProtectVirtualMemory(process_handle : UInt64, base_address : Pointer(Pointer(Void)), region_size : Pointer(UInt64), new_protect : UInt32, old_protect : Pointer(UInt32)) : Int32
  fun NtQueryInformationProcess(process_handle : Pointer(Void), process_info_class : UInt32, process_info : Pointer(UInt8), process_info_size : UInt32, return_length : Pointer(UInt32)) : UInt32
  fun NtReadVirtualMemory(process_handle : Pointer(Void), base_address : Pointer(Void), buffer : Pointer(UInt8), buffer_size : UInt64, bytes_read : Pointer(UInt64)) : UInt32
  fun NtClose(handle : LibC::HANDLE) : UInt32
end


@[Link("kernel32")]
lib Kernel32
  fun DebugActiveProcessStop(process_id : Int32) : Bool
  # fun CustomCreateProcessW(application_name : LibC::LPWSTR,command_line : LibC::LPWSTR,process_attributes : Pointer(Void),thread_attributes : Pointer(Void),inherit_handles : Bool,creation_flags : UInt32,environment : Pointer(Void),current_directory : LibC::LPWSTR,startup_info : Pointer(Void),process_information : Pointer(Void)) : Bool
end


# Constants
DEBUG_PROCESS = 0x00000001_u32
PAGE_EXECUTE_WRITECOPY = 0x80_u32


# Structs
struct STARTUPINFO
  property cb : Int32
  lp_reserved : Pointer(Void)
  lp_desktop : Pointer(UInt16) # LPWSTR
  lp_title : Pointer(UInt16)   # LPWSTR
  dw_x : Int32
  dw_y : Int32
  dw_x_size : Int32
  dw_y_size : Int32
  dw_x_count_chars : Int32
  dw_y_count_chars : Int32
  dw_fill_attribute : Int32
  dw_flags : Int32
  w_show_window : Int16
  cb_reserved2 : Int16
  lp_reserved2 : Pointer(Void)
  h_std_input : LibC::HANDLE
  h_std_output : LibC::HANDLE
  h_std_error : LibC::HANDLE

  def initialize
    @cb = sizeof(STARTUPINFO)   # Set the size of the struct
    @lp_reserved = Pointer(Void).null
    @lp_desktop = Pointer(UInt16).null
    @lp_title = Pointer(UInt16).null
    @dw_x = 0
    @dw_y = 0
    @dw_x_size = 0
    @dw_y_size = 0
    @dw_x_count_chars = 0
    @dw_y_count_chars = 0
    @dw_fill_attribute = 0
    @dw_flags = 0
    @w_show_window = 0
    @cb_reserved2 = 0
    @lp_reserved2 = Pointer(Void).null
    @h_std_input = LibC::HANDLE.new(0)
    @h_std_output = LibC::HANDLE.new(0)
    @h_std_error = LibC::HANDLE.new(0)
  end
end


struct PROCESS_INFORMATION
  property h_process : LibC::HANDLE
  property h_thread : LibC::HANDLE
  property dw_process_id : Int32
  property dw_thread_id : Int32

  # Initialize function
  def initialize(h_process : LibC::HANDLE, h_thread : LibC::HANDLE, dw_process_id : Int32, dw_thread_id : Int32)
    @h_process = h_process
    @h_thread = h_thread
    @dw_process_id = dw_process_id
    @dw_thread_id = dw_thread_id
  end

  # Getters
  def get_h_process : LibC::HANDLE
    @h_process
  end

  def get_h_thread : LibC::HANDLE
    @h_thread
  end

  def get_dw_process_id : Int32
    @dw_process_id
  end

  def get_dw_thread_id : Int32
    @dw_thread_id
  end
end


def get_windows_version
  os_info = Ntdll::OSVERSIONINFOEXW.new
  os_info.dwOSVersionInfoSize = 148

  result = Ntdll.RtlGetVersion(pointerof(os_info))
  if result == 0
    return {
      field0: os_info.dwMajorVersion.to_s,
      field1: os_info.dwMinorVersion.to_s,
      field2: os_info.dwBuildNumber.to_s
    }
  else
    raise "Failed to get Windows version. Error code: #{result}"
  end
end


def lock(filename = "lock.json")
  version = get_windows_version
  json_output = "[{\"field0\": \"#{version[:field0]}\", \"field1\": \"#{version[:field1]}\", \"field2\": \"#{version[:field2]}\"}]"

  # Create file  
  File.open(filename, "w") do |file|
    file.puts(json_output)
  end
  puts "[+] File #{filename} generated."
end


def readRemoteWStr(h_process : Pointer(Void), mem_address : UInt64) : String
  buffer = StaticArray(UInt8, 256).new(0) # Equivalent to `byte[] buff = new byte[256]`
  bytes_read = Pointer(UInt64).malloc(1)  # To store the number of bytes read

  # Call NtReadVirtualMemory to read the remote memory
  ntstatus = Ntdll.NtReadVirtualMemory(h_process, Pointer(Void).new(mem_address), buffer.to_unsafe, buffer.size.to_u32, bytes_read)

  # Check for errors
  if ntstatus != 0 && ntstatus != 0xC0000005_u32 && ntstatus != 0x8000000D_u32 && !h_process.null?
    puts "[-] Error calling NtReadVirtualMemory (ReadRemoteWStr). NTSTATUS: 0x#{ntstatus.to_s(16)} reading address 0x#{mem_address.to_s(16)}"
  end

  # Convert the buffer into a Unicode string
  unicode_str = String.build do |str|
    i = 0
    while i < buffer.size - 1
      # Read 2 bytes at a time
      char_code = (buffer[i] | (buffer[i + 1] << 8)) # Combine two bytes into a UTF-16 code unit
      break if char_code == 0 # Null-terminated string
      str << char_code.chr
      i += 2
    end
  end

  return unicode_str
end


def readRemoteIntPtr(h_process : Pointer(Void), mem_address : UInt64) : UInt64
#def read_remote_intptr(h_process : UInt64, mem_address : UInt64) : UInt64
  buffer = StaticArray(UInt8, 8).new(0) # Equivalent to `byte[] buff = new byte[8]`
  bytes_read = Pointer(UInt64).malloc(1) # To store the number of bytes read

  ntstatus = Ntdll.NtReadVirtualMemory(h_process, Pointer(Void).new(mem_address.to_u64), buffer.to_unsafe, buffer.size.to_u32, bytes_read)

  if ntstatus != 0 && ntstatus != 0xC0000005_u32 && ntstatus != 0x8000000D_u32 && h_process != 0
    puts "[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x#{ntstatus.to_s(16)} reading address 0x#{mem_address.to_s(16)}"
  end

  # Convert buffer to Int64
  value = buffer.to_slice.to_unsafe.as(Pointer(Int64)).value

  return value.to_u64
end


def custom_get_module_address(h_process : Pointer(Void), module_name : String ) : UInt64
  process_basic_information_size = 48_u32
  peb_offset = 0x8
  ldr_offset = 0x18
  in_initialization_order_module_list_offset = 0x30
  flink_dllbase_offset = 0x20
  flink_buffer_fulldllname_offset = 0x40
  flink_buffer_offset = 0x50

  # Pointer to PROCESS_BASIC_INFORMATION structure
  pbi_byte_array = Bytes.new(process_basic_information_size)
  pbi_addr = Pointer(UInt8).null
  pbi_addr = pbi_byte_array.to_unsafe

  # Call NtQueryInformationProcess
  return_length = 0_u32
  ntstatus = Ntdll.NtQueryInformationProcess(h_process, 0x0, pbi_addr, process_basic_information_size, pointerof(return_length))

  if ntstatus != 0
    puts "[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x#{ntstatus.to_s(16)}"
    return 0_u64
  end
  #puts "ntstatus: #{ntstatus}"

  # Get PEB Base Address
  #peb_pointer = Pointer(UInt64).new(pbi_byte_array[peb_offset].to_u64)
  #peb_address = readRemoteIntPtr(h_process, peb_pointer.address)
  peb_pointer = pbi_addr + peb_offset
  currentProcess = Pointer(Void).new(UInt64::MAX) #0xffffffff... = -1
  peb_address = readRemoteIntPtr(currentProcess, peb_pointer.address)

  #puts "peb_pointer: 0x#{peb_pointer}"
  #puts "peb_address: 0x#{peb_address.to_s(16)}"

  # Get Ldr
  ldr_pointer = Pointer(UInt64).new(peb_address + ldr_offset)
  ldr_address = readRemoteIntPtr(h_process, ldr_pointer.address)

  in_initialization_order_module_list = ldr_address + in_initialization_order_module_list_offset
  next_flink = readRemoteIntPtr(h_process, in_initialization_order_module_list)

  dll_base = UInt64::MAX
  while dll_base != 0
    next_flink -= 0x10

    # DLL base name
    buffer = readRemoteIntPtr(h_process, next_flink + flink_buffer_offset)
    base_dll_name = ""
    if buffer != 0
      base_dll_name = readRemoteWStr(h_process, buffer)
    end

    if base_dll_name == module_name
      # Get DLL base address
      dll_base = readRemoteIntPtr(h_process, next_flink + flink_dllbase_offset)
      return dll_base
    end
      
    next_flink = readRemoteIntPtr(h_process, next_flink + 0x10)
  end

  return 0_u64
end


# Function to check and get the text section info from an image
def get_text_section_info(ntdll_address : Pointer(Void)) : Array(UInt32)
  h_process = Pointer(Void).new(UInt64::MAX) #0xffffffff... = -1 #LibC.GetCurrentProcess()

  # Read e_lfanew at offset 0x3C (4 bytes)
  e_lfanew_data = Bytes.new(4)
  e_lfanew_address = ntdll_address + 0x3C
  Ntdll.NtReadVirtualMemory(h_process, e_lfanew_address, e_lfanew_data.to_unsafe, 4, Pointer(UInt64).null)

  e_lfanew = e_lfanew_data.to_unsafe.as(UInt32*).value #e_lfanew_data.unpack("I").first
  nt_headers_address = ntdll_address + e_lfanew
  optional_header_address = nt_headers_address + 24

  # Read SizeOfCode at offset 4 from Optional Header
  sizeofcode_address = optional_header_address + 4
  sizeofcode_data = Bytes.new(4)
  Ntdll.NtReadVirtualMemory(h_process, sizeofcode_address, sizeofcode_data.to_unsafe, sizeofcode_data.size, Pointer(UInt64).null)
  sizeofcode = sizeofcode_data.to_unsafe.as(UInt32*).value

  # Read BaseOfCode at offset 20 from Optional Header
  baseofcode_address = optional_header_address + 20
  baseofcode_data = Bytes.new(4)
  Ntdll.NtReadVirtualMemory(h_process, baseofcode_address, baseofcode_data.to_unsafe, baseofcode_data.size, Pointer(UInt64).null)

  baseofcode = baseofcode_data.to_unsafe.as(UInt32*).value

  # Return the BaseOfCode and SizeOfCode
  [baseofcode, sizeofcode]
end


# Function to create a debug process and copy ntdll.dll text section
def get_ntdll_from_debug_proc(process_path : String) : Pointer(UInt8)
  # Step 1: Create debug process
  si = LibC::STARTUPINFOW.new
  si.cb = sizeof(STARTUPINFO)
  #pi = LibC::PROCESS_INFORMATION.new(Pointer(Void).null, Pointer(Void).null, 0, 0)
  pi = LibC::PROCESS_INFORMATION.new
  pi.hProcess = Pointer(Void).null
  pi.hThread = Pointer(Void).null
  pi.dwProcessId = 0
  pi.dwThreadId = 0

  success = LibC.CreateProcessW(
    process_path.to_utf16, 
    nil, 
    Pointer(LibC::SECURITY_ATTRIBUTES).null, # Explicitly null for lpProcessAttributes
    Pointer(LibC::SECURITY_ATTRIBUTES).null, # Explicitly null for lpThreadAttributes
    false, 
    DEBUG_PROCESS, 
    Pointer(Void).null, 
    Pointer(UInt16).null, 
    pointerof(si), 
    pointerof(pi)
  )

  unless success
    puts "[-] Error calling CreateProcess"
    exit(1)
  end

  # Step 2: Retrieve local ntdll.dll address and text section info
  current_process = Pointer(Void).new(UInt64::MAX) # -1 (current process)
  local_ntdll_handle = custom_get_module_address(current_process, "ntdll.dll")
  result = get_text_section_info(Pointer(Void).new(local_ntdll_handle))
  local_ntdll_txt_base = result[0]
  local_ntdll_txt_size = result[1]
  local_ntdll_txt = local_ntdll_handle + local_ntdll_txt_base
    
  # Step 3: Read ntdll.dll text section into buffer
  ntdll_buffer = Bytes.new(local_ntdll_txt_size)
  read_result = Ntdll.NtReadVirtualMemory(pi.hProcess, Pointer(Void).new(local_ntdll_txt), ntdll_buffer.to_unsafe, ntdll_buffer.size, Pointer(UInt64).null)

  if read_result != 0
    puts "[-] Error calling NtReadVirtualMemory"
    exit(1)
  end

  # Step 4: Copy buffer pointer
  p_ntdll_buffer = Pointer(UInt8).null
  p_ntdll_buffer = ntdll_buffer.to_unsafe

  # Step 5: Cleanup and terminate debug process
  debug_stop_result = Kernel32.DebugActiveProcessStop(pi.dwProcessId)
  terminate_result = Ntdll.NtTerminateProcess(pi.hProcess, 0)

  unless debug_stop_result
    puts "#{debug_stop_result}"
    puts "[-] Error calling DebugActiveProcessStop"
    exit(1)
  end

  if terminate_result != 0
    puts "[-] Error calling NtTerminateProcess. NTSTATUS: 0x#{terminate_result.to_s(16)}"
    exit(1)
  end

  close_handle_proc = Ntdll.NtClose(pi.hProcess)
  close_handle_thread = Ntdll.NtClose(pi.hThread)

  if close_handle_proc != 0 || close_handle_thread != 0
    puts "[-] Error calling NtClose"
    exit(1)
  end

  # Return the buffer pointer
  p_ntdll_buffer
end


# Overwrite hooked ntdll .text section with a clean version
def replace_ntdll_txt_section(unhooked_ntdll_txt : Void*, local_ntdll_txt : Void*, local_ntdll_txt_size : UInt32)
  dw_old_protection = UInt32.new(0)
  current_process = UInt64::MAX # -1_i32 # (HANDLE)(-1) is equivalent to the current process in Windows API
  region_size_ptr = Pointer(UInt64).malloc(1)   # Pointer for UInt64
  region_size_ptr.value = local_ntdll_txt_size
  dw_old_protection = UInt32.new(0)
  
  # NtProtectVirtualMemory to PAGE_EXECUTE_WRITECOPY
  vp_res = Ntdll.NtProtectVirtualMemory(
    current_process, 
    pointerof(local_ntdll_txt), 
    region_size_ptr, 
    PAGE_EXECUTE_WRITECOPY, 
    pointerof(dw_old_protection)
  )
  if vp_res != 0      # != 0
    puts "[-] Error calling NtProtectVirtualMemory (PAGE_EXECUTE_WRITECOPY)"
    exit(1)
  end

  #STDIN.gets
  # Copy from one address to the other
  unhooked = unhooked_ntdll_txt.as(Pointer(UInt8))
  local = local_ntdll_txt.as(Pointer(UInt8))
  local_ntdll_txt_size.times do |i|
    local[i] = unhooked[i]
  end
  #STDIN.gets

  # NtProtectVirtualMemory back to the original protection (PAGE_EXECUTE_READ)
  vp2_res = Ntdll.NtProtectVirtualMemory(
    current_process, 
    pointerof(local_ntdll_txt), 
    region_size_ptr, 
    dw_old_protection, 
    pointerof(dw_old_protection)
  )
  if vp2_res != 0
    puts "[-] Error calling NtProtectVirtualMemory (restoring old protection)"
    exit(1)
  end
end


def remap_library(process_path : String)
  unhookedNtdllTxt = get_ntdll_from_debug_proc(process_path)
  currentProcess = Pointer(Void).new(UInt64::MAX)
  localNtdllHandle = custom_get_module_address(currentProcess, "ntdll.dll")
  result = get_text_section_info(Pointer(Void).new(localNtdllHandle))
  localNtdllTxtBase = result[0]
  localNtdllTxtSize = result[1]
  localNtdllTxt = localNtdllHandle + localNtdllTxtBase
  puts "[+] Replacing 0x#{localNtdllTxtSize.to_s(16)} bytes from 0x#{unhookedNtdllTxt.address.to_s(16)} to 0x#{localNtdllTxt.to_s(16)}"
  replace_ntdll_txt_section(unhookedNtdllTxt.as(Pointer(Void)), Pointer(Void).new(localNtdllTxt), localNtdllTxtSize)
end


def main()
  remap_ntdll = false
  json_name = "lock.json"

  option_parser = OptionParser.new do |parser|
    parser.banner = "Usage: lock [options]"
    parser.on("-j JSON_NAME", "--json_name=JSON_NAME", "JSON file name") do |n|
      json_name = n
    end
    parser.on("-r", "--remap", "Remap library") do
      remap_ntdll = true
    end
    parser.on("-h", "--help", "Print this help message") do
      puts parser
      exit
    end
  end

  option_parser.parse
  if remap_ntdll
    process_path = "C:\\Windows\\System32\\notepad.exe"
    remap_library(process_path)
  end

  lock(json_name)
end


main