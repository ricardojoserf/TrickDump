using System;
using System.Runtime.InteropServices;

namespace Shock
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr LoadLibrary(string lpFileName);
        [DllImport("ntdll.dll")] public static extern uint NtQueryVirtualMemory(IntPtr hProcess, IntPtr lpAddress, uint MemoryInformationClass, out MEMORY_BASIC_INFORMATION MemoryInformation, uint MemoryInformationLength, out uint ReturnLength);
        [StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION { public IntPtr BaseAddress; public IntPtr AllocationBase; public int AllocationProtect; public IntPtr RegionSize; public int State; public int Protect; public int Type; }


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


        static void Main(string[] args)
        {
            // Get library address
            IntPtr lsasrv_addr = LoadLibrary("lsasrv.dll");

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
            string file_name = "shock.json";
            WriteToFile(file_name, shock_json_content);
        }
    }
}