using System;
using System.Runtime.InteropServices;
using static Lock.NT;


namespace Lock
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct OSVERSIONINFOEX
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public short wServicePackMajor;
            public short wServicePackMinor;
            public short wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }


        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint RtlGetVersion(ref OSVERSIONINFOEX lpVersionInformation);


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


        static void Lock(string file_name) {
            OSVERSIONINFOEX osVersionInfo = getBuildNumber();
            string[] aux_array = { osVersionInfo.dwMajorVersion.ToString(), osVersionInfo.dwMinorVersion.ToString(), osVersionInfo.dwBuildNumber.ToString() };
            string aux_array_json = ToJson(aux_array);
            string[] aux_array_1 = { aux_array_json };
            string lock_json_content = ToJsonArray(aux_array_1);
            WriteToFile(file_name, lock_json_content);
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

            // Get OS information. Argument: Name of JSON file
            Lock("lock.json");
        }
    }
}