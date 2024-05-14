using System;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Socom2StreamData.Helpers
{
    public class Memory
    {
        /// IMPORTS
        
        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress( IntPtr hModule, string procName );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        /// MEMBERS

        public static bool bAttached;
        public static Process Proc;
        public static int ProcID;
        public static IntPtr ProcHandle;
        public static IntPtr ProcModBase;
        public static Encoding enc8 = Encoding.UTF8;

        /// METHODS
        public static int GetProcID(string pName)
        {
            var processes = Process.GetProcessesByName(pName);
            if (processes.Length <= 0)
                return 0;

            Proc = processes[0];
            return Proc.Id;
        }

        public static IntPtr GetModuleBase()
        {
            if (Proc.Id <= 0)
                return IntPtr.Zero;

            return Proc.Modules[0].BaseAddress;
        }

        public static IntPtr GetAddr(int offset)
        {
            return ProcModBase + offset;
        }

        public static bool Attach(string pName, ProcessAccessFlags flags)
        {
            if (bAttached)
                return false;

            ProcID = GetProcID(pName);
            if (ProcID <= 0)
                return false;

            ProcHandle = OpenProcess(flags, false, ProcID);
            if (ProcHandle.ToInt64() <= 0)
                return false;

            ProcModBase = GetModuleBase();
            if (ProcModBase.ToInt64() <= 0)
                return false;

            bAttached = true;

            return true;
        }

        public static void Detach()
        {
            //  winapi close handle to process
            CloseHandle(ProcHandle);

            ProcID = 0;
            ProcHandle = IntPtr.Zero;
            ProcModBase = IntPtr.Zero;
            bAttached = false;
        }

        public static byte[] ReadBytes(IntPtr addr, int size)
        {
            IntPtr bytesRead;
            byte[] buffer = new byte[size];
            
            bool rpm = ReadProcessMemory(ProcHandle, addr, buffer, size, out bytesRead);
            return buffer;
        }

        public static void WriteBytes(IntPtr addr, byte[] bytes, int size)
        {
            IntPtr bytesWritten;
            byte[] buffer = new byte[size];

            WriteProcessMemory(ProcHandle, addr, buffer, size, out bytesWritten);
        }
    }
}
