using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Socom2StreamData.Helpers
{
    public class Memory
    {
        /// STRUCTS


        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_DOS_HEADER
        {
            public short e_magic;
            public short e_cblp;
            public short e_cp;
            public short e_crlc;
            public short e_cparhdr;
            public short e_minalloc;
            public short e_maxalloc;
            public short e_ss;
            public short e_sp;
            public short e_csum;
            public short e_ip;
            public short e_cs;
            public short e_lfarlc;
            public short e_ovno;
            public short e_res_0;
            public short e_res_1;
            public short e_res_2;
            public short e_res_3;
            public short e_oemid;
            public short e_oeminfo;
            public short e_res2_0;
            public short e_res2_1;
            public short e_res2_2;
            public short e_res2_3;
            public short e_res2_4;
            public short e_res2_5;
            public short e_res2_6;
            public short e_res2_7;
            public short e_res2_8;
            public short e_res2_9;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_NT_HEADERS
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_OPTIONAL_HEADER
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ExportDirectory
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public ExportEntry[] Exports;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ExportEntry
        {
            public uint NameRVA;
            public uint Ordinal;
            public uint AddressOfData;
            public uint ForwarderRVA;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public MemoryProtectionFlags AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        /// IMPORTS


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

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        
        [Flags]
        public enum MemoryProtectionFlags : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        /// MEMBERS

        static bool bAttached;
        static Process Proc;
        static IntPtr ProcHandle;
        static Encoding enc8 = Encoding.UTF8;
        static Encoding encASC = Encoding.ASCII;
        public static int ProcID;
        public static IntPtr ProcModBase;
        public static IntPtr EEmem;

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

            foreach (var mod in Proc.Modules)
            {
                var name = mod.ToString();
                Console.WriteLine($"{name}");
            }
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

            // Define the structs for PE headers
            IMAGE_DOS_HEADER dosHeader;
            IMAGE_NT_HEADERS ntHeader;
            ExportDirectory exportDirectory;

            //  Read DOS header
            dosHeader = ReadStruct<IMAGE_DOS_HEADER>(ProcModBase);

            //  Read PE header
            ntHeader = ReadStruct<IMAGE_NT_HEADERS>(ProcModBase + dosHeader.e_lfanew);

            //  Get the address of the export table
            IntPtr exportTableAddress = (IntPtr)(ProcModBase.ToInt64() + ntHeader.OptionalHeader.DataDirectory[2].VirtualAddress);

            //  Read the export table
            exportDirectory = ReadStruct<ExportDirectory>(exportTableAddress);

            //  Find EEMem
            uint[] namesRvaArray = ReadArray<uint>((IntPtr)(ProcModBase.ToInt64() + exportDirectory.AddressOfNames), (int)exportDirectory.NumberOfNames);
            uint[] functionsRvaArray = ReadArray<uint>((IntPtr)(ProcModBase.ToInt64() + exportDirectory.AddressOfFunctions), (int)exportDirectory.NumberOfFunctions);
            ushort[] nameOrdinalsArray = ReadArray<ushort>((IntPtr)(ProcModBase.ToInt64() + exportDirectory.AddressOfNameOrdinals), (int)exportDirectory.NumberOfNames);

            //  Iterate names in names array
            uint rva;
            int index = -1;
            foreach (uint nameRva in namesRvaArray)
            {
                index++;
                string currentFunctionName = ReadString((IntPtr)(ProcModBase.ToInt64() + nameRva));
                if (currentFunctionName == "EEmem")
                {
                    rva = nameRva;
                    break;
                }
            }

            uint functionRva = functionsRvaArray[nameOrdinalsArray[index]];
            if (functionRva <= 0)
                return false;

            IntPtr functionAddress = (IntPtr)(ProcModBase.ToInt64() + functionRva);
            if (functionAddress.ToInt64() <= 0)
                return false;

            EEmem = functionAddress;

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

        //  obtains memory protection for the specified address
        public static MemoryProtectionFlags GetMemoryProtection(IntPtr addr)
        {
            MEMORY_BASIC_INFORMATION memoryInfo;
            if (VirtualQueryEx(ProcHandle, addr, out memoryInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == IntPtr.Zero)
            {
                // Failed to query memory information
                throw new InvalidOperationException("Failed to query memory information.");
            }

            return memoryInfo.Protect == 0 ? 0 : (MemoryProtectionFlags)memoryInfo.Protect;
        }

        //  modifies memory protection for the specified address
        public static bool ChangeMemoryProtection(IntPtr addr, IntPtr size, uint newProtection, out uint oldProtect)
        {
            return VirtualProtectEx(ProcHandle, addr, size, newProtection, out oldProtect);
        }

        //  Reads bytes from the specified address in memory
        public static byte[] ReadBytes(IntPtr addr, int size)
        {
            IntPtr bytesRead;
            byte[] buffer = new byte[size];
            
            bool rpm = ReadProcessMemory(ProcHandle, addr, buffer, size, out bytesRead);
            return buffer;
        }

        //  Reads an array of members at the specified address in memory
        public static T[] ReadArray<T>(IntPtr addr, int size) where T : struct
        {
            byte[] buffer = new byte[Marshal.SizeOf(typeof(T)) * size];
            IntPtr bytesRead;
            ReadProcessMemory(ProcHandle, addr, buffer, buffer.Length, out bytesRead);

            if (bytesRead.ToInt32() != buffer.Length)
            {
                throw new Exception($"Failed to read array from process memory at address {addr}");
            }

            T[] result = new T[size];
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            for (int i = 0; i < size; i++)
            {
                Marshal.Copy(buffer, i * Marshal.SizeOf(typeof(T)), ptr, Marshal.SizeOf(typeof(T))); 
                result[i] = Marshal.PtrToStructure<T>(ptr);
            }

            return result;
        }

        // Reads a null-terminated string from memory
        public static string ReadString(IntPtr addr)
        {
            List<byte> bytes = new List<byte>();
            byte currentByte;
            int bytesRead = 0;

            do
            {
                byte[] buf = ReadBytes(addr + bytesRead, 1);
                currentByte = buf[0];
                if (currentByte != 0)
                {
                    bytes.Add(currentByte);
                    bytesRead++;
                }
            } while (currentByte != 0);
            return Encoding.ASCII.GetString(bytes.ToArray());
        }

        //  Reads memory at the specified address and transforms the result into the input structure
        public static T ReadStruct<T>(IntPtr addr) where T : struct
        {
            int structSize = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[structSize];

            IntPtr bytesRead;
            if (!ReadProcessMemory(ProcHandle, addr, buffer, structSize, out bytesRead))
            {
                throw new Exception("Failed to read process memory.");
            }

            if (bytesRead.ToInt64() != structSize)
            {
                throw new Exception($"Failed to read struct from process memory at address {addr}");
            }

            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            }
            finally
            {
                handle.Free();
            }
        }

        //  Template read memory
        public static T ReadMemory<T>(IntPtr addr) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            byte[] buffer = new byte[size];
            IntPtr bytesRead;

            if (!ReadProcessMemory(ProcHandle, addr, buffer, size, out bytesRead))
            {
                throw new Exception("Failed to read process memory.");
            }

            if (bytesRead.ToInt32() != size)
            {
                throw new Exception($"Failed to read {size} bytes from process memory. Only {bytesRead} bytes read.");
            }

            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            }
            finally
            {
                handle.Free();
            }
        }

        public static void WriteBytes(IntPtr addr, byte[] bytes, int size)
        {
            IntPtr bytesWritten;
            byte[] buffer = new byte[size];

            WriteProcessMemory(ProcHandle, addr, buffer, size, out bytesWritten);
        }

        public static void WriteMemory<T>(IntPtr addr, T value) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            byte[] buffer = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(value, ptr, false);
                Marshal.Copy(ptr, buffer, 0, size);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            IntPtr bytesWritten;

            if (!WriteProcessMemory(ProcHandle, addr, buffer, size, out bytesWritten))
            {
                throw new Exception("Failed to write process memory.");
            }

            if (bytesWritten.ToInt32() != size)
            {
                throw new Exception($"Failed to write {size} bytes to process memory. Only {bytesWritten} bytes written.");
            }
        }

    }
}
