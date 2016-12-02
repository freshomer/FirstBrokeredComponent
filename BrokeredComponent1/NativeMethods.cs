using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace BrokeredComponent1
{
    #region NativeMethods
    internal sealed class SafeUserTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeUserTokenHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(base.handle);
        }
    }

    internal static class NativeMethods
    {

        [DllImport("user32.dll")]
        internal static extern bool CloseWindow(IntPtr hWnd);
        #region Impersonation

        internal const int LOGON32_PROVIDER_DEFAULT = 0;
        internal const int LOGON32_LOGON_INTERACTIVE = 2;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LogonUser([MarshalAs(UnmanagedType.LPWStr)]string lpszUsername,
                                              [MarshalAs(UnmanagedType.LPWStr)]string lpszDomain,
                                              [MarshalAs(UnmanagedType.LPWStr)]string lpszPassword,
                                              int dwLogonType,
                                              int dwLogonProvider,
                                              out SafeUserTokenHandle phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);

        #endregion

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int LoadString(SafeFileHandle hInstance, int uID, StringBuilder lpBuffer, int nBufferMax);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "LoadStringW")]
        public static extern int LoadString(IntPtr hInstance, uint uID, [Out] StringBuilder lpBuffer, int nBufferMax);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeFileHandle LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr LoadLibrary(string stModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void FreeLibrary(SafeFileHandle hModule);

        [DllImport("kernel32.dll", EntryPoint = "FreeLibrary")]
        public static extern int FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", EntryPoint = "GetLastError")]
        public static extern int GetLastError();


        /// <summary>
        /// This is the native windows CreateProcess Method
        /// http://msdn.microsoft.com/en-us/library/ms682425(VS.85).aspx
        /// </summary>
        /// <param name="lpApplicationName">Name of the module to be executed</param>
        /// <param name="lpCommandLine">The command line to be executed</param>
        /// <param name="lpProcessAttributes">A pointer to SECURITY_ATTRIBUTES structure</param>
        /// <param name="lpThreadAttributes">A pointer to SECURITY_ATTRIBUTES structure</param>
        /// <param name="bInheritHandles">If True each inheritable handle in calling process is inherited by the new process</param>
        /// <param name="dwCreationFlags">The flags that control the priority class of the process</param>
        /// <param name="lpEnviroment">Pointer to the enviroment block for the new process</param>
        /// <param name="lpCurrentDirectory">Full path to the current directory of the process</param>
        /// <param name="lpStartupInfo">Pointer to STARTUPINFO structure</param>
        /// <param name="lpProcessInformation">Pointer to PROCESS_INFORMATION structure</param>
        /// <returns></returns>
        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnviroment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]

        /*UInt32 CommandCtrlC = 0;
        bool result = ClientPlatform.NativeMethods.GenerateConsoleCtrlEvent(CommandCtrlC,
        Convert.ToUInt32(syncProcess.Id));*/
        public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent,
            uint dwProcessGroupId);
        [DllImport("kernel32.dll")]
        public static extern bool FreeConsole();

        [DllImport("kernel32.dll")]
        public static extern bool AttachConsole(int dwProcessId);


        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern bool CreateHardLink(
            string lpFileName,
            string lpExistingFileName,
            IntPtr lpSecurityAttributes
        );


        /// <summary>
        /// This is the STARTUPINFO struct used
        /// in the native CreateProcess method
        /// </summary>
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        /// <summary>
        /// This is the PROCESS_INFORMATION struct
        /// used in the native CreateProcess method
        /// </summary>
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public static Type m_type = Type.GetTypeFromProgID("WScript.Shell");
        public static object m_shell = Activator.CreateInstance(m_type);

        [ComImport, TypeLibType((short)0x1040), Guid("F935DC23-1CF0-11D0-ADB9-00C04FD58A0B")]
        public interface IWshShortcut
        {
            [DispId(0)]
            string FullName { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0)] get; }
            [DispId(0x3e8)]
            string Arguments { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3e8)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3e8)] set; }
            [DispId(0x3e9)]
            string Description { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3e9)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3e9)] set; }
            [DispId(0x3ea)]
            string Hotkey { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3ea)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ea)] set; }
            [DispId(0x3eb)]
            string IconLocation { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3eb)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3eb)] set; }
            [DispId(0x3ec)]
            string RelativePath { [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ec)] set; }
            [DispId(0x3ed)]
            string TargetPath { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3ed)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ed)] set; }
            [DispId(0x3ee)]
            int WindowStyle { [DispId(0x3ee)] get; [param: In] [DispId(0x3ee)] set; }
            [DispId(0x3ef)]
            string WorkingDirectory { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3ef)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ef)] set; }
            [TypeLibFunc((short)0x40), DispId(0x7d0)]
            void Load([In, MarshalAs(UnmanagedType.BStr)] string PathLink);
            [DispId(0x7d1)]
            void Save();
        }

        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredDelete(
            [In] string target,
            [In] CRED_TYPE type,
            [In] UInt32 flags);

        public enum CRED_TYPE : uint
        {
            CRED_TYPE_GENERIC = 1,
            CRED_TYPE_DOMAIN_PASSWORD = 2,
            CRED_TYPE_DOMAIN_CERTIFICATE = 3,
            CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4
        }

        public enum RpcAuthnLevel
        {
            Default = 0,
            None = 1,
            Connect = 2,
            Call = 3,
            Pkt = 4,
            PktIntegrity = 5,
            PktPrivacy = 6
        }


        public enum RpcImpLevel
        {
            Default = 0,
            Anonymous = 1,
            Identify = 2,
            Impersonate = 3,
            Delegate = 4
        }

        public enum EoAuthnCap
        {
            None = 0x00,
            MutualAuth = 0x01,
            StaticCloaking = 0x20,
            DynamicCloaking = 0x40,
            AnyAuthority = 0x80,
            MakeFullSIC = 0x100,
            Default = 0x800,
            SecureRefs = 0x02,
            AccessControl = 0x04,
            AppID = 0x08,
            Dynamic = 0x10,
            RequireFullSIC = 0x200,
            AutoImpersonate = 0x400,
            NoCustomMarshal = 0x2000,
            DisableAAA = 0x1000
        }

        [System.Runtime.InteropServices.DllImport("ole32.dll")]
        public static extern int CoInitializeSecurity(IntPtr pVoid, int
            cAuthSvc, IntPtr asAuthSvc, IntPtr pReserved1, RpcAuthnLevel level,
            RpcImpLevel impers, IntPtr pAuthList, EoAuthnCap dwCapabilities, IntPtr
            pReserved3);


        [DllImport("ole32.DLL", CharSet = CharSet.Auto)]
        public static extern uint CoSetProxyBlanket(
                                              IntPtr pProxy,
                                              uint dwAuthnSvc,
                                              uint dwAuthzSvc,
                                              //IntPtr pServerPrincName,
                                              string pServerPrincName,
                                              //uint dwAuthnLevel,
                                              RpcAuthnLevel dwAuthnLevel,
                                              RpcImpLevel dwImpLevel,
                                              IntPtr pAuthInfo,
                                              uint dwCapababilities);


        public const uint RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF;
        public const uint RPC_C_AUTHZ_DEFAULT = 0xFFFFFFFF;
        public const uint RPC_C_AUTHZ_NONE = 0;
        public const uint RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;
        public const uint RPC_C_IMP_LEVEL_DEFAULT = 0;
        public const uint COLE_DEFAULT_AUTHINFO = 0xFFFFFFFF;
        public const uint COLE_DEFAULT_PRINCIPAL = 0;
        public const uint EOAC_DEFAULT = 0x800;


        #region Credentials

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct Credential
        {
            public UInt32 flags;
            public UInt32 type;
            public string targetName;
            public string comment;
            //public System.Runtime.InteropServices.FILETIME lastWritten; // .NET 1.1
            public System.Runtime.InteropServices.ComTypes.FILETIME lastWritten; // .NET 2.0
            public UInt32 credentialBlobSize;
            //public IntPtr credentialBlob;
            public byte[] credentialBlob;
            public UInt32 persist;
            public UInt32 attributeCount;
            public IntPtr credAttribute;
            public string targetAlias;
            public string userName;
        }

        [DllImport("credui.dll", EntryPoint = "CredUnPackAuthenticationBufferW", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredUnPackAuthenticationBuffer(
            [In] UInt32 flags,
            [In] IntPtr authBuffer,
            //[In] byte[] authBuffer,
            [In] UInt32 authBufferSize,
            [Out] StringBuilder userName,
            [In, Out] ref UInt32 maxUserName,
            [Out] StringBuilder domainName,
            [In, Out] ref UInt32 maxDomainame,
            [Out] StringBuilder password,
            [In, Out] ref UInt32 maxPassword);


        [DllImport("credui.dll", EntryPoint = "CredPackAuthenticationBufferW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredPackAuthenticationBuffer(
            [In] UInt32 flags,
            [In] string userName,
            [In] string password,
            [Out] byte[] packedCredentials,
            [In, Out] ref UInt32 packedLength);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
        public static extern bool CredWrite([In] ref Credential userCredential, [In] UInt32 flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern void CredFree([In] IntPtr buffer);

        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CredRead(
            [In] string target,
            [In] CRED_TYPE type,
            [In] UInt32 reservedFlag,
            [Out] out IntPtr credential);


        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEMTIME
        {
            [MarshalAs(UnmanagedType.U2)]
            public short Year;
            [MarshalAs(UnmanagedType.U2)]
            public short Month;
            [MarshalAs(UnmanagedType.U2)]
            public short DayOfWeek;
            [MarshalAs(UnmanagedType.U2)]
            public short Day;
            [MarshalAs(UnmanagedType.U2)]
            public short Hour;
            [MarshalAs(UnmanagedType.U2)]
            public short Minute;
            [MarshalAs(UnmanagedType.U2)]
            public short Second;
            [MarshalAs(UnmanagedType.U2)]
            public short Milliseconds;

            public SYSTEMTIME(DateTime dt)
            {
                dt = dt.ToUniversalTime();  // SetSystemTime expects the SYSTEMTIME in UTC
                Year = (short)dt.Year;
                Month = (short)dt.Month;
                DayOfWeek = (short)dt.DayOfWeek;
                Day = (short)dt.Day;
                Hour = (short)dt.Hour;
                Minute = (short)dt.Minute;
                Second = (short)dt.Second;
                Milliseconds = (short)dt.Millisecond;
            }
        }

        [DllImport("kernel32.dll")]
        public static extern bool SystemTimeToTzSpecificLocalTime(IntPtr
           lpTimeZoneInformation, [In] ref SYSTEMTIME lpUniversalTime,
           out SYSTEMTIME lpLocalTime);



        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi,
                 SetLastError = true)]
        public static extern bool FileTimeToSystemTime([In] ref System.Runtime.InteropServices.ComTypes.FILETIME lpFileTime,
            out SYSTEMTIME lpSystemTime);


        #endregion


        #region SystemParametersInfo

        // Signatures for unmanaged calls
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern bool SystemParametersInfo(
           int uAction, int uParam, ref int lpvParam,
           int flags);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern bool SystemParametersInfo(
           int uAction, int uParam, ref bool lpvParam,
           int flags);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern bool SystemParametersInfo(
           int uAction, bool uParam, ref int lpvParam,
           int flags);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int PostMessage(IntPtr hWnd,
           int wMsg, int wParam, int lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr OpenDesktop(
           string hDesktop, int Flags, bool Inherit,
           uint DesiredAccess);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern bool CloseDesktop(
           IntPtr hDesktop);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern bool EnumDesktopWindows(
           IntPtr hDesktop, EnumDesktopWindowsProc callback,
           IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern bool IsWindowVisible(
           IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        [DllImport("user32")]
        public static extern bool LockWorkStation();

        // Callbacks
        public delegate bool EnumDesktopWindowsProc(
           IntPtr hDesktop, IntPtr lParam);

        // Constants
        public const int SPI_GETSCREENSAVERACTIVE = 16;
        public const int SPI_SETSCREENSAVERACTIVE = 17;
        public const int SPI_GETSCREENSAVERTIMEOUT = 14;
        public const int SPI_SETSCREENSAVERTIMEOUT = 15;
        public const int SPI_GETSCREENSAVERRUNNING = 114;
        public const int SPI_SETSCREENSAVESECURE = 119;
        public const int SPI_GETSCREENSAVESECURE = 118;
        public const int SPIF_SENDWININICHANGE = 2;

        public const uint DESKTOP_WRITEOBJECTS = 0x0080;
        public const uint DESKTOP_READOBJECTS = 0x0001;
        public const int WM_CLOSE = 16;


        #endregion

    }

    #endregion

}
