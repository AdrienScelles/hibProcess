//**************************** BaseAddressLib ****************************
//************************************************************************
//**************************author:adrien scelles*************************
//*********************contact:adrienscelles@gmail.com********************
//************************************************************************
using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using System.IO;

namespace hibProcesses
{
    //------------------------------------------------------------------------
    //------------------------------- Statics -------------------------------
    //------------------------------------------------------------------------
    /// <summary>
    /// Import
    /// </summary>
    public static class Import
    {
        //Open/Close Process handle
        #region Function - OpenProcess

        /// <summary>
        /// Open process for external manipulation.
        /// </summary>
        /// <param name="dwDesiredAccess">The desired access to the external program.</param>
        /// <param name="bInheritHandle">Whether or not we wish to inherit a handle.</param>
        /// <param name="dwProcessId">The unique process ID of the external program.</param>
        /// <returns>Returns a process handle used in memory manipulation.</returns>
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)]bool bInheritHandle, int dwProcessId);

        #endregion Function - OpenProcess
        #region Enum - ProcessAccessFlags

        [Flags]
        /// <summary>
        /// Set Acces flags to OpenProcess
        /// </summary>
        public enum ProcessAccessFlags : uint
        {
            /// <summary>
            /// All Acess
            /// </summary>
            All = 0x001F0FFF,
            /// <summary>
            /// Terminate Process
            /// </summary>
            Terminate = 0x00000001,
            /// <summary>
            /// Create Thread
            /// </summary>
            CreateThread = 0x00000002,
            /// <summary>
            /// Virtual Memory Operation
            /// </summary>
            VMOperation = 0x00000008,
            /// <summary>
            /// Virtual Memory Reading
            /// </summary>
            VMRead = 0x00000010,
            /// <summary>
            /// Virtual Memory Writing
            /// </summary>
            VMWrite = 0x00000020,
            /// <summary>
            /// Dup Handle
            /// </summary>
            DupHandle = 0x00000040,
            /// <summary>
            /// Set Information
            /// </summary>
            SetInformation = 0x00000200,
            /// <summary>
            /// Query Information
            /// </summary>
            QueryInformation = 0x00000400,
            /// <summary>
            /// Synchronize
            /// </summary>
            Synchronize = 0x00100000
        }

        #endregion Enum - ProcessAccessFlags (kernel32)
        #region Function - CloseHandle

        /// <summary>
        /// Closes an open object handle.
        /// </summary>
        /// <param name="hObject">The object handle we wish to close.</param>
        /// <returns>Returns non-zero if success, zero if failure.</returns>
        [DllImport("kernel32.dll")]
        public static extern Int32 CloseHandle(IntPtr hObject);

        #endregion Function - CloseHandle
        #region Function - GetCurrentProcess

        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();

        #endregion Function - GetCurrentProcess
        #region Function - IsWow64Process

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr processHandle, [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        #endregion Function - IsWow64Process

        //Tokens
        #region Old
        //public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        //public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        //public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
        //public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
        //public const int ERROR_SUCCESS = 0x0;
        //public const int ERROR_ACCESS_DENIED = 0x5;
        //public const int ERROR_NOT_ENOUGH_MEMORY = 0x8;
        //public const int ERROR_NO_TOKEN = 0x3f0;
        //public const int ERROR_NOT_ALL_ASSIGNED = 0x514;
        //public const int ERROR_NO_SUCH_PRIVILEGE = 0x521;
        //public const int ERROR_CANT_OPEN_ANONYMOUS = 0x543;
        //public static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        //public static uint STANDARD_RIGHTS_READ = 0x00020000;
        //public static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        //public static uint TOKEN_DUPLICATE = 0x0002;
        //public static uint TOKEN_IMPERSONATE = 0x0004;
        //public static uint TOKEN_QUERY = 0x0008;
        //public static uint TOKEN_QUERY_SOURCE = 0x0010;
        //public static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        //public static uint TOKEN_ADJUST_GROUPS = 0x0040;
        //public static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        //public static uint TOKEN_ADJUST_SESSIONID = 0x0100;
        //public static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        //public static uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
        //    TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
        //    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
        //    TOKEN_ADJUST_SESSIONID);
        //public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        //public const string SE_AUDIT_NAME = "SeAuditPrivilege";
        //public const string SE_BACKUP_NAME = "SeBackupPrivilege";
        //public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
        //public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
        //public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
        //public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
        //public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";
        //public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
        //public const string SE_DEBUG_NAME = "SeDebugPrivilege";
        //public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
        //public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
        //public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
        //public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        //public const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
        //public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
        //public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
        //public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
        //public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
        //public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
        //public const string SE_RELABEL_NAME = "SeRelabelPrivilege";
        //public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
        //public const string SE_RESTORE_NAME = "SeRestorePrivilege";
        //public const string SE_SECURITY_NAME = "SeSecurityPrivilege";
        //public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        //public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
        //public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
        //public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
        //public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
        //public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
        //public const string SE_TCB_NAME = "SeTcbPrivilege";
        //public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
        //public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
        //public const string SE_UNDOCK_NAME = "SeUndockPrivilege";
        //public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";
        //#region Function - OpenProcessToken

        //[DllImport("advapi32.dll", SetLastError = true)]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //public static extern bool OpenProcessToken(IntPtr ProcessHandle,
        //    UInt32 DesiredAccess, out IntPtr TokenHandle);

        //#endregion Function - OpenProcessToken
        //#region Function - LookupPrivilegeValue

        //[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName,
        //    out LUID lpLuid);

        //#endregion Function - LookupPrivilegeValue
        //#region Function - AdjustTokenPrivileges

        //// Use this signature if you do not want the previous state
        //[DllImport("advapi32.dll", SetLastError = true)]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
        //   [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
        //   ref TOKEN_PRIVILEGES NewState,
        //   UInt32 Zero,
        //   IntPtr Null1,
        //   IntPtr Null2);

        //#endregion Function - AdjustTokenPrivileges
        //#region Struct - LUID

        //[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        //public struct LUID
        //{
        //    internal uint LowPart;
        //    internal uint HighPart;
        //}

        //#endregion Struct - LUID
        //#region Struct - LUID_AND_ATTRIBUTES

        //[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        //public struct LUID_AND_ATTRIBUTES
        //{
        //    internal LUID Luid;
        //    internal uint Attributes;
        //}

        //#endregion Struct - LUID_AND_ATTRIBUTES
        //#region Struct - TOKEN_PRIVILEGE

        //[StructLayout(LayoutKind.Sequential)]
        //public struct TOKEN_PRIVILEGES
        //{
        //    public UInt32 PrivilegeCount;
        //    public LUID Luid;
        //    public UInt32 Attributes;
        //}

        //#endregion Struct - TOKEN_PRIVILEGE
        #endregion Old
        public const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int TOKEN_QUERY = 0x00000008;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        #region Function - OpenProcessToken

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
        phtok);

        #endregion Function - OpenProcessToken
        #region Function - LookupPrivilegeValue

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string host, string name,
        ref long pluid);

        #endregion Function - LookupPrivilegeValue
        #region Function - AdjustTokenPrivileges

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
        ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        #endregion Function - AdjustTokenPrivileges
        #region Struct - TokPriv1Luid

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        #endregion Struct - TokPriv1Luid


        //Threads
        #region Function - CreateRemoteThread (kernel32)

        /// <summary>
        /// Creates a thread that runs in the virtual address space of another process.
        /// </summary>
        /// <param name="hProcess">A handle to the process in which the thread is to be created.</param>
        /// <param name="lpThreadAttributes">A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new thread and determines whether child processes can inherit the returned handle. If lpThreadAttributes is NULL, the thread gets a default security descriptor and the handle cannot be inherited.</param>
        /// <param name="dwStackSize">The initial size of the stack, in bytes. The system rounds this value to the nearest page. If this parameter is 0 (zero), the new thread uses the default size for the executable.</param>
        /// <param name="lpStartAddress">A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread and represents the starting address of the thread in the remote process. The function must exist in the remote process.</param>
        /// <param name="lpParameter">A pointer to a variable to be passed to the thread function.</param>
        /// <param name="dwCreationFlags">The flags that control the creation of the thread.</param>
        /// <param name="dwThreadId">A pointer to a variable that receives the thread identifier.</param>
        /// <returns>If the function succeeds, the return value is a handle to the new thread.  If the function fails, the return value is IntPtr.Zero.</returns>
        [DllImport("kernel32", EntryPoint = "CreateRemoteThread")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            ThreadCreationFlags dwCreationFlags,
            out IntPtr dwThreadId);

        #endregion Function - CreateRemoteThread (kernel32)
        #region Enum - ThreadCreationFlags (kernel32)

        /// <summary>
        /// Values which determine the state or creation-state of a thread.
        /// </summary>
        public enum ThreadCreationFlags : uint
        {
            /// <summary>
            /// The thread will execute immediately.
            /// </summary>
            THREAD_EXECUTE_IMMEDIATELY = 0x00,
            /// <summary>
            /// The thread will be created in a suspended state.  Use <see cref="Imports.ResumeThread"/> to resume the thread.
            /// </summary>
            CREATE_SUSPENDED = 0x04,
            /// <summary>
            /// The dwStackSize parameter specifies the initial reserve size of the stack. If this flag is not specified, dwStackSize specifies the commit size.
            /// </summary>
            STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000,
            /// <summary>
            /// The thread is still active.
            /// </summary>
            STILL_ACTIVE = 259,
        }

        #endregion Enum - ThreadCreationFlags (kernel32)
        #region Function - WaitForSingleObject (kernel32)

        /// <summary>
        /// Waits until the specified object is in the signaled state or the time-out interval elapses.
        /// </summary>
        /// <param name="hObject">A handle to the object. For a list of the object types whose handles can be specified, see the following Remarks section.</param>
        /// <param name="dwMilliseconds">The time-out interval, in milliseconds. The function returns if the interval elapses, even if the object's state is nonsignaled. If dwMilliseconds is zero, the function tests the object's state and returns immediately. If dwMilliseconds is INFINITE, the function's time-out interval never elapses.</param>
        /// <returns>If the function succeeds, the return value indicates the event that caused the function to return. If the function fails, the return value is WAIT_FAILED ((DWORD)0xFFFFFFFF).</returns>
        [DllImport("kernel32", EntryPoint = "WaitForSingleObject")]
        public static extern WaitResult WaitForSingleObject(IntPtr hObject, uint dwMilliseconds);

        #endregion Function - WaitForSingleObject (kernel32)
        #region Enum - WaitValues (kernel32)

        /// <summary>
        /// Values that determine the wait status of an object (thread, mutex, event, etc.).
        /// </summary>
        public enum WaitResult : uint
        {
            /// <summary>
            /// The object is in a signaled state.
            /// </summary>
            WAIT_OBJECT_0 = 0x00000000,
            /// <summary>
            /// The specified object is a mutex object that was not released by the thread that owned the mutex object before the owning thread terminated. Ownership of the mutex object is granted to the calling thread, and the mutex is set to nonsignaled.
            /// </summary>
            WAIT_ABANDONED = 0x00000080,
            /// <summary>
            /// The time-out interval elapsed, and the object's state is nonsignaled.
            /// </summary>
            WAIT_TIMEOUT = 0x00000102,
            /// <summary>
            /// The wait has failed.
            /// </summary>
            WAIT_FAILED = 0xFFFFFFFF,
        }

        #endregion Enum - WaitValues (kernel32)
        #region Function - GetExitCodeThread (kernel32)

        /// <summary>
        /// Retrieves the termination status of the specified thread.
        /// </summary>
        /// <param name="hThread">A handle to the thread.</param>
        /// <param name="lpExitCode">[Out] The exit code of the thread.</param>
        /// <returns>A pointer to a variable to receive the thread termination status.For more information.</returns>
        [DllImport("kernel32", EntryPoint = "GetExitCodeThread")]
        public static extern bool GetExitCodeThread(IntPtr hThread, out UIntPtr lpExitCode);

        #endregion Function - GetExitCodeThread(kernel32)
        #region Function - OpenThread (kernel32)

        /// <summary>
        /// Opens an existing thread object.
        /// </summary>
        /// <param name="dwDesiredAccess">The access to the thread object. This access right is checked against the security descriptor for the thread. This parameter can be one or more of the thread access rights.</param>
        /// <param name="bInheritHandle">If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.</param>
        /// <param name="dwThreadId">The identifier of the thread to be opened.</param>
        /// <returns>
        /// If the function succeeds, the return value is an open handle to the specified thread.
        /// 
        /// If the function fails, the return value is NULL.
        /// </returns>
        [DllImport("kernel32", EntryPoint = "OpenThread")]
        public static extern IntPtr OpenThread(ThreadAccessFlags dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        #endregion Function - OpenThread (kernel32)
        #region Enum - ThreadAccessFlags (kernel32)

        /// <summary>
        /// Values to gain required access to a thread.
        /// </summary>
        public enum ThreadAccessFlags : uint
        {
            /// <summary>
            /// Standard rights required to mess with an object's security descriptor, change, or delete the object.
            /// </summary>
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            /// <summary>
            /// The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state. Some object types do not support this access right.
            /// </summary>
            SYNCHRONIZE = 0x00100000,
            /// <summary>
            /// Required to terminate a thread using TerminateThread.
            /// </summary>
            THREAD_TERMINATE = 0x0001,
            /// <summary>
            /// Required to suspend or resume a thread.
            /// </summary>
            THREAD_SUSPEND_RESUME = 0x0002,
            /// <summary>
            /// Required to read the context of a thread using <see cref="Imports.GetThreadContext"/>
            /// </summary>
            THREAD_GET_CONTEXT = 0x0008,
            /// <summary>
            /// Required to set the context of a thread using <see cref="Imports.SetThreadContext"/>
            /// </summary>
            THREAD_SET_CONTEXT = 0x0010,
            /// <summary>
            /// Required to read certain information from the thread object, such as the exit code (see GetExitCodeThread).
            /// </summary>
            THREAD_QUERY_INFORMATION = 0x0040,
            /// <summary>
            /// Required to set certain information in the thread object.
            /// </summary>
            THREAD_SET_INFORMATION = 0x0020,
            /// <summary>
            /// Required to set the impersonation token for a thread using SetThreadToken.
            /// </summary>
            THREAD_SET_THREAD_TOKEN = 0x0080,
            /// <summary>
            /// Required to use a thread's security information directly without calling it by using a communication mechanism that provides impersonation services.
            /// </summary>
            THREAD_IMPERSONATE = 0x0100,
            /// <summary>
            /// Required for a server thread that impersonates a client.
            /// </summary>
            THREAD_DIRECT_IMPERSONATION = 0x0200,

            /// <summary>
            /// All possible access rights for a thread object.
            /// </summary>
            THREAD_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF,
        }

        #endregion Enum - ThreadAccessFlags (kernel32)
        #region Function - SuspendThread (kernel32)

        /// <summary>
        /// Suspends execution of a given thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread that will be suspended.</param>
        /// <returns>Returns (DWORD)-1 on failure, otherwise the suspend count of the thread.</returns>
        [DllImport("kernel32", EntryPoint = "SuspendThread")]
        public static extern uint SuspendThread(IntPtr hThread);

        #endregion Function - SuspendThread (kernel32)
        #region Function - ResumeThread (kernel32)

        /// <summary>
        /// Resumes execution of a given thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread that will be suspended.</param>
        /// <returns>Returns (DWORD)-1 on failure, otherwise the previous suspend count of the thread.</returns>
        [DllImport("kernel32", EntryPoint = "ResumeThread")]
        public static extern uint ResumeThread(IntPtr hThread);

        #endregion Function - ResumeThread (kernel32)
        #region Function - TerminateThread (kernel32)

        /// <summary>
        /// Terminates the specified thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread to exit.</param>
        /// <param name="dwExitCode">Exit code that will be stored in the thread object.</param>
        /// <returns>Returns zero on failure, non-zero on success.</returns>
        [DllImport("kernel32", EntryPoint = "TerminateThread")]
        public static extern uint TerminateThread(IntPtr hThread, uint dwExitCode);

        #endregion Function - TerminateThread (kernel32)
        #region Function - GetThreadContext (kernel32)

        /// <summary>
        /// Gets the context of a given thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread for which the context will be returned.</param>
        /// <param name="lpContext">CONTEXT structure into which context will be read</param>
        /// <returns>Returns true on success, false on failure.</returns>
        [DllImport("kernel32", EntryPoint = "GetThreadContext")]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        #endregion Function - GetThreadContext (kernel32)
        #region Function - SetThreadContext (kernel32)

        /// <summary>
        /// Sets the context of a given thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread for which the context will be set.</param>
        /// <param name="lpContext">CONTEXT structure to which the thread's context will be set.</param>
        /// <returns>Returns true on success, false on failure.</returns>
        [DllImport("kernel32", EntryPoint = "SetThreadContext")]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        #endregion Function - SetThreadContext (kernel32)
        #region Struct - CONTEXT (kernel32)

        /// <summary>
        /// Used for getting or setting a thread's context.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            ///<summary>
            /// The flags values within this flag control the contents of a CONTEXT record.
            ///
            /// If the context record is used as an input parameter, then for each portion of the context record controlled by a flag whose value is set, it is assumed that that portion of the context record contains valid context. If the context record is being used to modify a threads context, then only that portion of the threads context will be modified.
            ///
            /// If the context record is used as an IN OUT parameter to capture the context of a thread, then only those portions of the thread's context corresponding to set flags will be returned.
            ///
            /// The context record is never used as an OUT only parameter.
            /// </summary>
            public uint ContextFlags;


            /// <summary>
            /// Specified/returned if <see cref="CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS"/> flag is set.
            /// </summary>
            public uint Dr0;
            /// <summary>
            /// Specified/returned if <see cref="CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS"/> flag is set.
            /// </summary>
            public uint Dr1;
            /// <summary>
            /// Specified/returned if <see cref="CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS"/> flag is set.
            /// </summary>
            public uint Dr2;
            /// <summary>
            /// Specified/returned if <see cref="CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS"/> flag is set.
            /// </summary>
            public uint Dr3;
            /// <summary>
            /// Specified/returned if <see cref="CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS"/> flag is set.
            /// </summary>
            public uint Dr6;
            /// <summary>
            /// Specified/returned if <see cref="CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS"/> flag is set.
            /// </summary>
            public uint Dr7;


            /// <summary>
            /// This section is specified/returned if the ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
            /// </summary>
            [MarshalAs(UnmanagedType.Struct)]
            public FLOATING_SAVE_AREA FloatSave;


            /// <summary>
            /// This is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_SEGMENTS"/>.
            /// </summary>
            public uint SegGs;
            /// <summary>
            /// This is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_SEGMENTS"/>.
            /// </summary>
            public uint SegFs;
            /// <summary>
            /// This is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_SEGMENTS"/>.
            /// </summary>
            public uint SegEs;
            /// <summary>
            /// This is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_SEGMENTS"/>.
            /// </summary>
            public uint SegDs;


            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_INTEGER"/>.
            /// </summary>
            public uint Edi;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_INTEGER"/>.
            /// </summary>
            public uint Esi;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_INTEGER"/>.
            /// </summary>
            public uint Ebx;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_INTEGER"/>.
            /// </summary>
            public uint Edx;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_INTEGER"/>.
            /// </summary>
            public uint Ecx;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_INTEGER"/>.
            /// </summary>
            public uint Eax;


            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_CONTROL"/>.
            /// </summary>
            public uint Ebp;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_CONTROL"/>.
            /// </summary>
            public uint Eip;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_CONTROL"/>.
            /// </summary>
            public uint SegCs;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_CONTROL"/>.
            /// </summary>
            public uint EFlags;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_CONTROL"/>.
            /// </summary>
            public uint Esp;
            /// <summary>
            /// This register is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_CONTROL"/>.
            /// </summary>
            public uint SegSs;


            /// <summary>
            /// This section is specified/returned if the ContextFlags word contains the flag <see cref="CONTEXT_FLAGS.CONTEXT_EXTENDED_REGISTERS"/>.  The format and contexts are processor specific.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        #endregion Struct - CONTEXT (kernel32)
        #region Struct - FLOATING_SAVE_AREA (kernel32)

        /// <summary>
        /// Returned if <see cref="CONTEXT_FLAGS.CONTEXT_FLOATING_POINT"/> flag is specified.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            /// <summary>
            /// None.
            /// </summary>
            public uint ControlWord;
            /// <summary>
            /// None.
            /// </summary>
            public uint StatusWord;
            /// <summary>
            /// None.
            /// </summary>
            public uint TagWord;
            /// <summary>
            /// None.
            /// </summary>
            public uint ErrorOffset;
            /// <summary>
            /// None.
            /// </summary>
            public uint ErrorSelector;
            /// <summary>
            /// None.
            /// </summary>
            public uint DataOffset;
            /// <summary>
            /// None.
            /// </summary>
            public uint DataSelector;
            /// <summary>
            /// None.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            /// <summary>
            /// None.
            /// </summary>
            public uint Cr0NpxState;
        }

        #endregion Struct - FLOATING_SAVE_AREA (kernel32)
        #region Enum - CONTEXT_FLAGS (kernel32)

        /// <summary>
        /// Determines which registers are returned or set when using <see cref="Imports.GetThreadContext"/> or <see cref="Imports.SetThreadContext"/>.
        /// </summary>
        public enum CONTEXT_FLAGS : uint
        {
            /// <summary>
            /// SS:SP, CS:IP, FLAGS, BP
            /// </summary>
            CONTEXT_CONTROL = (0x00010000 | 0x01),
            /// <summary>
            /// AX, BX, CX, DX, SI, DI
            /// </summary>
            CONTEXT_INTEGER = (0x00010000 | 0x02),
            /// <summary>
            /// DS, ES, FS, GS
            /// </summary>
            CONTEXT_SEGMENTS = (0x00010000 | 0x04),
            /// <summary>
            /// 387 state
            /// </summary>
            CONTEXT_FLOATING_POINT = (0x00010000 | 0x08),
            /// <summary>
            /// DB 0-3,6,7
            /// </summary>
            CONTEXT_DEBUG_REGISTERS = (0x00010000 | 0x10),
            /// <summary>
            /// cpu specific extensions
            /// </summary>
            CONTEXT_EXTENDED_REGISTERS = (0x00010000 | 0x20),

            /// <summary>
            /// Everything but extended information and debug registers.
            /// </summary>
            CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS),
            /// <summary>
            /// Everything.
            /// </summary>
            CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
                                            CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |
                                            CONTEXT_EXTENDED_REGISTERS)
        }

        #endregion Enum - CONTEXT_FLAGS (kernel32)

        //Memory Map/Allocation
        #region Function - VirtualQueryEx (kernel32)

        [DllImport("kernel32.dll")]
        public static extern UInt32 VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        #endregion Function - VirtualQueryEx (kernel32)
        #region Function - VirtualProtectEx (kernel32)
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr dwAddress, int nSize, uint flNewProtect, out uint lpflOldProtect);
        #endregion
        #region Class - MEMORY_BASIC_INFORMATION (kernel32)

        [StructLayout(LayoutKind.Sequential)]
        /// <summary>
        /// Memory Basic Informations for 32bits
        /// </summary>
        public struct MEMORY_BASIC_INFORMATION
        {
            /// <summary>
            /// A pointer to the base address of the region of pages.
            /// </summary>
            public IntPtr BaseAddress;
            /// <summary>
            /// A pointer to the base address of a range of pages allocated by the VirtualAlloc function.
            /// The page pointed to by the BaseAddress member is contained within this allocation range.
            /// </summary>
            public IntPtr AllocationBase;
            /// <summary>
            /// The memory protection option when the region was initially allocated.
            /// This member can be one of the memory protection constants or 0 if the caller does not have access.
            /// </summary>
            public MemoryProtect AllocationProtect;
            /// <summary>
            /// The size of the region beginning at the base address in which all pages have identical attributes, in bytes.
            /// </summary>
            public IntPtr RegionSize;
            /// <summary>
            /// The state of the pages in the region. This member can be one of the following values:
            /// </summary>
            public MemoryState State;
            /// <summary>
            /// The access protection of the pages in the region. This member is one of the values listed for the AllocationProtect member.
            /// </summary>
            public MemoryProtect Protect;
            /// <summary>
            /// The type of pages in the region. This member can be one of the following values:
            /// </summary>
            public MemoryType Type;
        }

        #endregion Class - MEMORY_BASIC_INFORMATION (kernel32)
        #region Class - MemoryProtect (kernel32)

        /// <summary>
        /// Memory Protection
        /// </summary>
        public enum MemoryProtect : uint
        {
            /// <summary>
            /// Enables execute access to the committed region of pages.
            /// An attempt to read from or write to the committed region results in an access violation.
            /// This flag is not supported by the CreateFileMapping function.
            /// </summary>
            PAGE_EXECUTE = 0x10,
            /// <summary>
            /// Enables execute or read-only access to the committed region of pages.
            /// An attempt to write to the committed region results in an access violation. 
            /// </summary>
            PAGE_EXECUTE_READ = 0x20,
            /// <summary>
            /// Enables execute, read-only, or read/write access to the committed region of pages.
            /// </summary>
            PAGE_EXECUTE_READWRITE = 0x40,
            /// <summary>
            /// Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object.
            /// An attempt to write to a committed copy-on-write page results in a private copy of the page being made for the process.
            /// The private page is marked as PAGE_EXECUTE_READWRITE, and the change is written to the new page.
            /// This flag is not supported by the VirtualAlloc or VirtualAllocEx functions. 
            /// </summary>
            PAGE_EXECUTE_WRITECOPY = 0x80,
            /// <summary>
            /// Disables all access to the committed region of pages. 
            /// An attempt to read from, write to, or execute the committed region results in an access violation.
            /// This flag is not supported by the CreateFileMapping function.
            /// </summary>
            PAGE_NOACCESS = 0x01,
            /// <summary>
            /// Enables read-only access to the committed region of pages.
            /// An attempt to write to the committed region results in an access violation.
            /// If Data Execution Prevention is enabled, an attempt to execute code in the committed region results in an access violation.
            /// </summary>
            PAGE_READONLY = 0x02,
            /// <summary>
            /// Enables read-only or read/write access to the committed region of pages.
            /// If Data Execution Prevention is enabled, attempting to execute code in the committed region results in an access violation.
            /// </summary>
            PAGE_READWRITE = 0x04,
            /// <summary>
            /// Enables read-only or copy-on-write access to a mapped view of a file mapping object.
            /// An attempt to write to a committed copy-on-write page results in a private copy of the page being made for the process.
            /// The private page is marked as PAGE_READWRITE, and the change is written to the new page.
            /// If Data Execution Prevention is enabled, attempting to execute code in the committed region results in an access violation.This flag is not supported by the VirtualAlloc or VirtualAllocEx functions.
            /// </summary>
            PAGE_WRITECOPY = 0x08,

            /// <summary>
            /// Pages in the region become guard pages.
            /// Any attempt to access a guard page causes the system to raise a STATUS_GUARD_PAGE_VIOLATION exception and turn off the guard page status.
            /// Guard pages thus act as a one-time access alarm. For more information, see Creating Guard Pages.
            /// When an access attempt leads the system to turn off guard page status, the underlying page protection takes over.
            /// If a guard page exception occurs during a system service, the service typically returns a failure status indicator.
            /// This value cannot be used with PAGE_NOACCESS.
            /// This flag is not supported by the CreateFileMapping function.
            /// </summary>
            PAGE_GUARD = 0x100,
            /// <summary>
            /// Sets all pages to be non-cachable. 
            /// Applications should not use this attribute except when explicitly required for a device. 
            /// Using the interlocked functions with memory that is mapped with SEC_NOCACHE can result in an EXCEPTION_ILLEGAL_INSTRUCTION exception.The PAGE_NOCACHE flag cannot be used with the PAGE_GUARD, PAGE_NOACCESS, or PAGE_WRITECOMBINE flags.
            /// The PAGE_NOCACHE flag can be used only when allocating private memory with the VirtualAlloc, VirtualAllocEx, or VirtualAllocExNuma functions.
            /// To enable non-cached memory access for shared memory, specify the SEC_NOCACHE flag when calling the CreateFileMapping function.
            /// </summary>
            PAGE_NOCACHE = 0x200,
            /// <summary>
            /// Sets all pages to be write-combined.
            /// Applications should not use this attribute except when explicitly required for a device.
            /// Using the interlocked functions with memory that is mapped as write-combined can result in an EXCEPTION_ILLEGAL_INSTRUCTION exception.
            /// The PAGE_WRITECOMBINE flag cannot be specified with the PAGE_NOACCESS, PAGE_GUARD, and PAGE_NOCACHE flags.
            /// The PAGE_WRITECOMBINE flag can be used only when allocating private memory with the VirtualAlloc, VirtualAllocEx, or VirtualAllocExNuma functions.
            /// To enable write-combined memory access for shared memory, specify the SEC_WRITECOMBINE flag when calling the CreateFileMapping function.
            /// </summary>
            PAGE_WRITECOMBINE = 0x400,

        }

        #endregion Class - MemoryProtect (kernel32)
        #region Class - MemoryState (kernel32)

        /// <summary>
        /// Memory State Information
        /// </summary>
        public enum MemoryState : uint
        {
            /// <summary>
            /// Indicates committed pages for which physical storage has been allocated, either in memory or in the paging file on disk.
            /// </summary>
            MEM_COMMIT = 0x1000,
            /// <summary>
            /// Indicates free pages not accessible to the calling process and available to be allocated.
            /// For free pages, the information in the AllocationBase, AllocationProtect, Protect, and Type members is undefined.
            /// </summary>
            MEM_FREE = 0x10000,
            /// <summary>
            /// Indicates reserved pages where a range of the process's virtual address space is reserved without any physical storage being allocated.
            /// For reserved pages, the information in the Protect member is undefined.
            /// </summary>
            MEM_RESERVE = 0x2000
        }

        #endregion Class - MemoryState (kernel32)
        #region Class - MemoryType (kernel32)

        [Flags()]
        /// <summary>
        /// Memory Type
        /// </summary>
        public enum MemoryType : uint
        {
            /// <summary>
            /// Indicates that the memory pages within the region are mapped into the view of an image section.
            /// </summary>
            MEM_IMAGE = 0x1000000,
            /// <summary>
            /// Indicates that the memory pages within the region are mapped into the view of a section.
            /// </summary>
            MEM_MAPPED = 0x40000,
            /// <summary>
            /// Indicates that the memory pages within the region are private (that is, not shared by other processes).
            /// </summary>
            MEM_PRIVATE = 0x20000
        }

        #endregion Class - MemoryType (kernel32)
        #region Function - VirtualAllocEx (kernel32)

        /// <summary>
        /// Reserves or commits a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero, unless MEM_RESET is used.
        /// </summary>
        /// <param name="hProcess">The handle to a process. The function allocates memory within the virtual address space of this process.</param>
        /// <param name="dwAddress">The pointer that specifies a desired starting address for the region of pages that you want to allocate. (optional)</param>
        /// <param name="nSize">The size of the region of memory to allocate, in bytes.  If dwAddress is null, nSize is rounded up to the next page boundary.</param>
        /// <param name="dwAllocationType">The type of memory allocation. </param>
        /// <param name="dwProtect">The memory protection for the region of pages to be allocated.</param>
        /// <returns></returns>
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr dwAddress, uint nSize, AllocationType dwAllocationType, MemoryProtect dwProtect);

        #endregion Function - VirtualAllocEx (kernel32)
        #region Class - AllocationType (kernel32)

        [Flags()]
        /// <summary>
        /// Set Allocation Type
        /// </summary>
        public enum AllocationType : uint
        {
            /// <summary>
            /// Allocates physical storage in memory or in the paging file on disk for the specified reserved memory pages. The function initializes the memory to zero.
            /// To reserve and commit pages in one step, call VirtualAllocEx with MEM_COMMIT | MEM_RESERVE.
            /// The function fails if you attempt to commit a page that has not been reserved. The resulting error code is ERROR_INVALID_ADDRESS.
            /// </summary>
            MEM_COMMIT = 0x1000,
            /// <summary>
            /// Reserves a range of the process's virtual address space without allocating any actual physical storage in memory or in the paging file on disk. 
            /// </summary>
            MEM_RESERVE = 0x2000,
            /// <summary>
            /// Indicates that data in the memory range specified by lpAddress and dwSize is no longer of interest. The pages should not be read from or written to the paging file.
            /// However, the memory block will be used again later, so it should not be decommitted.
            /// </summary>
            MEM_RESET = 0x80000,
            /// <summary>
            /// Allocates memory using large page support.
            /// The size and alignment must be a multiple of the large-page minimum. To obtain this value, use the GetLargePageMinimum function.
            /// Windows XP/2000:   This flag is not supported !
            /// </summary>
            MEM_LARGE_PAGES = 0x20000000,
            /// <summary>
            /// Reserves an address range that can be used to map Address Windowing Extensions (AWE) pages.
            /// This value must be used with MEM_RESERVE and no other values.
            /// </summary>
            MEM_PHYSICAL = 0x400000,
            /// <summary>
            /// Allocates memory at the highest possible address. This can be slower than regular allocations, especially when there are many allocations.
            /// </summary>
            MEM_TOP_DOWN = 0x100000,
            /// <summary>
            /// Not Supported on 32bits.
            /// </summary>
            MEM_WRITE_WATCH = 0x200000
        }

        #endregion Class - AllocationType (kernel32)
        #region Function - VirtualFreeEx (kernel32)

        /// <summary>
        /// Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.
        /// </summary>
        /// <param name="hProcess">A handle to a process. The function frees memory within the virtual address space of the process. </param>
        /// <param name="dwAddress">A pointer to the starting address of the region of memory to be freed. </param>
        /// <param name="nSize">The size of the region of memory to free, in bytes.  If the dwFreeType parameter is MEM_RELEASE, dwSize must be 0 (zero). The function frees the entire region that is reserved in the initial allocation call to VirtualAllocEx.</param>
        /// <param name="dwFreeType">The type of free operation.  See Imports.MemoryFreeType.</param>
        /// <returns>If the function succeeds, the return value is a nonzero value.  If the function fails, the return value is 0 (zero).</returns>
        [DllImport("kernel32", EntryPoint = "VirtualFreeEx")]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr dwAddress, int nSize, MemoryFreeType dwFreeType);

        #endregion Function - VirtualFreeEx (kernel32)
        #region Enum - MemoryFreeType (kernel32)

        /// <summary>
        /// Values that determine how a block of memory is freed.
        /// </summary>
        public enum MemoryFreeType : uint
        {
            /// <summary>
            /// Decommits the specified region of committed pages. After the operation, the pages are in the reserved state.
            ///
            ///The function does not fail if you attempt to decommit an uncommitted page. This means that you can decommit a range of pages without first determining their current commitment state.
            ///
            ///Do not use this value with MEM_RELEASE.
            /// </summary>
            MEM_DECOMMIT = 0x4000,

            /// <summary>
            /// Releases the specified region of pages. After the operation, the pages are in the free state.
            /// If you specify this value, dwSize must be 0 (zero), and lpAddress must point to the base address returned by the VirtualAllocEx function when the region is reserved. The function fails if either of these conditions is not met.
            /// If any pages in the region are committed currently, the function first decommits, and then releases them.
            /// The function does not fail if you attempt to release pages that are in different states, some reserved and some committed. This means that you can release a range of pages without first determining the current commitment state.
            /// Do not use this value with MEM_DECOMMIT.
            /// </summary>
            MEM_RELEASE = 0x8000
        }

        #endregion Enum - MemoryFreeType (kernel32)

        //Read and Write
        #region Function - ReadProcessMemory (kernel32)

        [DllImport("kernel32.dll")]
        public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesRead);

        #endregion Function - ReadProcessMemory (kernel32)
        #region Function - WriteProcessMemory (kernel32)

        [DllImport("kernel32.dll")]
        public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesWritten);

        #endregion Function - WriteProcessMemory (kernel32)

        //Others process
        #region Function - GetProcAdress (kernel32)

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        #endregion Function - GetProcAdress (kernel32)
        #region Function - GetModuleHandle (kernel32)

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        #endregion Function - GetModuleHandle (kernel32)

        //Windows
        #region Function - EnumWindowsProc

        /// <summary>
        /// Callback function to be used with <see cref="Imports.EnumWindows"/>.
        /// </summary>
        /// <param name="hWnd">The window handle of the current window.</param>
        /// <param name="lParam">The parameter passed to EnumWindows.</param>
        /// <returns>To continue enumeration, the callback function must return TRUE; to stop enumeration, it must return FALSE. </returns>
        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        #endregion
        #region Function - EnumWindows

        /// <summary>
        /// Enumerates all open windows.
        /// </summary>
        /// <param name="lpEnumFunc">Callback function that will be called with the window handle of each window.</param>
        /// <param name="lParam">Parameter that will be passed to the callback function.</param>
        /// <returns>Returns true on success, false on failure.</returns>
        [DllImport("user32", EntryPoint = "EnumWindows")]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        #endregion Function - EnumWindows
        #region Function - GetDesktopWindow

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetDesktopWindow();

        #endregion Function - GetDesktopWindow
        #region Function - GetWindowThreadProcessId

        /// <summary>
        /// Gets the process and thread IDs associated with a given window.
        /// </summary>
        /// <param name="hWnd">The window handle of the window in question.</param>
        /// <param name="dwProcessId">[Out] The process ID of the process which created the provided window.</param>
        /// <returns>The thread ID of the process which created the provided window.</returns>
        [DllImport("user32", EntryPoint = "GetWindowThreadProcessId")]
        public static extern int GetWindowThreadProcessId(IntPtr hWnd, out int dwProcessId);

        #endregion Function - GetWindowThreadProcessId
        #region Enum - WINDOWPLACEMENT_FLAGS

        [Flags]
        /// <summary>
        /// WINDOWPLACEMENT_FLAGS
        /// </summary>
        public enum WINDOWPLACEMENT_FLAGS : uint
        {
            /// <summary>
            /// If the calling thread and the thread that owns the window are attached to different input queues, the system posts the request to the thread that owns the window.
            /// This prevents the calling thread from blocking its execution while other threads process the request.
            /// </summary>
            WPF_ASYNCWINDOWPLACEMENT = 0x0004,

            /// <summary>
            /// The restored window will be maximized, regardless of whether it was maximized before it was minimized.
            /// This setting is only valid the next time the window is restored. It does not change the default restoration behavior.
            /// This flag is only valid when the SW_SHOWMINIMIZED value is specified for the showCmd member.
            /// </summary>
            WPF_RESTORETOMAXIMIZED = 0x0002,

            /// <summary>
            /// The coordinates of the minimized window may be specified.
            /// This flag must be specified if the coordinates are set in the ptMinPosition member.
            /// </summary>
            WPF_SETMINPOSITION = 0x0001
        }

        #endregion Enum - WINDOWPLACEMENT_FLAGS
        #region Enum - WINDOWPLACEMENT_SHOWCMD

        /// <summary>
        /// WINDOWPLACEMENT_SHOWCMD
        /// </summary>
        public enum WINDOWPLACEMENT_SHOWCMD : uint
        {
            /// <summary>
            /// Hides the window and activates another window.
            /// </summary>
            SW_HIDE = 0,

            /// <summary>
            /// Maximizes the specified window.
            /// </summary>
            SW_MAXIMIZE = 3,

            /// <summary>
            /// Minimizes the specified window and activates the next top-level window in the z-order.
            /// </summary>
            SW_MINIMIZE = 6,

            /// <summary>
            /// Activates and displays the window. If the window is minimized or maximized, the system restores it to its original size and position.
            /// An application should specify this flag when restoring a minimized window.
            /// </summary>
            SW_RESTORE = 9,

            /// <summary>
            /// Activates the window and displays it in its current size and position
            /// </summary>
            SW_SHOW = 5,

            /// <summary>
            /// Activates the window and displays it as a maximized window.
            /// </summary>
            SW_SHOWMAXIMIZED = 3,

            /// <summary>
            /// Activates the window and displays it as a minimized window.
            /// </summary>
            SW_SHOWMINIMIZED = 2,

            /// <summary>
            /// Displays the window as a minimized window.
            /// This value is similar to SW_SHOWMINIMIZED, except the window is not activated.
            /// </summary>
            SW_SHOWMINNOACTIVE = 7,

            /// <summary>
            /// Displays the window in its current size and position.
            /// This value is similar to SW_SHOW, except the window is not activated.
            /// </summary>
            SW_SHOWNA = 8,

            /// <summary>
            /// Displays a window in its most recent size and position.
            /// This value is similar to SW_SHOWNORMAL, except the window is not activated.
            /// </summary>
            SW_SHOWNOACTIVATE = 8,

            /// <summary>
            /// Activates and displays a window. If the window is minimized or maximized, the system restores it to its original size and position.
            /// An application should specify this flag when displaying the window for the first time.
            /// </summary>
            SW_SHOWNORMAL = 1
        }

        #endregion Enum - WINDOWPLACEMENT_SHOWCMD
        #region Enum - WINDOWPLACEMENT

        /// <summary>
        /// WINDOWPLACEMENT
        /// </summary>
        public struct WINDOWPLACEMENT
        {
            /// <summary>
            /// length
            /// </summary>
            public uint length;

            /// <summary>
            /// flags
            /// </summary>
            public WINDOWPLACEMENT_FLAGS flags;

            /// <summary>
            /// showCmd
            /// </summary>
            public WINDOWPLACEMENT_SHOWCMD showCmd;

            /// <summary>
            /// ptMinPosition
            /// </summary>
            public Point ptMinPosition;

            /// <summary>
            /// ptMaxPosition
            /// </summary>
            public Point ptMaxPosition;

            /// <summary>
            /// rcNormalPosition
            /// </summary>
            public RECT rcNormalPosition;
    }

        #endregion Enum - WINDOWPLACEMENT
        #region Function - GetWindowPlacement

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetWindowPlacement(IntPtr hWnd, ref WINDOWPLACEMENT lpwndpl);

        #endregion Function - GetWindowPlacement
        #region Function - SetWindowPlacement

        /// <summary>
        /// Sets the show state and the restored, minimized, and maximized positions of the specified window.
        /// </summary>
        /// <param name="hWnd">
        /// A handle to the window.
        /// </param>
        /// <param name="lpwndpl">
        /// A pointer to a WINDOWPLACEMENT structure that specifies the new show state and window positions.
        /// <para>
        /// Before calling SetWindowPlacement, set the length member of the WINDOWPLACEMENT structure to sizeof(WINDOWPLACEMENT). SetWindowPlacement fails if the length member is not set correctly.
        /// </para>
        /// </param>
        /// <returns>
        /// If the function succeeds, the return value is nonzero.
        /// <para>
        /// If the function fails, the return value is zero. To get extended error information, call GetLastError.
        /// </para>
        /// </returns>
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetWindowPlacement(IntPtr hWnd, [In] ref WINDOWPLACEMENT lpwndpl);

        #endregion Function - SetWindowPlacement
        #region Function - _GetWindowText

        [DllImport("user32", EntryPoint = "GetWindowText")]
        public static extern int _GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        #endregion Function - _GetWindowText
        #region Function - _GetClassName

        [DllImport("user32", EntryPoint = "GetClassName")]
        private static extern int _GetClassName(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        #endregion Function - _GetClassName
        #region Function - GetClassName

        /// <summary>
        /// Gets the classname of the supplied window.
        /// </summary>
        /// <param name="hWnd">The window handle of the window in question.</param>
        /// <returns>Returns the classname of the supplied window.</returns>
        public static string GetClassName(IntPtr hWnd)
        {
            return GetClassName(hWnd, 256);
        }

        /// <summary>
        /// Gets the classname of the supplied window.
        /// </summary>
        /// <param name="hWnd">The window handle of the window in question.</param>
        /// <param name="nMaxCount">The maximum number of characters to return.</param>
        /// <returns>Returns the classname of the supplied window.</returns>
        public static string GetClassName(IntPtr hWnd, int nMaxCount)
        {
            StringBuilder s = new StringBuilder(nMaxCount);
            int Length;

            if ((Length = _GetClassName(hWnd, s, nMaxCount)) > 0)
                return s.ToString(0, Length);

            return null;
        }

        #endregion Function - GetClassName
        #region Struct - Rect

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left;        // x position of upper-left corner
            public int Top;         // y position of upper-left corner
            public int Right;       // x position of lower-right corner
            public int Bottom;      // y position of lower-right corner
        }

        #endregion Struct - Rect
        #region (USELESS) Function - GetWindowRect
        //[DllImport("user32.dll")]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //public static extern bool GetWindowRect(IntPtr hwnd, out RECT lpRect);
        #endregion (USELESS) Function - GetWindowRect
        #region Function - FindWindow
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        #endregion Function - FindWindow
        #region (USELESS) Function - IsWindowVisible

        ///// <summary>
        ///// Determines whether a window is visible or hidden.
        ///// </summary>
        ///// <param name="hWnd">The window handle of the window in question.</param>
        ///// <returns>Returns true if the window is visible, false if not.</returns>
        //[DllImport("user32", EntryPoint = "IsWindowVisible")]
        //public static extern bool IsWindowVisible(IntPtr hWnd);

        #endregion (USELESS) Function - IsWindowVisible
        #region (USELESS) Enum - SetWinPosFlag

        //[Flags]
        ///// <summary>
        ///// Set flags to SetWindowPos
        ///// </summary>
        //public enum SetWinPosFlag : uint
        //{
        //    /// <summary>
        //    /// If the calling thread and the thread that owns the window are attached to different input queues, the system posts the request to the thread that owns the window.
        //    /// This prevents the calling thread from blocking its execution while other threads process the request. 
        //    /// </summary>
        //    SWP_ASYNCWINDOWPOS = 0x4000,

        //    /// <summary>
        //    /// Prevents generation of the WM_SYNCPAINT message.
        //    /// </summary>
        //    SWP_DEFERERASE = 0x2000,

        //    /// <summary>
        //    /// Draws a frame (defined in the window's class description) around the window.
        //    /// </summary>
        //    SWP_DRAWFRAME = 0x0020,

        //    /// <summary>
        //    /// Applies new frame styles set using the SetWindowLong function. Sends a WM_NCCALCSIZE message to the window, even if the window's size is not being changed.
        //    /// If this flag is not specified, WM_NCCALCSIZE is sent only when the window's size is being changed.
        //    /// </summary>
        //    SWP_FRAMECHANGED = 0x0020,

        //    /// <summary>
        //    /// Hides the window.
        //    /// </summary>
        //    SWP_HIDEWINDOW = 0x0080,

        //    /// <summary>
        //    /// Does not activate the window.
        //    /// If this flag is not set, the window is activated and moved to the top of either the topmost or non-topmost group (depending on the setting of the hWndInsertAfter parameter).
        //    /// </summary>
        //    SWP_NOACTIVATE = 0x0010,

        //    /// <summary>
        //    /// Discards the entire contents of the client area.
        //    /// If this flag is not specified, the valid contents of the client area are saved and copied back into the client area after the window is sized or repositioned.
        //    /// </summary>
        //    SWP_NOCOPYBITS = 0x0100,

        //    /// <summary>
        //    /// Retains the current position (ignores X and Y parameters).
        //    /// </summary>
        //    SWP_NOMOVE = 0x0002,

        //    /// <summary>
        //    /// Does not change the owner window's position in the Z order.
        //    /// </summary>
        //    SWP_NOOWNERZORDER = 0x0200,

        //    /// <summary>
        //    /// Does not redraw changes. If this flag is set, no repainting of any kind occurs.
        //    /// This applies to the client area, the nonclient area (including the title bar and scroll bars), and any part of the parent window uncovered as a result of the window being moved.
        //    /// When this flag is set, the application must explicitly invalidate or redraw any parts of the window and parent window that need redrawing.
        //    /// </summary>
        //    SWP_NOREDRAW = 0x0008,

        //    /// <summary>
        //    /// Same as the SWP_NOOWNERZORDER flag.
        //    /// </summary>
        //    SWP_NOREPOSITION = 0x0200,

        //    /// <summary>
        //    /// Prevents the window from receiving the WM_WINDOWPOSCHANGING message.
        //    /// </summary>
        //    SWP_NOSENDCHANGING = 0x0400,

        //    /// <summary>
        //    /// Retains the current size (ignores the cx and cy parameters).
        //    /// </summary>
        //    SWP_NOSIZE = 0x0001,

        //    /// <summary>
        //    /// Retains the current Z order (ignores the hWndInsertAfter parameter).
        //    /// </summary>
        //    SWP_NOZORDER = 0x0004,

        //    /// <summary>
        //    /// Displays the window.
        //    /// </summary>
        //    SWP_SHOWWINDOW = 0x0040
        //}

        #endregion (USELESS) Enum - SetWinPosFlag
        #region (USELESS) Function - SetWindowPos

        //[DllImport("user32.dll", EntryPoint = "SetWindowPos")]
        //public static extern IntPtr SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int x, int Y, int cx, int cy, SetWinPosFlag wFlags);

        #endregion (USELESS) Function - SetWindowPos
        #region (USELESS) Function - SetForegroundWindow

        //[DllImport("user32.dll")]
        //[return: MarshalAs(UnmanagedType.Bool)]
        //public static extern bool SetForegroundWindow(IntPtr hWnd);

        #endregion (USELESS) Function - SetForegroundWindow

        //Graphic
        #region Function - GetWindowDC

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetWindowDC(IntPtr window);

        #endregion Function - GetWindowDC
        #region Function - GetPixel

        [DllImport("gdi32.dll", SetLastError = true)]
        public static extern uint GetPixel(IntPtr dc, int x, int y);

        #endregion Function - GetPixel
        #region Function - ReleaseDC

        [DllImport("user32.dll", SetLastError = true)]
        public static extern int ReleaseDC(IntPtr window, IntPtr dc);

        #endregion Function - ReleaseDC

        //Devices
        #region SendInput Defines

        [StructLayout(LayoutKind.Explicit)]
        public struct INPUT
        {
            [FieldOffset(0)]
            public InputType type;
            [FieldOffset(4)]
            public MOUSEINPUT mi;
            [FieldOffset(4)]
            public KEYBDINPUT ki;
            [FieldOffset(4)]
            public HARDWAREINPUT hi;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HARDWAREINPUT
        {
            public int uMsg;
            public short wParamL;
            public short wParamH;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEYBDINPUT
        {
            public VirtualKeys wVk;
            public ushort wScan;
            public KEYEVENTF dwFlags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MOUSEINPUT
        {
            public int dx;
            public int dy;
            public uint mouseData;
            public MOUSEEVENTF dwFlags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [Flags]
        public enum InputType : int
        {
            INPUT_MOUSE = 0,
            INPUT_KEYBOARD = 1,
            INPUT_HARDWARE = 2
        }

        [Flags]
        public enum MOUSEEVENTF : uint
        {
            MOVE = 0x0001, /* mouse move */
            LEFTDOWN = 0x0002, /* left button down */
            LEFTUP = 0x0004, /* left button up */
            RIGHTDOWN = 0x0008, /* right button down */
            RIGHTUP = 0x0010, /* right button up */
            MIDDLEDOWN = 0x0020, /* middle button down */
            MIDDLEUP = 0x0040, /* middle button up */
            XDOWN = 0x0080, /* x button down */
            XUP = 0x0100, /* x button down */
            WHEEL = 0x0800, /* wheel button rolled */
            MOVE_NOCOALESCE = 0x2000, /* do not coalesce mouse moves */
            VIRTUALDESK = 0x4000, /* map to entire virtual desktop */
            ABSOLUTE = 0x8000 /* absolute move */
        }

        [Flags]
        public enum KEYEVENTF : uint
        {
            KEYDOWN = 0,
            EXTENDEDKEY = 0x0001,
            KEYUP = 0x0002,
            UNICODE = 0x0004,
            SCANCODE = 0x0008,
        }

        #endregion SendInput Defines
        #region Function - SendInput
        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
        #endregion Function - SendInput
        #region Enum - MapVirtualKeyMapTypes

        /// <summary>
        /// The set of valid MapTypes used in MapVirtualKey
        /// </summary>
        public enum MapVirtualKeyMapTypes : uint
        {
            /// <summary>
            /// uCode is a virtual-key code and is translated into a scan code.
            /// If it is a virtual-key code that does not distinguish between left- and
            /// right-hand keys, the left-hand scan code is returned.
            /// If there is no translation, the function returns 0.
            /// </summary>
            MAPVK_VK_TO_VSC = 0x00,

            /// <summary>
            /// uCode is a scan code and is translated into a virtual-key code that
            /// does not distinguish between left- and right-hand keys. If there is no
            /// translation, the function returns 0.
            /// </summary>
            MAPVK_VSC_TO_VK = 0x01,

            /// <summary>
            /// uCode is a virtual-key code and is translated into an unshifted
            /// character value in the low-order word of the return value. Dead keys (diacritics)
            /// are indicated by setting the top bit of the return value. If there is no
            /// translation, the function returns 0.
            /// </summary>
            MAPVK_VK_TO_CHAR = 0x02,

            /// <summary>
            /// Windows NT/2000/XP: uCode is a scan code and is translated into a
            /// virtual-key code that distinguishes between left- and right-hand keys. If
            /// there is no translation, the function returns 0.
            /// </summary>
            MAPVK_VSC_TO_VK_EX = 0x03,

            /// <summary>
            /// Not currently documented
            /// </summary>
            MAPVK_VK_TO_VSC_EX = 0x04
        }

        #endregion Enum - MapVirtualKeyMapTypes
        #region Function - MapVirtualKey
        [DllImport("user32.dll")]
        public static extern uint MapVirtualKey(uint uCode, uint uMapType);
        #endregion Function - MapVirtualKey
        #region Enum - VirtualMessages

        /// <summary>
        /// Virtual Messages
        /// </summary>
        public enum VirtualMessages : int
        {
            WM_LBUTTONDOWN = 0x201, //Left mousebutton down
            WM_LBUTTONUP = 0x202,  //Left mousebutton up
            WM_LBUTTONDBLCLK = 0x203, //Left mousebutton doubleclick
            WM_RBUTTONDOWN = 0x204, //Right mousebutton down
            WM_RBUTTONUP = 0x205,   //Right mousebutton up
            WM_RBUTTONDBLCLK = 0x206, //Right mousebutton doubleclick
            WM_KEYDOWN = 0x100,  //Key down
            WM_KEYUP = 0x101,   //Key up
        }

        #endregion Enum - VirtualMessages
        #region Enum - VirtualKeys

        /// <summary>
        /// Virtual Keys
        /// </summary>
        public enum VirtualKeys : ushort
        {
            VK_LBUTTON = 0x01,   //Left mouse button
            VK_RBUTTON = 0x02,   //Right mouse button
            VK_CANCEL = 0x03,   //Control-break processing
            VK_MBUTTON = 0x04,   //Middle mouse button (three-button mouse)
            VK_BACK = 0x08,   //BACKSPACE key
            VK_TAB = 0x09,   //TAB key
            VK_CLEAR = 0x0C,   //CLEAR key
            VK_RETURN = 0x0D,   //ENTER key
            VK_SHIFT = 0x10,   //SHIFT key
            VK_CONTROL = 0x11,   //CTRL key
            VK_MENU = 0x12,   //ALT key
            VK_PAUSE = 0x13,   //PAUSE key
            VK_CAPITAL = 0x14,   //CAPS LOCK key
            VK_ESCAPE = 0x1B,   //ESC key
            VK_SPACE = 0x20,   //SPACEBAR
            VK_PRIOR = 0x21,   //PAGE UP key
            VK_NEXT = 0x22,   //PAGE DOWN key
            VK_END = 0x23,   //END key
            VK_HOME = 0x24,   //HOME key
            VK_LEFT = 0x25,   //LEFT ARROW key
            VK_UP = 0x26,   //UP ARROW key
            VK_RIGHT = 0x27,   //RIGHT ARROW key
            VK_DOWN = 0x28,   //DOWN ARROW key
            VK_SELECT = 0x29,   //SELECT key
            VK_PRINT = 0x2A,   //PRINT key
            VK_EXECUTE = 0x2B,   //EXECUTE key
            VK_SNAPSHOT = 0x2C,   //PRINT SCREEN key
            VK_INSERT = 0x2D,   //INS key
            VK_DELETE = 0x2E,   //DEL key
            VK_HELP = 0x2F,   //HELP key
            VK_0 = 0x30,   //0 key
            VK_1 = 0x31,   //1 key
            VK_2 = 0x32,   //2 key
            VK_3 = 0x33,   //3 key
            VK_4 = 0x34,   //4 key
            VK_5 = 0x35,   //5 key
            VK_6 = 0x36,    //6 key
            VK_7 = 0x37,    //7 key
            VK_8 = 0x38,   //8 key
            VK_9 = 0x39,    //9 key
            VK_A = 0x41,   //A key
            VK_B = 0x42,   //B key
            VK_C = 0x43,   //C key
            VK_D = 0x44,   //D key
            VK_E = 0x45,   //E key
            VK_F = 0x46,   //F key
            VK_G = 0x47,   //G key
            VK_H = 0x48,   //H key
            VK_I = 0x49,    //I key
            VK_J = 0x4A,   //J key
            VK_K = 0x4B,   //K key
            VK_L = 0x4C,   //L key
            VK_M = 0x4D,   //M key
            VK_N = 0x4E,    //N key
            VK_O = 0x4F,   //O key
            VK_P = 0x50,    //P key
            VK_Q = 0x51,   //Q key
            VK_R = 0x52,   //R key
            VK_S = 0x53,   //S key
            VK_T = 0x54,   //T key
            VK_U = 0x55,   //U key
            VK_V = 0x56,   //V key
            VK_W = 0x57,   //W key
            VK_X = 0x58,   //X key
            VK_Y = 0x59,   //Y key
            VK_Z = 0x5A,    //Z key
            VK_NUMPAD0 = 0x60,   //Numeric keypad 0 key
            VK_NUMPAD1 = 0x61,   //Numeric keypad 1 key
            VK_NUMPAD2 = 0x62,   //Numeric keypad 2 key
            VK_NUMPAD3 = 0x63,   //Numeric keypad 3 key
            VK_NUMPAD4 = 0x64,   //Numeric keypad 4 key
            VK_NUMPAD5 = 0x65,   //Numeric keypad 5 key
            VK_NUMPAD6 = 0x66,   //Numeric keypad 6 key
            VK_NUMPAD7 = 0x67,   //Numeric keypad 7 key
            VK_NUMPAD8 = 0x68,   //Numeric keypad 8 key
            VK_NUMPAD9 = 0x69,   //Numeric keypad 9 key
            VK_SEPARATOR = 0x6C,   //Separator key
            VK_SUBTRACT = 0x6D,   //Subtract key
            VK_DECIMAL = 0x6E,   //Decimal key
            VK_DIVIDE = 0x6F,   //Divide key
            VK_F1 = 0x70,   //F1 key
            VK_F2 = 0x71,   //F2 key
            VK_F3 = 0x72,   //F3 key
            VK_F4 = 0x73,   //F4 key
            VK_F5 = 0x74,   //F5 key
            VK_F6 = 0x75,   //F6 key
            VK_F7 = 0x76,   //F7 key
            VK_F8 = 0x77,   //F8 key
            VK_F9 = 0x78,   //F9 key
            VK_F10 = 0x79,   //F10 key
            VK_F11 = 0x7A,   //F11 key
            VK_F12 = 0x7B,   //F12 key
            VK_SCROLL = 0x91,   //SCROLL LOCK key
            VK_LSHIFT = 0xA0,   //Left SHIFT key
            VK_RSHIFT = 0xA1,   //Right SHIFT key
            VK_LCONTROL = 0xA2,   //Left CONTROL key
            VK_RCONTROL = 0xA3,    //Right CONTROL key
            VK_LMENU = 0xA4,      //Left MENU key
            VK_RMENU = 0xA5,   //Right MENU key
            VK_PLAY = 0xFA,   //Play key
            VK_ZOOM = 0xFB, //Zoom key
            VK_XBUTTON1 = 0x05,
            VK_XBUTTON2 = 0x06,
            VK_KANA = 0x15,
            VK_HANGEUL = 0x15, /* old name - should be here for compatibility */
            VK_HANGUL = 0x15,
            VK_JUNJA = 0x17,
            VK_FINAL = 0x18,
            VK_HANJA = 0x19,
            VK_KANJI = 0x19,
            VK_CONVERT = 0x1C,
            VK_NONCONVERT = 0x1D,
            VK_ACCEPT = 0x1E,
            VK_MODECHANGE = 0x1F,
            VK_LWIN = 0x5B,
            VK_RWIN = 0x5C,
            VK_APPS = 0x5D,
            VK_SLEEP = 0x5F,
            VK_MULTIPLY = 0x6A,
            VK_ADD = 0x6B,
            VK_F13 = 0x7C,
            VK_F14 = 0x7D,
            VK_F15 = 0x7E,
            VK_F16 = 0x7F,
            VK_F17 = 0x80,
            VK_F18 = 0x81,
            VK_F19 = 0x82,
            VK_F20 = 0x83,
            VK_F21 = 0x84,
            VK_F22 = 0x85,
            VK_F23 = 0x86,
            VK_F24 = 0x87,
            VK_NUMLOCK = 0x90,
            VK_OEM_NEC_EQUAL = 0x92, // '=' key on numpad
            VK_OEM_FJ_JISHO = 0x92, // 'Dictionary' key
            VK_OEM_FJ_MASSHOU = 0x93, // 'Unregister word' key
            VK_OEM_FJ_TOUROKU = 0x94, // 'Register word' key
            VK_OEM_FJ_LOYA = 0x95, // 'Left OYAYUBI' key
            VK_OEM_FJ_ROYA = 0x96, // 'Right OYAYUBI' key
            VK_BROWSER_BACK = 0xA6,
            VK_BROWSER_FORWARD = 0xA7,
            VK_BROWSER_REFRESH = 0xA8,
            VK_BROWSER_STOP = 0xA9,
            VK_BROWSER_SEARCH = 0xAA,
            VK_BROWSER_FAVORITES = 0xAB,
            VK_BROWSER_HOME = 0xAC,
            VK_VOLUME_MUTE = 0xAD,
            VK_VOLUME_DOWN = 0xAE,
            VK_VOLUME_UP = 0xAF,
            VK_MEDIA_NEXT_TRACK = 0xB0,
            VK_MEDIA_PREV_TRACK = 0xB1,
            VK_MEDIA_STOP = 0xB2,
            VK_MEDIA_PLAY_PAUSE = 0xB3,
            VK_LAUNCH_MAIL = 0xB4,
            VK_LAUNCH_MEDIA_SELECT = 0xB5,
            VK_LAUNCH_APP1 = 0xB6,
            VK_LAUNCH_APP2 = 0xB7,
            VK_OEM_1 = 0xBA, // ';:' for US
            VK_OEM_PLUS = 0xBB, // '+' any country
            VK_OEM_COMMA = 0xBC, // ',' any country
            VK_OEM_MINUS = 0xBD, // '-' any country
            VK_OEM_PERIOD = 0xBE, // '.' any country
            VK_OEM_2 = 0xBF, // '/?' for US
            VK_OEM_3 = 0xC0, // '`~' for US
            VK_OEM_4 = 0xDB, // '[{' for US
            VK_OEM_5 = 0xDC, // '|' for US
            VK_OEM_6 = 0xDD, // ']}' for US
            VK_OEM_7 = 0xDE, // ''"' for US
            VK_OEM_8 = 0xDF,
            VK_OEM_AX = 0xE1, // 'AX' key on Japanese AX kbd
            VK_OEM_102 = 0xE2, // "<>" or "|" on RT 102-key kbd.
            VK_ICO_HELP = 0xE3, // Help key on ICO
            VK_ICO_00 = 0xE4, // 00 key on ICO
            VK_PROCESSKEY = 0xE5,
            VK_ICO_CLEAR = 0xE6,
            VK_PACKET = 0xE7,
            VK_OEM_RESET = 0xE9,
            VK_OEM_JUMP = 0xEA,
            VK_OEM_PA1 = 0xEB,
            VK_OEM_PA2 = 0xEC,
            VK_OEM_PA3 = 0xED,
            VK_OEM_WSCTRL = 0xEE,
            VK_OEM_CUSEL = 0xEF,
            VK_OEM_ATTN = 0xF0,
            VK_OEM_FINISH = 0xF1,
            VK_OEM_COPY = 0xF2,
            VK_OEM_AUTO = 0xF3,
            VK_OEM_ENLW = 0xF4,
            VK_OEM_BACKTAB = 0xF5,
            VK_ATTN = 0xF6,
            VK_CRSEL = 0xF7,
            VK_EXSEL = 0xF8,
            VK_EREOF = 0xF9,
            VK_NONAME = 0xFC,
            VK_PA1 = 0xFD,
            VK_OEM_CLEAR = 0xFE,
        }

        #endregion Enum - VirtualKeys
        #region Function - PostMessage
        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool PostMessage(HandleRef hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);
        #endregion Function - PostMessage
        #region Function - SendMessage
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);
        #endregion Function - SendMessage
        #region Function - keybd_event
        [DllImport("user32.dll")]
        public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
        #endregion Function - keybd_event
        #region Function - VkKeyScan
        [DllImport("user32.dll")]
        public static extern short VkKeyScan(char ch);
        #endregion Function - VkKeyScan
        #region Function - GetMessageExtraInfo
        [DllImport("user32.dll")]
        public static extern IntPtr GetMessageExtraInfo();
        #endregion Function - GetMessageExtraInfo
        #region Function - SetCursorPos
        [DllImport("user32.dll")]
        public static extern bool SetCursorPos(int X, int Y);
        #endregion Function - SetCursorPos
        #region Enum - MouseEventFlags

        [Flags]
        public enum MouseEventFlags : uint
        {
            LEFTDOWN = 0x00000002,
            LEFTUP = 0x00000004,
            MIDDLEDOWN = 0x00000020,
            MIDDLEUP = 0x00000040,
            MOVE = 0x00000001,
            ABSOLUTE = 0x00008000,
            RIGHTDOWN = 0x00000008,
            RIGHTUP = 0x00000010,
            WHEEL = 0x00000800,
            XDOWN = 0x00000080,
            XUP = 0x00000100
        }

        #endregion Enum - MouseEventFlags
        #region Enum - MouseEventDataXButtons

        //Use the values of this enum for the 'dwData' parameter
        //to specify an X button when using MouseEventFlags.XDOWN or
        //MouseEventFlags.XUP for the dwFlags parameter.
        public enum MouseEventDataXButtons : uint
        {
            XBUTTON1 = 0x00000001,
            XBUTTON2 = 0x00000002
        }

        #endregion Enum - MouseEventDataXButtons
        #region Function - mouse_event
        [DllImport("user32.dll")]
        public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);
        #endregion Function - mouse_event
    }

    /// <summary>
    /// Converter
    /// </summary>
    public static class Converter
    {
        #region DecToHexaString (Int16)
        /// <summary>
        /// Change a Int16 to a Hexadecimal String
        /// </summary>
        /// <param name="argShort">Short</param>
        public static string DecToHexaString(Int16 argShort)
        {
            return String.Format("{0:X}", argShort);
        }
        #endregion DecToHexaString (Int16)
        #region DecToHexaString (Int32)
        /// <summary>
        /// Change a Int32 to a Hexadecimal String
        /// </summary>
        /// <param name="argInteger">Integer</param>
        public static string DecToHexaString(Int32 argInteger)
        {
            return String.Format("{0:X}", argInteger);
        }
        #endregion DecToHexaString (Int32)
        #region DecToHexaString (Int64)
        /// <summary>
        /// Change a Int64 to a Hexadecimal String
        /// </summary>
        /// <param name="argLong">Long</param>
        public static string DecToHexaString(Int64 argLong)
        {
            return String.Format("{0:X}", argLong);
        }
        #endregion DecToHexaString (Int64)
        #region HexaStringToDec16 (Int16)
        /// <summary>
        /// Change a Hexadecimal String to a Int16
        /// </summary>
        /// <param name="argString">String source</param>
        public static Int16 HexaStringToDec16(String argString)
        {
            return Int16.Parse(argString, System.Globalization.NumberStyles.HexNumber);
        }
        #endregion HexaStringToDec16 (Int16)
        #region HexaStringToDec32 (Int32)
        /// <summary>
        /// Change a Hexadecimal String to a Int32
        /// </summary>
        /// <param name="argString">String source</param>
        public static Int32 HexaStringToDec32(String argString)
        {
            return Int32.Parse(argString, System.Globalization.NumberStyles.HexNumber);
        }
        #endregion HexaStringToDec32 (Int32)
        #region HexaStringToDec64 (Int64)
        /// <summary>
        /// Change a Hexadecimal String to a Int64
        /// </summary>
        /// <param name="argString">String source</param>
        public static Int64 HexaStringToDec64(String argString)
        {
            return Int64.Parse(argString, System.Globalization.NumberStyles.HexNumber);
        }
        #endregion HexaStringToDec64 (Int64)
    }


    //------------------------------------------------------------------------
    //-------------------------------- Core ---------------------------------
    //------------------------------------------------------------------------
    /// <summary>
    /// A powerfull process manager.
    /// </summary>
    /// <remarks>Created by Adrien SCELLES</remarks>
    /// <remarks>Enjoy hack and crack !</remarks>
    /// <remarks>Release 1.7.7</remarks>
    public class hibProcess
    {
        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// Process
        /// </summary>
        private Process _process = null;

        /// <summary>
        /// Process
        /// </summary>
        public Process Process
        {
            get
            {
                //Return
                return _process;
            }
            set { }
        }

        /// <summary>
        /// Handle used for process operations/manipulations.
        /// </summary>
        private IntPtr _operationsHandle = IntPtr.Zero;

        /// <summary>
        /// Handle used for process operations/manipulations.
        /// </summary>
        public IntPtr OperationHandle
        {
            get
            {
                //Return
                return _operationsHandle;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Define if the process is open for operations/manipulations.
        /// </summary>
        private bool _isOpen = false;

        /// <summary>
        /// Define if the hibProcess is link with a System.Diagnostics.Process .
        /// </summary>
        public bool IsOpen
        {
            get
            {
                //Return
                return _isOpen;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Define if process is x64.
        /// </summary>
        /// <remarks>You need to open the process before !</remarks>
        public bool IsX64
        {
            get
            {
                //check _isOpen
                if (!_isOpen) return false;

                //Check environment
                if (Environment.Is64BitOperatingSystem)
                {
                    //Check is wow64
                    bool retval;
                    if (Import.IsWow64Process(OperationHandle, out retval))
                    {
                        //Return
                        return false;
                    }

                    //Return
                    return true;
                }
                else
                {
                    //Return
                    return false;
                }
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Modules
        /// </summary>
        private ModulesMgr _modules = null;

        /// <summary>
        /// Modules
        /// </summary>
        public ModulesMgr Modules
        {
            get
            {
                //Return
                return _modules;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Regions
        /// </summary>
        private RegionsMgr _regions = null;

        /// <summary>
        /// Regions
        /// </summary>
        public RegionsMgr Regions
        {
            get
            {
                //Return
                return _regions;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Threads
        /// </summary>
        private ThreadsMgr _threads = null;

        /// <summary>
        /// Threads
        /// </summary>
        public ThreadsMgr Threads
        {
            get
            {
                //Return
                return _threads;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Read
        /// </summary>
        private ReadMgr _read = null;

        /// <summary>
        /// Read
        /// </summary>
        public ReadMgr Read
        {
            get
            {
                //Return
                return _read;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Write
        /// </summary>
        private WriteMgr _write = null;

        /// <summary>
        /// Write
        /// </summary>
        public WriteMgr Write
        {
            get
            {
                //Return
                return _write;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Patterns
        /// </summary>
        private PatternsMgr _patterns = null;

        /// <summary>
        /// Patterns
        /// </summary>
        public PatternsMgr Patterns
        {
            get
            {
                //Return
                return _patterns;
            }
            set
            {
            }
        }

        /// <summary>
        /// Patchs
        /// </summary>
        private PatchsMgr _patchs = null;

        /// <summary>
        /// Patchs
        /// </summary>
        public PatchsMgr Patchs
        {
            get
            {
                //Return
                return _patchs;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Injections
        /// </summary>
        private InjectionsMgr _injections = null;

        /// <summary>
        /// Injections
        /// </summary>
        public InjectionsMgr Injections
        {
            get
            {
                //Return
                return _injections;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Hooks
        /// </summary>
        private HooksMgr _hooks = null;

        /// <summary>
        /// Hooks
        /// </summary>
        public HooksMgr Hooks
        {
            get
            {
                //Return
                return _hooks;
            }
            set
            {
            }
        }

        /// <summary>
        /// Windows
        /// </summary>
        private WindowsMgr _windows = null;

        /// <summary>
        /// Windows
        /// </summary>
        public WindowsMgr Windows
        {
            get
            {
                //Return
                return _windows;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Pixels
        /// </summary>
        private PixelsMgr _pixels = null;

        /// <summary>
        /// Pixels
        /// </summary>
        public PixelsMgr Pixels
        {
            get
            {
                //Return
                return _pixels;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Mouse
        /// </summary>
        private MouseMgr _mouse = null;

        /// <summary>
        /// Mouse
        /// </summary>
        public MouseMgr Mouse
        {
            get
            {
                //Return
                return _mouse;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Keyboard
        /// </summary>
        private KeyboardMgr _keyboard = null;

        /// <summary>
        /// Keyboard
        /// </summary>
        public KeyboardMgr Keyboard
        {
            get
            {
                //Return
                return _keyboard;
            }
            set
            {
                //Empty
            }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Create a new hibProcess based on a System.Diagnostics.Process.
        /// </summary>
        /// <param name="argProcess">Process</param>
        public hibProcess(Process argProcess)
        {
            //Check argProcess
            if (argProcess == null)
            {
                //Throw new exception
                throw new Exception("Process argument cannot be null !");
            }

            //Define _process
            _process = argProcess;

            //Create managers
            _modules = new ModulesMgr(this);
            _regions = new RegionsMgr(this);
            _threads = new ThreadsMgr(this);
            _read = new ReadMgr(this);
            _write = new WriteMgr(this);
            _patterns = new PatternsMgr(this);
            _patchs = new PatchsMgr(this);
            _injections = new InjectionsMgr(this);
            _hooks = new HooksMgr(this);
            _windows = new WindowsMgr(this);
            _pixels = new PixelsMgr(this);
            _mouse = new MouseMgr(this);
            _keyboard = new KeyboardMgr(this);
        }

        /// <summary>
        /// Destructor
        /// </summary>
        ~hibProcess()
        {
            //Close handle
            if (_isOpen) CloseHandle();
        }

        /// <summary>
        /// Open process with all acces.
        /// </summary>
        /// <returns>Returns true on success, false on failure.</returns>
        public bool OpenHandle()
        {
            //Call
            return OpenHandle(Import.ProcessAccessFlags.All);
        }

        /// <summary>
        /// Open process with desired acces.
        /// </summary>
        /// <param name="argDesiredAccess">Desired access</param>
        /// <returns>Returns true on success, false on failure.</returns>
        public bool OpenHandle(Import.ProcessAccessFlags argDesiredAccess)
        {
            //Call
            return OpenHandle(argDesiredAccess, false);
        }

        /// <summary>
        /// Open process with desired acces and debug mode if necessary.
        /// </summary>
        /// <param name="argDesiredAccess">Desired access</param>
        /// <param name="argDebugMode">Debug mode</param>
        /// <returns>Returns true on success, false on failure.</returns>
        public bool OpenHandle(Import.ProcessAccessFlags argDesiredAccess, bool argDebugMode)
        {
            //Call
            return OpenHandle(argDesiredAccess, argDebugMode, false);
        }

        /// <summary>
        /// Open process with desired acces, debug mode and inherit handles.
        /// </summary>
        /// <param name="argDesiredAccess">Desired access</param>
        /// <param name="argDebugMode">Debug mode</param>
        /// <param name="argInheritHandle">Inherit handle</param>
        /// <returns>Returns true on success, false on failure.</returns>
        public bool OpenHandle(Import.ProcessAccessFlags argDesiredAccess, bool argDebugMode, bool argInheritHandle)
        {
            try
            {
                //Get All Tokens Privileges
                //List<string> TokensSeq = new List<string>();
                //TokensSeq.Add("SeAssignPrimaryTokenPrivilege");
                //TokensSeq.Add("SeAuditPrivilege");
                //TokensSeq.Add("SeBackupPrivilege");
                //TokensSeq.Add("SeChangeNotifyPrivilege");
                //TokensSeq.Add("SeCreateGlobalPrivilege");
                //TokensSeq.Add("SeCreatePagefilePrivilege");
                //TokensSeq.Add("SeCreatePermanentPrivilege");
                //TokensSeq.Add("SeCreateSymbolicLinkPrivilege");
                //TokensSeq.Add("SeCreateTokenPrivilege");
                //TokensSeq.Add("SeDebugPrivilege");
                //TokensSeq.Add("SeEnableDelegationPrivilege");
                //TokensSeq.Add("SeImpersonatePrivilege");
                //TokensSeq.Add("SeIncreaseBasePriorityPrivilege");
                //TokensSeq.Add("SeIncreaseQuotaPrivilege");
                //TokensSeq.Add("SeIncreaseWorkingSetPrivilege");
                //TokensSeq.Add("SeLoadDriverPrivilege");
                //TokensSeq.Add("SeLockMemoryPrivilege");
                //TokensSeq.Add("SeMachineAccountPrivilege");
                //TokensSeq.Add("SeManageVolumePrivilege");
                //TokensSeq.Add("SeProfileSingleProcessPrivilege");
                //TokensSeq.Add("SeRelabelPrivilege");
                //TokensSeq.Add("SeRemoteShutdownPrivilege");
                //TokensSeq.Add("SeRestorePrivilege");
                //TokensSeq.Add("SeSecurityPrivilege");
                //TokensSeq.Add("SeShutdownPrivilege");
                //TokensSeq.Add("SeSyncAgentPrivilege");
                //TokensSeq.Add("SeSystemEnvironmentPrivilege");
                //TokensSeq.Add("SeSystemProfilePrivilege");
                //TokensSeq.Add("SeSystemtimePrivilege");
                //TokensSeq.Add("SeTakeOwnershipPrivilege");
                //TokensSeq.Add("SeTcbPrivilege");
                //TokensSeq.Add("SeTimeZonePrivilege");
                //TokensSeq.Add("SeTrustedCredManAccessPrivilege");
                //TokensSeq.Add("SeUndockPrivilege");
                //TokensSeq.Add("SeUnsolicitedInputPrivilege");
                //Imports.TokPriv1Luid tp;
                //IntPtr hproc = Imports.GetCurrentProcess();
                //IntPtr htok = IntPtr.Zero;
                //Imports.OpenProcessToken(hproc, Imports.TOKEN_ADJUST_PRIVILEGES | Imports.TOKEN_QUERY, ref htok);
                //foreach (string s in TokensSeq)
                //{
                //tp.Count = 1;
                //tp.Luid = 0;
                //tp.Attr = Imports.SE_PRIVILEGE_ENABLED;
                //Imports.LookupPrivilegeValue(null, s, ref tp.Luid);
                //Imports.AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                //}
                //CloseHandle(hproc);

                //Check _isOpen
                if (_isOpen)
                {
                    //Throw new exception
                    throw new Exception("Process handle is already open !");
                }

                //Enter DebugMode
                if (argDebugMode)
                {
                    //Enter
                    Process.EnterDebugMode();
                }
                else
                {
                    //Leave
                    Process.LeaveDebugMode();
                }

                //Open Process
                IntPtr pHandle = Import.OpenProcess(argDesiredAccess, argInheritHandle, _process.Id);
                if (pHandle != null)
                {
                    //Define _isOpen
                    _isOpen = true;

                    //Define _operationsHandle
                    _operationsHandle = pHandle;

                    //Return
                    return true;
                }
                else
                {
                    //Define _isOpen
                    _isOpen = false;

                    //Return
                    return false;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
                //Define _isOpen
                _isOpen = false;

                //Return
                return false;
            }
        }

        /// <summary>
        /// Close opened handle.
        /// </summary>
        /// <returns>Returns true on success, false on failure.</returns>
        public bool CloseHandle()
        {
            try
            {
                if (Import.CloseHandle(_operationsHandle) != 0)
                {
                    //Define _isOpen
                    _isOpen = false;

                    //Return
                    return true;
                }
                else
                {
                    //Return
                    return false;
                }
            }
            catch
            {
                //Return
                return false;
            }
        }

        /// <summary>
        /// Gets the process ID of the process that created the supplied window handle.
        /// </summary>
        /// <param name="arghWnd">Handle to the main window of the process in question.</param>
        /// <returns>Returns non-zero on success, zero on failure.</returns>
        public static int GetProcessIdFromWindow(IntPtr arghWnd)
        {
            int dwProcessId = 0;
            Import.GetWindowThreadProcessId(arghWnd, out dwProcessId);
            return dwProcessId;
        }

        /// <summary>
        /// Gets the process ID of the process that created the first window to match the given window title.
        /// </summary>
        /// <param name="argWindowTitle">Title of the main window whose process id we want.</param>
        /// <returns>Returns non-zero on success, zero on failure.</returns>
        public static int GetProcessIdFromWindowTitle(string argWindowTitle)
        {
            IntPtr hWnd = WindowsMgr.FindWindow(null, argWindowTitle);
            if (hWnd == IntPtr.Zero)
                return 0;

            return GetProcessIdFromWindow(hWnd);
        }

        /// <summary>
        /// Returns an array of process ids of processes that match given window title.
        /// </summary>
        /// <param name="argWindowTitle">Title of windows to match.</param>
        /// <returns>Returns null on failure, array of integers populated with process ids on success.</returns>
        public static int[] GetProcessesIdFromWindowTitle(string argWindowTitle)
        {
            IntPtr[] hWnds = WindowsMgr.FindWindows(null, argWindowTitle);
            if (hWnds == null || hWnds.Length == 0)
                return null;

            int[] ret = new int[hWnds.Length];

            for (int i = 0; i < ret.Length; i++)
                ret[i] = GetProcessIdFromWindow(hWnds[i]);

            return ret;
        }

        /// <summary>
        /// Gets the process ID of the process that created the first window to match the given window title.
        /// </summary>
        /// <param name="argClassname">Classname of the main window whose process id we want.</param>
        /// <returns>Returns non-zero on success, zero on failure.</returns>
        public static int GetProcessIdFromClassname(string argClassname)
        {
            IntPtr hWnd = WindowsMgr.FindWindow(argClassname, null);
            if (hWnd == IntPtr.Zero)
                return 0;

            return GetProcessIdFromWindow(hWnd);
        }

        /// <summary>
        /// Returns an array of process ids of processes that match given window title.
        /// </summary>
        /// <param name="argClassname">Classname of windows to match.</param>
        /// <returns>Returns null on failure, array of integers populated with process ids on success.</returns>
        public static int[] GetProcessesIdFromClassname(string argClassname)
        {
            IntPtr[] hWnds = WindowsMgr.FindWindows(argClassname, null);
            if (hWnds == null || hWnds.Length == 0)
                return null;

            int[] ret = new int[hWnds.Length];

            for (int i = 0; i < ret.Length; i++)
                ret[i] = GetProcessIdFromWindow(hWnds[i]);

            return ret;
        }

        /// <summary>
        /// Gets the process id of the process whose executable name matches that which is supplied.
        /// </summary>
        /// <param name="argProcessName">Name of the executable to match.</param>
        /// <returns>Returns non-zero on success, zero on failure.</returns>
        public static int GetProcessIdFromProcessName(string argProcessName)
        {
            if (argProcessName.EndsWith(".exe"))
                argProcessName = argProcessName.Remove(argProcessName.Length - 4, 4);

            Process[] procs = Process.GetProcessesByName(argProcessName);
            if (procs == null || procs.Length == 0)
                return 0;

            return procs[0].Id;
        }
    }


    //------------------------------------------------------------------------
    //--------------------------------- Bases -------------------------------
    //------------------------------------------------------------------------
    /// <summary>
    /// hibClass
    /// </summary>
    public class hibClass
    {
        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// Parent
        /// </summary>
        public hibProcess Parent
        {
            get
            {
                //Return
                return _parent;
            }
            set
            {
                //Empty
            }
        }

        /// <summary>
        /// Parent
        /// </summary>
        private hibProcess _parent = null;


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Create a new class linked with the desired hibProcess.
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public hibClass(hibProcess argParent)
        {
            //Set _parent
            _parent = argParent;
        }
    }


    //------------------------------------------------------------------------
    //-------------------------------- Modules ------------------------------
    //------------------------------------------------------------------------
    /// <summary>
    /// Modules manager
    /// </summary>
    public class ModulesMgr : hibClass
    {
        //-----------------------------------------
        //--------------- Objects -----------------
        /// <summary>
        /// Module
        /// </summary>
        public class Module : hibClass
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// ProcessModule
            /// </summary>
            private ProcessModule _processModule = null;

            /// <summary>
            /// Name
            /// </summary>
            private string _name
            {
                get
                {
                    return _processModule.ModuleName;
                }
                set
                {
                }
            }

            /// <summary>
            /// MemorySize
            /// </summary>
            private UIntPtr _memorySize
            {
                get
                {
                    return (UIntPtr)_processModule.ModuleMemorySize;
                }
                set
                {
                }
            }

            /// <summary>
            /// BaseAddress
            /// </summary>
            private IntPtr _baseAddress
            {
                get
                {
                    return _processModule.BaseAddress;
                }
                set
                {
                }
            }

            /// <summary>
            /// EntryPointAddress
            /// </summary>
            private IntPtr _entryPointAddress
            {
                get
                {
                    return _processModule.EntryPointAddress;
                }
                set
                {
                }
            }

            /// <summary>
            /// File
            /// </summary>
            private FileInfo _file
            {
                get
                {
                    return new FileInfo(_processModule.FileName);
                }
                set
                {
                }
            }

            /// <summary>
            /// FileVersionInfo
            /// </summary>
            private FileVersionInfo _fileVersionInfo
            {
                get
                {
                    return _processModule.FileVersionInfo;
                }
                set
                {
                }
            }

            /// <summary>
            /// ProcessModule
            /// </summary>
            public ProcessModule ProcessModule
            {
                get
                {
                    //Return
                    return _processModule;
                }
                set
                {
                }
            }

            /// <summary>
            /// Name
            /// </summary>
            public string Name
            {
                get
                {
                    //Return
                    return _name;
                }
                set
                {
                }
            }

            /// <summary>
            /// MemorySize
            /// </summary>
            public UIntPtr MemorySize
            {
                get
                {
                    //Return
                    return _memorySize;
                }
                set
                {
                }
            }

            /// <summary>
            /// BaseAddress
            /// </summary>
            public IntPtr BaseAddress
            {
                get
                {
                    //Return
                    return _baseAddress;
                }
                set
                {
                }
            }

            /// <summary>
            /// EntryPointAddress
            /// </summary>
            public IntPtr EntryPointAddress
            {
                get
                {
                    //Return
                    return _entryPointAddress;
                }
                set
                {
                }
            }

            /// <summary>
            /// File
            /// </summary>
            public FileInfo File
            {
                get
                {
                    //Return
                    return _file;
                }
                set
                {
                }
            }

            /// <summary>
            /// FileVersionInfo
            /// </summary>
            public FileVersionInfo FileVersionInfo
            {
                get
                {
                    //Return
                    return _fileVersionInfo;
                }
                set
                {
                }
            }

            /// <summary>
            /// Regions
            /// </summary>
            public List<RegionsMgr.Region> Regions
            {
                get
                {
                    //Create list
                    List<RegionsMgr.Region> list = new List<RegionsMgr.Region>();

                    //Search
                    foreach (RegionsMgr.Region r in Parent.Regions.All)
                    {
                        if (((long)r.BaseAddress >= (long)_baseAddress) && ((long)r.BaseAddress + (long)r.RegionSize) <= ((long)_baseAddress + (long)_memorySize))
                        {
                            list.Add(r);
                        }
                    }

                    //Return
                    return list;
                }
                set
                {
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="argParent">hibProcess</param>
            /// <param name="argProcessModule">ProcessModule</param>
            /// <exception cref="Exception">Throws general exception on failure.</exception>
            public Module(hibProcess argParent, ProcessModule argProcessModule) : base(argParent)
            {
                //Set values
                _processModule = argProcessModule;
            }
        }


        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// Modules
        /// </summary>
        private List<Module> _modules = new List<Module>();

        /// <summary>
        /// Modules
        /// </summary>
        public List<Module> Modules
        {
            get
            {
                //Verify converted modules count match
                if (_modules.Count == Parent.Process.Modules.Count)
                {
                    //Return
                    return _modules;
                }
                else
                {
                    //Convert missing modules and remove unloaded modules
                    lock (_modules)
                    {
                        foreach (ProcessModule pm in Parent.Process.Modules)
                        {
                            bool converted = false;
                            foreach (Module m in _modules)
                            {
                                if (m.ProcessModule == pm) converted = true;
                            }
                            if (!converted)
                            {
                                //Create new module
                                _modules.Add(new Module(Parent, pm));
                            }
                        }
                        foreach (Module m in _modules)
                        {
                            bool unloaded = true;
                            foreach (ProcessModule pm in Parent.Process.Modules)
                            {
                                if (pm == m.ProcessModule) unloaded = false;
                            }
                            if (unloaded)
                            {
                                _modules.Remove(m);
                            }
                        }
                    }

                    //Return
                    return _modules;
                }
            }
            set
            {
            }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public ModulesMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Retrieve a specific module from his name.
        /// </summary>
        /// <param name="argName">Name</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return module found, null if not.</returns>
        public Module GetModuleFromName(string argName)
        {
            //Search module
            foreach (Module m in Modules)
            {
                if (m.Name == argName)
                {
                    //Return
                    return m;
                }
            }

            //Return
            return null;
        }

        /// <summary>
        /// Retrieve a specific module from his base adresses.
        /// </summary>
        /// <param name="argBaseAddress">BaseAddress</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return module found, null if not.</returns>
        public Module GetModuleFromBaseAddress(IntPtr argBaseAddress)
        {
            //Search module
            foreach (Module m in Modules)
            {
                if (m.BaseAddress == argBaseAddress)
                {
                    //Return
                    return m;
                }
            }

            //Return
            return null;
        }
    }

    /// <summary>
    /// Regions manager
    /// </summary>
    public class RegionsMgr : hibClass
    {
        //-----------------------------------------
        //--------------- Objects -----------------
        /// <summary>
        /// Region
        /// </summary>
        public class Region : hibClass
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// A pointer to the base address of the region of pages.
            /// </summary>
            private IntPtr _baseAddress;

            /// <summary>
            /// A pointer to the base address of the region of pages.
            /// </summary>
            public IntPtr BaseAddress
            {
                get
                {
                    //Return
                    return _baseAddress;
                }
                set
                {
                }
            }

            /// <summary>
            /// A pointer to the base address of a range of pages allocated by the VirtualAlloc function.
            /// The page pointed to by the BaseAddress member is contained within this allocation range.
            /// </summary>
            private IntPtr _allocationBase;

            /// <summary>
            /// A pointer to the base address of a range of pages allocated by the VirtualAlloc function.
            /// The page pointed to by the BaseAddress member is contained within this allocation range.
            /// </summary>
            public IntPtr AllocationBase
            {
                get
                {
                    //Return
                    return _allocationBase;
                }
                set
                {
                }
            }

            /// <summary>
            /// The memory protection option when the region was initially allocated.
            /// This member can be one of the memory protection constants or 0 if the caller does not have access.
            /// </summary>
            private Import.MemoryProtect _allocationProtect;

            /// <summary>
            /// The memory protection option when the region was initially allocated.
            /// This member can be one of the memory protection constants or 0 if the caller does not have access.
            /// </summary>
            public Import.MemoryProtect AllocationProtect
            {
                get
                {
                    //Return
                    return _allocationProtect;
                }
                set
                {
                }
            }

            /// <summary>
            /// The size of the region beginning at the base address in which all pages have identical attributes, in bytes.
            /// </summary>
            private IntPtr _regionSize;

            /// <summary>
            /// The size of the region beginning at the base address in which all pages have identical attributes, in bytes.
            /// </summary>
            public IntPtr RegionSize
            {
                get
                {
                    //Return
                    return _regionSize;
                }
                set
                {
                }
            }

            /// <summary>
            /// The state of the pages in the region. This member can be one of the following values:
            /// </summary>
            private Import.MemoryState _state;

            /// <summary>
            /// The state of the pages in the region. This member can be one of the following values:
            /// </summary>
            public Import.MemoryState State
            {
                get
                {
                    //Return
                    return _state;
                }
                set
                {
                }
            }

            /// <summary>
            /// The access protection of the pages in the region. This member is one of the values listed for the AllocationProtect member.
            /// </summary>
            private Import.MemoryProtect _protect;

            /// <summary>
            /// The access protection of the pages in the region. This member is one of the values listed for the AllocationProtect member.
            /// </summary>
            public Import.MemoryProtect Protect
            {
                get
                {
                    //Return
                    return _protect;
                }
                set
                {
                    //Set
                    uint OldProtection;
                    Parent.Regions.VirtualProtectEx(_baseAddress, (int)_regionSize, (uint)value, out OldProtection);
                }
            }

            /// <summary>
            /// The type of pages in the region. This member can be one of the following values:
            /// </summary>
            private Import.MemoryType _type;

            /// <summary>
            /// The type of pages in the region. This member can be one of the following values:
            /// </summary>
            public Import.MemoryType Type
            {
                get
                {
                    //Return
                    return _type;
                }
                set
                {
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Create a new region.
            /// </summary>
            /// <param name="argParent">hibProcess</param>
            public Region(hibProcess argParent) : base(argParent)
            {
            }

            /// <summary>
            /// Get Data from the region.
            /// </summary>
            public byte[] Read()
            {
                //Read
                try
                {
                    //Write data
                    byte[] Result = Parent.Read.Bytes(_baseAddress, (uint)_regionSize);

                    //Return
                    return Result;
                }
                catch
                {
                    //Return
                    return null;
                }
            }

            /// <summary>
            /// Set Data to the region.
            /// Warning : Check the lenght !
            /// </summary>
            public bool Write(byte[] argNewData)
            {
                //Check Lenght
                if ((long)argNewData.Length > (long)RegionSize) return false;

                //Write Data
                try
                {
                    //Write data
                    Parent.Write.Bytes(_baseAddress, argNewData);
                }
                catch
                {
                    //Return false on error
                    return false;
                }

                //return
                return true;
            }

            /// <summary>
            /// Refresh all informations.
            /// Warning : Based on BaseAdress !
            /// </summary>
            public bool Refresh()
            {
                //Container
                Import.MEMORY_BASIC_INFORMATION m = new Import.MEMORY_BASIC_INFORMATION();

                //Get
                try
                {
                    //Query
                    Import.VirtualQueryEx(Parent.OperationHandle, _baseAddress, out m, (uint)Marshal.SizeOf(m));

                    //Check container
                    if ((uint)m.RegionSize == 0)
                    {
                        //Return false
                        return false;
                    }

                    //Cast
                    FromMemoryBasicInformation(m);
                }
                catch
                {
                    //Return false
                    return false;
                }

                //Return true
                return true;
            }

            /// <summary>
            /// Refresh all informations from a specific region adress.
            /// </summary>
            /// <param name="argAdress">Adress</param>
            public bool RefreshFromAdress(IntPtr argAdress)
            {
                //Container
                Import.MEMORY_BASIC_INFORMATION m = new Import.MEMORY_BASIC_INFORMATION();

                //Get
                try
                {
                    //Query
                    Import.VirtualQueryEx(Parent.OperationHandle, argAdress, out m, (uint)Marshal.SizeOf(m));

                    //Check container
                    if ((uint)m.RegionSize == 0)
                    {
                        //Return false
                        return false;
                    }

                    //Cast
                    FromMemoryBasicInformation(m);
                }
                catch
                {
                    //Return false
                    return false;
                }

                //Return true
                return true;
            }

            /// <summary>
            /// Free the region.
            /// </summary>
            public bool Free()
            {
                //Check state
                if (_state == Import.MemoryState.MEM_FREE) return false;

                //Free Memory
                try
                {
                    if (!Parent.Regions.FreeMemory(_baseAddress))
                    {
                        //Return
                        return false;
                    }
                }
                catch
                {
                    //Return
                    return false;
                }

                //Return
                return true;
            }

            /// <summary>
            /// Get informations from a Memory_Region_Information structure.
            /// </summary>
            /// <param name="argMemoryBasicInformation">informations</param>
            public void FromMemoryBasicInformation(Import.MEMORY_BASIC_INFORMATION argMemoryBasicInformation)
            {
                _baseAddress = argMemoryBasicInformation.BaseAddress;
                _allocationBase = argMemoryBasicInformation.AllocationBase;
                _allocationProtect = argMemoryBasicInformation.AllocationProtect;
                _regionSize = argMemoryBasicInformation.RegionSize;
                _state = argMemoryBasicInformation.State;
                _protect = argMemoryBasicInformation.Protect;
                _type = argMemoryBasicInformation.Type;
            }
        }

        /// <summary>
        /// Manage a custom memory allocation into the target process.
        /// </summary>
        /// <<remarks>This class free the allocated memory into the destructor by default !You can disable it with FreeOnDispose propertie.</remarks>
        public class Allocation : Region
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// Define if the class free the memory allocation on dispose.
            /// </summary>
            public bool FreeOnDispose
            {
                get
                {
                    return _freeOnDispose;
                }
                set
                {
                    _freeOnDispose = value;
                }
            }

            /// <summary>
            /// Define if the class free the memory allocation on dispose.
            /// </summary>
            private bool _freeOnDispose = true;


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// AllocatedMemory
            /// </summary>
            public Allocation(hibProcess argParent) : base(argParent)
            {
            }

            /// <summary>
            /// Destructor
            /// </summary>
            ~Allocation()
            {
                try
                {
                    //Free
                    if (_freeOnDispose) Free();

                    //Remove from list
                    if (Parent.Regions.Allocations.Contains(this))
                    {
                        Parent.Regions.Allocations.Remove(this);
                    }
                }
                catch
                {
                }
            }
        }

        /// <summary>
        /// CodeCave
        /// </summary>
        public class CodeCave : hibClass
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// Base address
            /// </summary>
            private IntPtr _baseAddress;

            /// <summary>
            /// Base address
            /// </summary>
            public IntPtr BaseAddress
            {
                get
                {
                    //Return
                    return _baseAddress;
                }
                set
                {
                }
            }

            /// <summary>
            /// Size
            /// </summary>
            private UIntPtr _size;

            /// <summary>
            /// Size
            /// </summary>
            public UIntPtr Size
            {
                get
                {
                    //Return
                    return _size;
                }
                set
                {
                }
            }

            /// <summary>
            /// Define if the CodeCave is clear on dispose.
            /// </summary>
            private bool _clearOnDispose = false;

            /// <summary>
            /// Define if the CodeCave is clear on dispose.
            /// </summary>
            public bool ClearOnDispose
            {
                get
                {
                    //Return
                    return _clearOnDispose;
                }
                set
                {
                    _clearOnDispose = value;
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Constructor
            /// </summary>
            public CodeCave(hibProcess argParent, IntPtr argBaseAdress, UIntPtr argSize) : base(argParent)
            {
                //Defines
                _baseAddress = argBaseAdress;
                _size = argSize;
            }

            /// <summary>
            /// Destructor
            /// </summary>
            ~CodeCave()
            {
                if (_clearOnDispose) Clear();
            }

            /// <summary>
            /// Get Data from the CodeCave.
            /// </summary>
            public byte[] Read()
            {
                //Read
                try
                {
                    //Read data
                    byte[] Result = Parent.Read.Bytes(_baseAddress, (uint)_size);

                    //Return
                    return Result;
                }
                catch
                {
                    return null;
                }
            }

            /// <summary>
            /// Set Data to the CodeCave.
            /// Warning : Check the lenght !
            /// </summary>
            public bool Write(byte[] NewData)
            {
                //Check Lenght
                if ((ulong)NewData.Length > (ulong)_size) return false;

                //Write Data
                Parent.Write.Bytes(_baseAddress, NewData);

                //return
                return true;
            }

            /// <summary>
            /// Clear the CodeCave.
            /// </summary>
            public bool Clear()
            {
                //Write 0x00
                try
                {
                    List<byte> Data = new List<byte>();
                    for (int i = 1; i <= (uint)_size; i++)
                    {
                        Data.Add(0x00);
                    }
                    Parent.Write.Bytes(_baseAddress, Data.ToArray());
                }
                catch
                {
                    return false;
                }

                //Return
                return true;
            }
        }


        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// All regions
        /// </summary>
        private List<Region> _all = new List<Region>();

        /// <summary>
        /// All regions
        /// </summary>
        public List<Region> All
        {
            get
            {
                //Get regions
                if (_all.Count == 0)
                {
                    RefreshRegions();
                }

                //Return
                return _all;
            }
            set
            {
            }
        }

        /// <summary>
        /// Commited regions
        /// </summary>
        public List<Region> Commited
        {
            get
            {
                //Create new list
                List<Region> tlist = new List<Region>();

                //Add
                foreach (Region r in _all)
                {
                    if (r.State == Import.MemoryState.MEM_COMMIT)
                    {
                        tlist.Add(r);
                    }
                }

                //Return
                return tlist;
            }
            set
            {
            }
        }

        /// <summary>
        /// Reserved regions
        /// </summary>
        public List<Region> Reserved
        {
            get
            {
                //Create new list
                List<Region> tlist = new List<Region>();

                //Add
                foreach (Region r in _all)
                {
                    if (r.State == Import.MemoryState.MEM_RESERVE)
                    {
                        tlist.Add(r);
                    }
                }

                //Return
                return tlist;
            }
            set
            {
            }
        }

        /// <summary>
        /// Free regions
        /// </summary>
        public List<Region> Free
        {
            get
            {
                //Create new list
                List<Region> tlist = new List<Region>();

                //Add
                foreach (Region r in _all)
                {
                    if (r.State == Import.MemoryState.MEM_FREE)
                    {
                        tlist.Add(r);
                    }
                }

                //Return
                return tlist;
            }
            set
            {
            }
        }

        /// <summary>
        /// Allocated regions
        /// </summary>
        private List<Allocation> _allocations = new List<Allocation>();

        /// <summary>
        /// Allocated regions
        /// </summary>
        public List<Allocation> Allocations
        {
            get
            {
                //Return
                return _allocations;
            }
            set
            {
            }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        #region Constructor

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public RegionsMgr(hibProcess argParent) : base(argParent)
        {
        }

        #endregion Constructor
        #region AllocateMemory

        /// <summary>
        /// Allocates 0x1000 (4096 dec) bytes of memory in the target process.
        /// </summary>
        /// <returns>Returns zero on failure, or the base address of the allocated block of memory on success.</returns>
        public IntPtr AllocateMemory()
        {
            //Return
            return AllocateMemory((UIntPtr)0x1000);
        }

        /// <summary>
        /// Allocates a block of memory in the target process.
        /// </summary>
        /// <param name="argSize">Number of bytes to be allocated.  Default is 0x1000.</param>
        /// <returns>Returns zero on failure, or the base address of the allocated block of memory on success.</returns>
        public IntPtr AllocateMemory(UIntPtr argSize)
        {
            //Return
            return AllocateMemory(argSize, Import.AllocationType.MEM_COMMIT, Import.MemoryProtect.PAGE_EXECUTE_READWRITE);
        }

        /// <summary>
        /// Allocates a block of memory in the target process.
        /// </summary>
        /// <param name="argSize">Number of bytes to be allocated.  Default is 0x1000.</param>
        /// <param name="argAllocationType">The type of memory allocation.  See <see cref="Import.AllocationType"/></param>
        /// <param name="argProtect">The memory protection for the region of pages to be allocated. If the pages are being committed, you can specify any one of the <see cref="Import.MemoryProtect"/> constants.</param>
        /// <returns>Returns zero on failure, or the base address of the allocated block of memory on success.</returns>
        public IntPtr AllocateMemory(UIntPtr argSize, Import.AllocationType argAllocationType, Import.MemoryProtect argProtect)
        {
            //Return
            return AllocateMemory(argSize, argAllocationType, argProtect, IntPtr.Zero);
        }

        /// <summary>
        /// Allocates a block of memory at the specified adress in the target process.
        /// </summary>
        /// <param name="argSize">Number of bytes to be allocated.  Default is 0x1000.</param>
        /// <param name="argAllocationType">The type of memory allocation.  See <see cref="Import.AllocationType"/></param>
        /// <param name="argProtect">The memory protection for the region of pages to be allocated. If the pages are being committed, you can specify any one of the <see cref="Import.MemoryProtect"/> constants.</param>
        /// <param name="argAddress">Base Adress into process in which memory will be allocated.</param>
        /// <returns>Returns zero on failure, or the base address of the allocated block of memory on success.</returns>
        public IntPtr AllocateMemory(UIntPtr argSize, Import.AllocationType argAllocationType, Import.MemoryProtect argProtect, IntPtr argAddress)
        {
            return Import.VirtualAllocEx(Parent.OperationHandle, argAddress, argSize.ToUInt32(), argAllocationType, argProtect);
        }

        #endregion AllocateMemory
        #region VirtualProtectEx

        /// <summary>
        /// Set protection for a specified range into the memory.
        /// </summary>
        /// <param name="argAddress">Adress</param>
        /// <param name="argSize">Size</param>
        /// <param name="argNewProtect">Protection</param>
        /// <param name="argNewProtect">Container for the old protection.</param>
        /// <returns>Returns zero on failure, or the old protection value of the allocated block of memory on success.</returns>
        public bool VirtualProtectEx(IntPtr argAddress, int argSize, uint argNewProtect, out uint refOldProtect)
        {
            return Import.VirtualProtectEx(Parent.OperationHandle, argAddress, argSize, argNewProtect, out refOldProtect);
        }

        #endregion VirtualProtectEx
        #region FreeMemory

        /// <summary>
        /// Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.
        /// </summary>
        /// <param name="argAddress">A pointer to the starting address of the region of memory to be freed. </param>
        /// <returns>Returns true on success, false on failure.</returns>
        /// <remarks>
        /// Uses <see cref="MemoryFreeType.MEM_RELEASE"/> to free the page(s) specified.
        /// </remarks>
        public bool FreeMemory(IntPtr argAddress)
        {
            return FreeMemory(argAddress, 0, Import.MemoryFreeType.MEM_RELEASE);
        }

        /// <summary>
        /// Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.
        /// </summary>
        /// <param name="argAddress">A pointer to the starting address of the region of memory to be freed. </param>
        /// <param name="argSize">
        /// The size of the region of memory to free, in bytes. 
        /// If the dwFreeType parameter is MEM_RELEASE, dwSize must be 0 (zero). The function frees the entire region that is reserved in the initial allocation call to VirtualAllocEx.</param>
        /// <param name="argFreeType">The type of free operation.  See <see cref="MemoryFreeType"/>.</param>
        /// <returns>Returns true on success, false on failure.</returns>
        public bool FreeMemory(IntPtr argAddress, int argSize, Import.MemoryFreeType argFreeType)
        {
            if (argFreeType == Import.MemoryFreeType.MEM_RELEASE)
                argSize = 0;

            return Import.VirtualFreeEx(Parent.OperationHandle, argAddress, argSize, argFreeType);
        }

        #endregion FreeMemory
        #region RefreshRegions

        /// <summary>
        /// Refresh memory regions lists.
        /// </summary>
        /// <returns>Return true if succeed, false on failure.</returns>
        public bool RefreshRegions()
        {
            //Clear list
            _all.Clear();

            //Map
            Import.MEMORY_BASIC_INFORMATION m = new Import.MEMORY_BASIC_INFORMATION();
            IntPtr address = IntPtr.Zero;
            for (; ; address = IntPtr.Add(m.BaseAddress, m.RegionSize.ToInt32()))
            {
                //Get Region
                if (0 == Import.VirtualQueryEx(Parent.OperationHandle, (IntPtr)address, out m, (uint)Marshal.SizeOf(m)))
                {
                    break;
                }

                //Add
                Region NewRegion = new Region(Parent);
                NewRegion.FromMemoryBasicInformation(m);
                _all.Add(NewRegion);
            }

            //Return
            return true;
        }

        #endregion RefreshRegions
        #region GetRegionByAdress

        /// <summary>
        /// Get region at the specific adress. 
        /// </summary>
        /// <param name="argAdress">Adress</param>
        /// <exception cref="Exception">Return null on failure.</exception>
        /// <returns>Returns region on success, null on failure.</returns>
        public Region GetRegionByAdress(IntPtr argAdress)
        {
            //Container
            Import.MEMORY_BASIC_INFORMATION m = new Import.MEMORY_BASIC_INFORMATION();

            //Get
            try
            {
                //Query
                Import.VirtualQueryEx(Parent.OperationHandle, argAdress, out m, (uint)Marshal.SizeOf(m));

                //Check container
                if ((uint)m.RegionSize == 0)
                {
                    //Return false
                    return null;
                }

                //Create and cast
                Region NewRegion = new Region(Parent);
                NewRegion.FromMemoryBasicInformation(m);

                //Return
                return NewRegion;
            }
            catch
            {
                //Return false
                return null;
            }
        }

        #endregion GetRegionByAdress
        #region GetRegionsByModule

        /// <summary>
        /// Get regions from a specific module. 
        /// </summary>
        /// <param name="argProcessModule">Module</param>
        /// <returns>Returns regions on success, null on failure.</returns>
        public List<Region> GetRegionsByModule(ProcessModule argProcessModule)
        {
            //List
            List<Region> List = new List<Region>();

            //Check Module
            if (argProcessModule == null) return null;

            //Get regions
            IntPtr NextAdress = argProcessModule.BaseAddress;
            while ((uint)NextAdress < (uint)(argProcessModule.BaseAddress + argProcessModule.ModuleMemorySize))
            {
                //Container
                Import.MEMORY_BASIC_INFORMATION m = new Import.MEMORY_BASIC_INFORMATION();

                //Query
                Import.VirtualQueryEx(Parent.OperationHandle, NextAdress, out m, (uint)Marshal.SizeOf(m));

                //Add To list
                Region NewRegion = new Region(Parent);
                NewRegion.FromMemoryBasicInformation(m);
                List.Add(NewRegion);

                //Increment
                NextAdress = (IntPtr)(NextAdress + (int)m.RegionSize);
            }

            //Return
            return List;
        }

        #endregion GetRegionsByModule
        #region CreateAllocation

        /// <summary>
        /// Create a new allocation with a default size. (0x1000)
        /// </summary>
        /// <returns>Returns null on failure, or the allocation on success.</returns>
        public Allocation CreateAllocation()
        {
            //Return
            return CreateAllocation((UIntPtr)0x1000);
        }

        /// <summary>
        /// Create a new allocation with a custom size.
        /// </summary>
        /// <param name="argSize">Number of bytes to be allocated.  Default is 0x1000.</param>
        /// <returns>Returns null on failure, or the allocation on success.</returns>
        public Allocation CreateAllocation(UIntPtr argSize)
        {
            //Return
            return CreateAllocation(argSize, IntPtr.Zero);
        }

        /// <summary>
        /// Create a new allocation at the specific adress with a custom size.
        /// </summary>
        /// <param name="argSize">Number of bytes to be allocated.  Default is 0x1000.</param>
        /// <param name="argAdress">Adress</param>
        /// <returns>Returns null on failure, or the allocation on success.</returns>
        public Allocation CreateAllocation(UIntPtr argSize, IntPtr argAdress)
        {
            //Create allocation
            Allocation newAllocation = new Allocation(Parent);

            try
            {
                //Allocate memory
                IntPtr Adress = AllocateMemory((UIntPtr)argSize, Import.AllocationType.MEM_COMMIT, Import.MemoryProtect.PAGE_EXECUTE_READWRITE, argAdress);

                //Check allocation
                if (Adress == null) return null;

                try
                {
                    //Refresh informations
                    if (!newAllocation.RefreshFromAdress(Adress)) return null;
                }
                catch
                {
                    //Free memory
                    FreeMemory(Adress, (int)argSize, Import.MemoryFreeType.MEM_RELEASE);

                    //Return
                    return null;
                }
            }
            catch
            {
                //Return
                return null;
            }

            //Add to the list
            _allocations.Add(newAllocation);

            //Return
            return newAllocation;
        }

        #endregion CreateAllocation
        #region GetCodeCave

        /// <summary>
        /// Get a CodeCave with a specific Length.
        /// </summary>
        /// <param name="argSize">Number of bytes needed.</param>
        /// <returns>Returns a codecave on found, or null.</returns>
        /// s<remarks>Length must be >= 15 !</remarks>
        /// <remarks>This function scan the process memory, call it async to avoid th main thread.</remarks>
        public CodeCave GetCodeCave(UIntPtr argSize)
        {
            //Check size
            if ((ulong)argSize < 15) return null;

            //Create pattern
            List<PatternsMgr.Pattern> list = new List<PatternsMgr.Pattern>();
            PatternsMgr.Pattern p = new PatternsMgr.Pattern(Parent, "");
            List<byte> Data = new List<byte>();
            for (int i = 0; i <= ((uint)argSize - 1); i++)
            {
                p.StaticOffsets.Add(new PatternsMgr.ByteInfo(i, 0x00));
            }
            list.Add(p);

            //Scan
            Parent.Patterns.ScanRegions(PatternsMgr.ScanMode.StaticsOffsets, Import.MemoryState.MEM_COMMIT, Import.MemoryProtect.PAGE_EXECUTE_READ, list);

            //Verify
            if (p.Adress != IntPtr.Zero)
            {
                //Return
                return new CodeCave(Parent, p.Adress, argSize);
            }
            else
            {
                //Return
                return null;
            }
        }

        #endregion GetCodeCave
    }

    /// <summary>
    /// Threads manager
    /// </summary>
    public class ThreadsMgr : hibClass
    {
        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// All threads of the target process.
        /// </summary>
        public ProcessThreadCollection AllThreads
        {
            get
            {
                return Parent.Process.Threads;
            }
            set { }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public ThreadsMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Gets the main thread ID of a given process.
        /// </summary>
        /// <param name="dwProcessId">The ID of the process whose main thread ID will be returned.</param>
        /// <returns>Returns non-zero on success, zero on failure.</returns>
        public static int GetMainThreadId(int dwProcessId)
        {
            if (dwProcessId == 0)
                return 0;

            Process proc = Process.GetProcessById(dwProcessId);
            return proc.Threads[0].Id;
        }

        /// <summary>
        /// Gets the main thread of a given process.
        /// </summary>
        /// <param name="dwProcessId">The ID of the process whose main thread will be returned.</param>
        /// <returns>Returns the main thread on success, null on failure.</returns>
        public static ProcessThread GetMainThread(int dwProcessId)
        {
            if (dwProcessId == 0)
                return null;


            Process proc = Process.GetProcessById(dwProcessId);
            return proc.Threads[0];
        }

        /// <summary>
        /// Creates a thread inside another process' context.
        /// </summary>
        /// <param name="hProcess">Handle to the process inside which thread will be created.</param>
        /// <param name="dwStartAddress">Address at which thread will start.</param>
        /// <param name="dwParameter">Parameter that will be passed to the thread.</param>
        /// <returns>Returns the handle of the created thread.</returns>
        public static IntPtr CreateRemoteThread(IntPtr hProcess, uint dwStartAddress, uint dwParameter)
        {
            uint dwThreadId;
            return CreateRemoteThread(hProcess, dwStartAddress, dwParameter, Import.ThreadCreationFlags.THREAD_EXECUTE_IMMEDIATELY, out dwThreadId);
        }

        /// <summary>
        /// Creates a thread inside another process' context.
        /// </summary>
        /// <param name="hProcess">Handle to the process inside which thread will be created.</param>
        /// <param name="dwStartAddress">Address at which thread will start.</param>
        /// <param name="dwParameter">Parameter that will be passed to the thread.</param>
        /// /// <param name="dwThreadId">[Out] The id of the created thread.</param>
        /// <returns>Returns the handle of the created thread.</returns>
        public static IntPtr CreateRemoteThread(IntPtr hProcess, uint dwStartAddress, uint dwParameter, out uint dwThreadId)
        {
            return CreateRemoteThread(hProcess, dwStartAddress, dwParameter, Import.ThreadCreationFlags.THREAD_EXECUTE_IMMEDIATELY, out dwThreadId);
        }

        /// <summary>
        /// Creates a thread inside another process' context.
        /// </summary>
        /// <param name="hProcess">Handle to the process inside which thread will be created.</param>
        /// <param name="dwStartAddress">Address at which thread will start.</param>
        /// <param name="dwParameter">Parameter that will be passed to the thread.</param>
        /// <param name="dwCreationFlags">Flags that control creation of the thread.</param>
        /// <param name="dwThreadId">[Out] The id of the created thread.</param>
        /// <returns>Returns the handle of the created thread.</returns>
        public static IntPtr CreateRemoteThread(IntPtr hProcess, uint dwStartAddress, uint dwParameter, Import.ThreadCreationFlags dwCreationFlags, out uint dwThreadId)
        {
            IntPtr hThread, lpThreadId;

            hThread = Import.CreateRemoteThread(hProcess, IntPtr.Zero, 0, (IntPtr)dwStartAddress, (IntPtr)dwParameter, dwCreationFlags, out lpThreadId);
            dwThreadId = (uint)lpThreadId;

            return hThread;
        }

        /// <summary>
        /// Opens a thread for manipulation.  AccessRights.THREAD_ALL_ACCESS is automatically granted.
        /// </summary>
        /// <param name="dwThreadId">The ID of the thread in question.</param>
        /// <returns>Returns a handle to the thread allowing manipulation.</returns>
        public static IntPtr OpenThread(int dwThreadId)
        {
            return OpenThread(Import.ThreadAccessFlags.THREAD_ALL_ACCESS, dwThreadId);
        }

        /// <summary>
        /// Opens a thread for manipulation.
        /// </summary>
        /// <param name="dwDesiredAccess">The desired access rights to the thread in question.</param>
        /// <param name="dwThreadId">The ID of the thread in question.</param>
        /// <returns>Returns a handle to the thread allowing manipulation.</returns>
        public static IntPtr OpenThread(Import.ThreadAccessFlags dwDesiredAccess, int dwThreadId)
        {
            return Import.OpenThread(dwDesiredAccess, false, (uint)dwThreadId);
        }

        /// <summary>
        /// Suspends execution of a given thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread that will be suspended.</param>
        /// <returns>Returns (DWORD)-1 on failure, otherwise the suspend count of the thread.</returns>
        public static uint SuspendThread(IntPtr hThread)
        {
            return Import.SuspendThread(hThread);
        }

        /// <summary>
        /// Resumes execution of a given thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread that will be suspended.</param>
        /// <returns>Returns (DWORD)-1 on failure, otherwise the previous suspend count of the thread.</returns>
        public static uint ResumeThread(IntPtr hThread)
        {
            return ResumeThread(hThread);
        }

        /// <summary>
        /// Terminates the specified thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread to exit.</param>
        /// <param name="dwExitCode">Exit code that will be stored in the thread object.</param>
        /// <returns>Returns zero on failure, non-zero on success.</returns>
        public static uint TerminateThread(IntPtr hThread, uint dwExitCode)
        {
            return TerminateThread(hThread, dwExitCode);
        }

        /// <summary>
        /// Gets the context of a given thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread for which the context will be returned.</param>
        /// <param name="ContextFlags">Determines which set(s) of registers will be returned.</param>
        /// <returns>Returns the context of the thread.  If failure, sets CONTEXT.ContextFlags to zero.</returns>
        public static Import.CONTEXT GetThreadContext(IntPtr hThread, uint ContextFlags)
        {
            Import.CONTEXT ctx = new Import.CONTEXT();
            ctx.ContextFlags = ContextFlags;

            if (!Import.GetThreadContext(hThread, ref ctx))
                ctx.ContextFlags = 0;

            return ctx;
        }

        /// <summary>
        /// Sets the context of a given thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread for which the context will be set.</param>
        /// <param name="ctx">CONTEXT structure to which the thread's context will be set.</param>
        /// <returns>Returns true on success, false on failure.</returns>
        public static bool SetThreadContext(IntPtr hThread, Import.CONTEXT ctx)
        {
            return Import.SetThreadContext(hThread, ref ctx);
        }

        /// <summary>
        /// Gets the exit code of the specified thread.
        /// </summary>
        /// <param name="hThread">Handle to the thread whose exit code is wanted.</param>
        /// <returns>Returns 0 on failure, non-zero on success.</returns>
        public static uint GetExitCodeThread(IntPtr hThread)
        {
            UIntPtr dwExitCode;
            if (!Import.GetExitCodeThread(hThread, out dwExitCode))
                throw new Exception("GetExitCodeThread failed.");
            return (uint)dwExitCode;
        }

        /// <summary>
        /// Waits for an object to enter a signaled state.
        /// </summary>
        /// <param name="hObject">The object for which to wait.</param>
        /// <returns>Returns one of the values in the static WaitValues class.</returns>
        public static Import.WaitResult WaitForSingleObject(IntPtr hObject)
        {
            /// <summary>
            /// Wait an infinite amount of time for the object to become signaled.
            /// </summary>
            uint INFINITE = 0xFFFFFFFF;

            return WaitForSingleObject(hObject, INFINITE);
        }

        /// <summary>
        /// Waits for an object to enter a signaled state.
        /// </summary>
        /// <param name="hObject">The object for which to wait.</param>
        /// <param name="dwMilliseconds">Number of milliseconds to wait.</param>
        /// <returns>Returns one of the values in the static WaitValues class.</returns>
        public static Import.WaitResult WaitForSingleObject(IntPtr hObject, uint dwMilliseconds)
        {
            return Import.WaitForSingleObject(hObject, dwMilliseconds);
        }
    }

    /// <summary>
    /// Read manager
    /// </summary>
    public class ReadMgr : hibClass
    {
        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// RefIntPtr
        /// </summary>
        private IntPtr _refIntPtr = IntPtr.Zero;


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public ReadMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Read a byte.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return byte readed from memory.</returns>
        public Byte Byte(IntPtr argAddress)
        {
            //Return
            return Byte(argAddress, 0);
        }

        /// <summary>
        /// Read a byte at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return byte readed from memory.</returns>
        public Byte Byte(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[1];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Return Byte
            return buffer[0];
        }

        /// <summary>
        /// Read a bytes array.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argSize">Size</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return byte Array readed from memory.</returns>
        public Byte[] Bytes(IntPtr argAddress, UInt32 argSize)
        {
            //Return
            return Bytes(argAddress, argSize, 0);
        }

        /// <summary>
        /// Read a bytes array at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argSize">Size</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return byte array readed from memory.</returns>
        public Byte[] Bytes(IntPtr argAddress, UInt32 argSize, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[argSize];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, argSize, out _refIntPtr);

            //Return Bytes Array
            return buffer;
        }

        /// <summary>
        /// Read a short.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return short readed from memory.</returns>
        public Int16 Short(IntPtr argAddress)
        {
            //Return
            return Short(argAddress, 0);
        }

        /// <summary>
        /// Read a short at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return short readed from memory.</returns>
        public Int16 Short(IntPtr argAddress, UInt16 argOffset)
        {
            //Return Short
            return BitConverter.ToInt16(Bytes(IntPtr.Add(argAddress, argOffset), 2), 0);
        }

        /// <summary>
        /// Read a unsigned short.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return ushort readed from memory.</returns>
        public UInt16 UShort(IntPtr argAddress)
        {
            //Return
            return UShort(argAddress, 0);
        }

        /// <summary>
        /// Read a unsigned short at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return ushort readed from memory.</returns>
        public UInt16 UShort(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[2];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //return UShort
            return BitConverter.ToUInt16(buffer, 0);
        }

        /// <summary>
        /// Read a integer.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return integer readed from memory.</returns>
        public Int32 Integer(IntPtr argAddress)
        {
            //Return
            return Integer(argAddress, 0);
        }

        /// <summary>
        /// Read a integer at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return integer readed from memory.</returns>
        public Int32 Integer(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[4];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Return Integer
            return BitConverter.ToInt32(buffer, 0);
        }

        /// <summary>
        /// Read a unsigned integer.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return uinteger readed from memory.</returns>
        public UInt32 UInteger(IntPtr argAddress)
        {
            //Return
            return UInteger(argAddress, 0);
        }

        /// <summary>
        /// Read a unsigned integer at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return uinteger readed from memory.</returns>
        public UInt32 UInteger(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[4];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Return UInteger
            return BitConverter.ToUInt32(buffer, 0);
        }

        /// <summary>
        /// Read a long.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return long readed from memory.</returns>
        public Int64 Long(IntPtr argAddress)
        {
            //Return
            return Long(argAddress, 0);
        }

        /// <summary>
        /// Read a long at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return long readed from memory.</returns>
        public Int64 Long(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[8];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Return Long
            return BitConverter.ToInt64(buffer, 0);
        }

        /// <summary>
        /// Read a unsigned long.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return ulong readed from memory.</returns>
        public UInt64 ULong(IntPtr argAddress)
        {
            //Return
            return ULong(argAddress, 0);
        }

        /// <summary>
        /// Read a unsigned long at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return ulong readed from memory.</returns>
        public UInt64 ULong(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[8];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Return ULong
            return BitConverter.ToUInt64(buffer, 0);
        }

        /// <summary>
        /// Read a single.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return single readed from memory.</returns>
        public Single Single(IntPtr argAddress)
        {
            //Return
            return Single(argAddress, 0);
        }

        /// <summary>
        /// Read a single at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return single readed from memory.</returns>
        public Single Single(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[4];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Return Single
            return BitConverter.ToSingle(buffer, 0);
        }

        /// <summary>
        /// Read a double.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return double readed from memory.</returns>
        public Double Double(IntPtr argAddress)
        {
            //Return
            return Double(argAddress, 0);
        }

        /// <summary>
        /// Read a double at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return double readed from memory.</returns>
        public Double Double(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[8];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Return Double
            return BitConverter.ToDouble(buffer, 0);
        }

        /// <summary>
        /// Read a unicode char.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return unicode char readed from memory.</returns>
        public Char UnicodeChar(IntPtr argAddress)
        {
            //Return
            return UnicodeChar(argAddress, 0);
        }

        /// <summary>
        /// Read a unicode char at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return unicode Char readed from memory.</returns>
        public Char UnicodeChar(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[2];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Create Converter Object
            Encoding Unicode = Encoding.Unicode;

            //Return Char
            return Unicode.GetChars(buffer)[0];
        }

        /// <summary>
        /// Read a unicode string.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argLenght">Lenght</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return unicode string readed from memory.</returns>
        public String UnicodeString(IntPtr argAddress, UInt32 argLenght)
        {
            //Return
            return UnicodeString(argAddress, argLenght, 0);
        }

        /// <summary>
        /// Read a unicode string at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argLenght">Lenght</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return unicode string readed from memory.</returns>
        public String UnicodeString(IntPtr argAddress, UInt32 argLenght, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[argLenght * 2];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, argLenght * 2, out _refIntPtr);

            //Create Converter Object
            Encoding Unicode = Encoding.Unicode;

            //Return String
            return Unicode.GetString(buffer);
        }

        /// <summary>
        /// Read a ASCII char.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return ascii char readed from memory.</returns>
        public Char AsciiChar(IntPtr argAddress)
        {
            //Return
            return AsciiChar(argAddress, 0);
        }

        /// <summary>
        /// Read a ASCII char at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return ascii char readed from memory.</returns>
        public Char AsciiChar(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[1];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Decode Object
            System.Text.ASCIIEncoding ASCII = new System.Text.ASCIIEncoding();

            //Return Char
            return ASCII.GetChars(buffer)[0];
        }

        /// <summary>
        /// Read a ASCII string.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argLenght">Lenght</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return ascii string readed from memory.</returns>
        public String AsciiString(IntPtr argAddress, UInt32 argLenght)
        {
            //Return
            return AsciiString(argAddress, argLenght, 0);
        }

        /// <summary>
        /// Read a ASCII string at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argLenght">Lenght</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return ascii string readed from memory.</returns>
        public String AsciiString(IntPtr argAddress, UInt32 argLenght, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[argLenght];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)argLenght, out _refIntPtr);

            //Decode Object
            System.Text.ASCIIEncoding ASCII = new System.Text.ASCIIEncoding();


            //Return Char
            return ASCII.GetString(buffer);
        }

        /// <summary>
        /// Read a Structure.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return structure readed from memory.</returns>
        public T Structure<T>(IntPtr argAddress)
        {
            //Return
            return Structure<T>(argAddress, 0);
        }

        /// <summary>
        /// Read a Structure at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return structure readed from memory.</returns>
        public T Structure<T>(IntPtr argAddress, UInt16 argOffset)
        {
            //Create Buffer
            byte[] buffer = new byte[Marshal.SizeOf(typeof(T))];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Return
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return theStructure;
        }

        /// <summary>
        /// Read a type.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return type readed from memory.</returns>
        public T Types<T>(IntPtr argAddress)
        {
            //Return
            return Types<T>(argAddress, 0);
        }

        /// <summary>
        /// Read a type at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return type readed from memory.</returns>
        public T Types<T>(IntPtr argAddress, UInt16 argOffset)
        {
            object ret;

            // Handle types that don't have a real typecode
            // and/or can be done without the ReadByte bullshit
            if (typeof(T) == typeof(IntPtr))
            {
                ret = Marshal.ReadIntPtr(IntPtr.Add(argAddress, argOffset));
                return (T)ret;
            }

            if (typeof(T) == typeof(string))
            {
                byte[] buffer = new byte[1024];
                Marshal.Copy(IntPtr.Add(argAddress, argOffset), buffer, 0, 1024);

                int index = 0;
                foreach (var b in buffer)
                {
                    if (b == 0x00)
                        break;
                    index++;
                }

                byte[] convert = new byte[index];
                Array.Copy(buffer, convert, index);

                ret = Encoding.UTF8.GetString(convert);
                return (T)ret;
            }

            int size = Marshal.SizeOf(typeof(T));
            byte[] ba = Bytes(IntPtr.Add(argAddress, argOffset), (uint)size);

            switch (Type.GetTypeCode(typeof(T)))
            {
                case TypeCode.Boolean:
                    ret = BitConverter.ToBoolean(ba, 0);
                    break;
                case TypeCode.Char:
                    ret = BitConverter.ToChar(ba, 0);
                    break;
                case TypeCode.Byte:
                    ret = ba[0];
                    break;
                case TypeCode.Int16:
                    ret = BitConverter.ToInt16(ba, 0);
                    break;
                case TypeCode.UInt16:
                    ret = BitConverter.ToUInt16(ba, 0);
                    break;
                case TypeCode.Int32:
                    ret = BitConverter.ToInt32(ba, 0);
                    break;
                case TypeCode.UInt32:
                    ret = BitConverter.ToUInt32(ba, 0);
                    break;
                case TypeCode.Int64:
                    ret = BitConverter.ToInt64(ba, 0);
                    break;
                case TypeCode.UInt64:
                    ret = BitConverter.ToUInt64(ba, 0);
                    break;
                case TypeCode.Single:
                    ret = BitConverter.ToSingle(ba, 0);
                    break;
                case TypeCode.Double:
                    ret = BitConverter.ToDouble(ba, 0);
                    break;
                default:
                    throw new NotSupportedException(typeof(T).FullName + " is not currently supported by Read<T>");
            }
            return (T)ret;
        }

        /// <summary>
        /// Read a boolean.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return Boolean readed from memory.</returns>
        public Boolean Boolean(IntPtr argAddress)
        {
            //Return
            return Boolean(argAddress, 0);
        }

        /// <summary>
        /// Read a boolean at a specific offset.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argOffset">Offset</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return Boolean readed from memory.</returns>
        public Boolean Boolean(IntPtr argAddress, UInt16 argOffset)
        {
            //Return Buffer
            byte[] buffer = new byte[1];

            //Read
            Import.ReadProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, argOffset), buffer, (uint)buffer.Length, out _refIntPtr);

            //Return Boolean
            if (buffer[0] == 1) return true;
            else return false;
        }
    }

    /// <summary>
    /// Write manager
    /// </summary>
    public class WriteMgr : hibClass
    {
        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// RefIntPtr
        /// </summary>
        private IntPtr _refIntPtr = IntPtr.Zero;


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public WriteMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Write a byte.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argByte">Byte</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void Byte(IntPtr argAddress, Byte argByte)
        {
            //Set Buffer
            byte[] buffer = new byte[1];

            //Set Buffer Data
            buffer[0] = argByte;

            //Write Byte
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, buffer, 1, out _refIntPtr);
        }

        /// <summary>
        /// Write a bytes array.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argArray">Byte array</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void Bytes(IntPtr argAddress, Byte[] argArray)
        {
            //Write Bytes
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, argArray, (uint)argArray.Length, out _refIntPtr);
        }

        /// <summary>
        /// Write a short.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argShort">Short</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void Short(IntPtr argAddress, Int16 argShort)
        {
            //Write Short
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argShort), 2, out _refIntPtr);
        }

        /// <summary>
        /// Write a unsigned short.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argUShort">UShort</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void UShort(IntPtr argAddress, UInt16 argUShort)
        {
            //Write UShort
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argUShort), 2, out _refIntPtr);
        }

        /// <summary>
        /// Write a integer.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argInteger">Integer</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void Integer(IntPtr argAddress, Int32 argInteger)
        {
            //Write Integer
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argInteger), 4, out _refIntPtr);
        }

        /// <summary>
        /// Write a unsigned integer.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argUInteger">UInteger</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void UInteger(IntPtr argAddress, UInt32 argUInteger)
        {
            //Write UInteger
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argUInteger), 4, out _refIntPtr);
        }

        /// <summary>
        /// Write a long.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argLong">Long</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void Long(IntPtr argAddress, Int64 argLong)
        {
            //Write Long
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argLong), 8, out _refIntPtr);
        }

        /// <summary>
        /// Write a unsigned Long.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argULong">ULong</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void ULong(IntPtr argAddress, UInt64 argULong)
        {
            //Write ULong
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argULong), 8, out _refIntPtr);
        }

        /// <summary>
        /// Write a single.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argSingle">Single</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void Single(IntPtr argAddress, Single argSingle)
        {
            //Write Single
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argSingle), 4, out _refIntPtr);
        }

        /// <summary>
        /// Write a double.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argDouble">Double</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void Double(IntPtr argAddress, Double argDouble)
        {
            //Write Double
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argDouble), 8, out _refIntPtr);
        }

        /// <summary>
        /// Write a unicode char.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argChar">Character</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Returns true on success, false on failure.</returns>
        public void UnicodeChar(IntPtr argAddress, Char argChar)
        {
            //Write Char
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argChar), 2, out _refIntPtr);
        }

        /// <summary>
        /// Write a unicode string.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argString">String</param>
        /// <param name="argAddZeroEnding">Set it true if you want add a double null at end .</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void UnicodeString(IntPtr argAddress, string argString, bool argAddZeroEnding)
        {
            //Create buffer
            byte[] buffer = null;

            //Write buffer
            foreach (char ActualChar in argString)
            {
                buffer.SetValue(BitConverter.GetBytes(ActualChar), buffer.Length);
            }

            //Write String
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, buffer, (uint)buffer.Length, out _refIntPtr);

            //Check if we must ending line
            byte[] endingLine = new byte[2] { 0x00, 0x00 };
            if (argAddZeroEnding) Import.WriteProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, buffer.Length), endingLine, (uint)endingLine.Length, out _refIntPtr);
        }

        /// <summary>
        /// Write a ascii char.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argChar">Character</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void AsciiChar(IntPtr argAddress, Char argChar)
        {
            //Create CharArray
            string TemporaryString = Convert.ToString(argChar);

            //Create Buffer
            byte[] bBuffer = Encoding.ASCII.GetBytes(TemporaryString);

            //Write ASCIIString
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, bBuffer, (uint)bBuffer.Length, out _refIntPtr);
        }

        /// <summary>
        /// Write a ascii string.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argSentence">String</param>
        /// <param name="argAddZeroEnding">Set it true if you want add a null at end .</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void ASCIIString(IntPtr argAddress, string argSentence, bool argAddZeroEnding)
        {
            //Create Buffer
            byte[] bBuffer = Encoding.ASCII.GetBytes(argSentence);

            //Write ASCIIString
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, bBuffer, (uint)bBuffer.Length, out _refIntPtr);

            //Check if we must add null at end
            byte[] EndBuffer = new byte[1] { 0x00 };
            if (argAddZeroEnding) Import.WriteProcessMemory(Parent.OperationHandle, IntPtr.Add(argAddress, bBuffer.Length), EndBuffer, (uint)EndBuffer.Length, out _refIntPtr);
        }

        /// <summary>
        /// Write a boolean.
        /// </summary>
        /// <param name="argAddress">Address</param>
        /// <param name="argBool">Boolean</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public void Boolean(IntPtr argAddress, Boolean argBool)
        {
            //Write Boolean
            Import.WriteProcessMemory(Parent.OperationHandle, argAddress, BitConverter.GetBytes(argBool), 1, out _refIntPtr);
        }
    }

    /// <summary>
    /// Injections manager
    /// </summary>
    public class InjectionsMgr : hibClass
    {
        //-----------------------------------------
        //--------------- Defines -----------------
        /// <summary>
        /// RefIntPtr
        /// </summary>
        private IntPtr _refIntPtr = IntPtr.Zero;


        //-----------------------------------------
        //---------------- Voids ------------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public InjectionsMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Inject unmanaged file to a process and initialize a new thread.
        /// </summary>
        /// <param name="argFilePath">File</param>
        /// <returns>Return base adress of the injected code.</returns>
        /// <remarks>Process acces need CreateThread, QueryInformation,Set Information,VMOperation,VMRead,VMWrite !</remarks>
        public IntPtr InjectDllFile(string argFilePath)
        {
            //Open File
            FileStream FileData = File.OpenRead(argFilePath);

            //Create By Array
            byte[] Bytes = new byte[FileData.Length];

            //Reading
            FileData.Read(Bytes, 0, Convert.ToInt32(FileData.Length));

            //Close File
            FileData.Close();

            //Inject
            return InjectBytes(Bytes);
        }

        /// <summary>
        /// Inject unmanaged code as bytes to a process and initialize a new thread.
        /// </summary>
        /// <param name="argBytes">Bytes Array</param>
        /// <returns>Return base adress of the injected code.</returns>
        /// <remarks>Process acces need CreateThread, QueryInformation,Set Information,VMOperation,VMRead,VMWrite !</remarks>
        public IntPtr InjectBytes(byte[] argBytes)
        {
            try
            {
                //Get KernelModuleAdress
                IntPtr kernelAddress = Import.GetProcAddress(Import.GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                //Check if KernelModuleAdress was find
                if (kernelAddress == IntPtr.Zero) return IntPtr.Zero;

                //Allocate Memory
                IntPtr allocatedMemory = Parent.Regions.AllocateMemory((UIntPtr)argBytes.Length, Import.AllocationType.MEM_COMMIT | Import.AllocationType.MEM_RESERVE, Import.MemoryProtect.PAGE_EXECUTE_READWRITE);

                //Check if a Memory Region was Allocate
                if (allocatedMemory == IntPtr.Zero) return IntPtr.Zero;

                //Write Data
                Import.WriteProcessMemory(
                    Parent.OperationHandle,
                    allocatedMemory,
                    argBytes,
                    (uint)argBytes.Length,
                    out _refIntPtr);

                //Create Thread
                IntPtr thread = Import.CreateRemoteThread(
                    Parent.OperationHandle,
                    (IntPtr)null,
                    0,
                    kernelAddress,
                    allocatedMemory,
                    Import.ThreadCreationFlags.THREAD_EXECUTE_IMMEDIATELY,
                    out _refIntPtr);

                //Check if Thread was create
                if (thread == IntPtr.Zero) return IntPtr.Zero;

                //Return
                return allocatedMemory;
            }
            catch
            {
                //Return
                return IntPtr.Zero;
            }
        }
    }

    /// <summary>
    /// Patchs manager
    /// </summary>
    public class PatchsMgr : hibClass
    {
        //-----------------------------------------
        //--------------- Objects -----------------
        /// <summary>
        /// Patch
        /// </summary>
        public class Patch : hibClass
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// Name
            /// </summary>
            private string _name = "";

            /// <summary>
            /// Address
            /// </summary>
            private IntPtr _address = IntPtr.Zero;

            /// <summary>
            /// OriginalBytes
            /// </summary>
            private byte[] _originalBytes;

            /// <summary>
            /// PatchBytes
            /// </summary>
            private byte[] _patchBytes;

            /// <summary>
            /// IsEnable
            /// </summary>
            private bool _isEnable = false;

            /// <summary>
            /// DisableOnDispose
            /// </summary>
            private bool _disableOnDispose = true;

            /// <summary>
            /// Name
            /// </summary>
            public string Name
            {
                get
                {
                    //Return
                    return _name;
                }
                set
                {
                }
            }

            /// <summary>
            /// Address
            /// </summary>
            public IntPtr Adress
            {
                get
                {
                    //Return
                    return _address;
                }
                set
                {
                }
            }

            /// <summary>
            /// OriginalBytes
            /// </summary>
            public byte[] OriginalBytes
            {
                get
                {
                    //Return
                    return _originalBytes;
                }
                set
                {
                }
            }

            /// <summary>
            /// PatchBytes
            /// </summary>
            public byte[] PatchBytes
            {
                get
                {
                    //Return
                    return _patchBytes;
                }
                set
                {
                }
            }

            /// <summary>
            /// IsEnable
            /// </summary>
            public bool IsEnable
            {
                get
                {
                    //Return
                    return _isEnable;
                }
                set
                {
                }
            }

            /// <summary>
            /// DisableOnDispose
            /// </summary>
            public bool DisableOnDispose
            {
                get
                {
                    //Return
                    return _disableOnDispose;
                }
                set
                {
                    //Set _disableOnDispose
                    _disableOnDispose = value;
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="argParent">hibProcess</param>
            /// <param name="argName">Name</param>
            /// <param name="argAddress">Address</param>
            /// <param name="argPatchBytes">PatchBytes</param>
            public Patch(hibProcess argParent, string argName, IntPtr argAddress, byte[] argPatchBytes) : base(argParent)
            {
                //Set values
                _name = argName;
                _address = argAddress;
                _patchBytes = argPatchBytes;
            }

            /// <summary>
            /// Destructor
            /// </summary>
            ~Patch()
            {
                //Remove from list
                lock (Parent.Patchs.Patchs)
                {
                    if (Parent.Patchs.Patchs.Contains(this)) Parent.Patchs.Patchs.Remove(this);
                }

                //Disable if necessary
                if (_isEnable && _disableOnDispose)
                {
                    Disable();
                }
            }

            /// <summary>
            /// Enable
            /// </summary>
            /// <remarks>Throw an exception on failure.</remarks>
            public void Enable()
            {
                //Verify _isEnable
                if (_isEnable)
                {
                    throw new Exception("Patch already enable !");
                }

                //Get old protections and set new protections
                uint OldProtection;
                Parent.Regions.VirtualProtectEx((IntPtr)_address, _patchBytes.Length, (uint)Import.MemoryProtect.PAGE_EXECUTE_WRITECOPY, out OldProtection);

                //Read original bytes
                _originalBytes = Parent.Read.Bytes((IntPtr)_address, (uint)_patchBytes.Length);

                //Write
                Parent.Write.Bytes((IntPtr)_address, PatchBytes);

                //Set _isEnable
                _isEnable = true;

                //Set old Protection
                uint OldOldProtection;
                Parent.Regions.VirtualProtectEx((IntPtr)_address, _patchBytes.Length, (uint)OldProtection, out OldOldProtection);
            }

            /// <summary>
            /// Disable
            /// </summary>
            /// <remarks>Throw an exception on failure.</remarks>
            public bool Disable()
            {
                //Get old protections and set new protections
                uint OldProtection;
                Parent.Regions.VirtualProtectEx((IntPtr)_address, _originalBytes.Length, (uint)Import.MemoryProtect.PAGE_EXECUTE_READWRITE, out OldProtection);

                //UnPatch
                Parent.Write.Bytes((IntPtr)_address, _originalBytes);

                //Set _isEnable
                _isEnable = false;

                //Set old Protection
                Parent.Regions.VirtualProtectEx((IntPtr)_address, _originalBytes.Length, (uint)OldProtection, out OldProtection);

                //Return true
                return true;
            }
        }


        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// A list with all patchs created for the current process.
        /// </summary>
        private List<Patch> _patchs = new List<Patch>();

        /// <summary>
        /// A list with all patchs created for the current process.
        /// </summary>
        public List<Patch> Patchs
        {
            get
            {
                //Return
                return _patchs;
            }
            set
            {
            }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public PatchsMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Create patch
        /// </summary>
        /// <param name="argName">Name</param>
        /// <param name="argAddress">Address</param>
        /// <param name="argPatchBytes">PatchBytes</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Returns Patch on success, throw an exception on failure.</returns>
        public Patch CreatePatch(string argName, IntPtr argAddress, byte[] argPatchBytes)
        {
            //Create new Patch
            Patch p = new Patch(Parent, argName, argAddress, argPatchBytes);

            //Add it the list
            lock (_patchs)
            {
                _patchs.Add(p);
            }

            //Return
            return p;
        }

        /// <summary>
        /// Create patch from a specific pattern.
        /// </summary>
        /// <param name="argName">Name</param>
        /// <param name="argPattern">Pattern</param>
        /// <param name="argPatchBytes">PatchBytes</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Returns Patch on success, throw an exception on failure.</returns>
        public Patch CreatePatchFromPattern(string argName, PatternsMgr.Pattern argPattern, byte[] argPatchBytes)
        {
            //Create new Patch
            Patch p = new Patch(Parent, argName, argPattern.Adress, argPatchBytes);

            //Add it the list
            lock (_patchs)
            {
                _patchs.Add(p);
            }

            //Return
            return p;
        }

        /// <summary>
        /// Retrieve a specific patch from his name.
        /// </summary>
        /// <param name="argName">Name</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return patch found, null if not.</returns>
        public Patch GetPatchfromName(string argName)
        {
            //Browse _patchs
            lock (_patchs)
            {
                foreach (Patch p in _patchs)
                {
                    if (p.Name == argName)
                    {
                        //Return
                        return p;
                    }
                }
            }

            //Return
            return null;
        }
    }

    /// <summary>
    /// Patterns manager
    /// </summary>
    public class PatternsMgr : hibClass
    {
        //-----------------------------------------
        //---------------- Enums ------------------
        /// <summary>
        /// Define a specific scan mode to retrieve pattern(s) addresses.
        /// </summary>
        public enum ScanMode : uint
        {
            /// <summary>
            /// Search patterns with a static offset mode.
            /// </summary>
            StaticsOffsets = 0x0004
        }


        //-----------------------------------------
        //--------------- Objects -----------------
        /// <summary>
        /// Contain a patterns and some additional informations about it.
        /// </summary>
        public class Pattern : hibClass
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// Name
            /// </summary>
            private string _name = "";

            /// <summary>
            /// Name
            /// </summary>
            public string Name
            {
                get
                {
                    //Return
                    return _name;
                }
                set
                {
                }
            }

            /// <summary>
            /// Adress
            /// </summary>
            private IntPtr _adress = IntPtr.Zero;

            /// <summary>
            /// Adress
            /// </summary>
            public IntPtr Adress
            {
                get
                {
                    //Return
                    return _adress;
                }
                set
                {
                    //Set _Adress
                    _adress = value;
                }
            }

            /// <summary>
            /// Contain the list of static's offsets value for the search.
            /// </summary>
            private List<ByteInfo> _staticOffsets = new List<ByteInfo>();

            /// <summary>
            /// Contain the list of static's offsets value for the search.
            /// </summary>
            public List<ByteInfo> StaticOffsets
            {
                get
                {
                    //Return
                    return _staticOffsets;
                }
                set
                {
                    //Set _staticOffsets
                    _staticOffsets = value;
                }
            }

            /// <summary>
            /// Added value to adress when pattern is found.
            /// </summary>
            /// <remarks>This value can be negative.</remarks>
            private int _summary = 0;

            /// <summary>
            /// Added value to adress when pattern is found.
            /// </summary>
            /// <remarks>This value can be negative.</remarks>
            public int Summary
            {
                get
                {
                    //Return
                    return _summary;
                }
                set
                {
                    //Set _summary
                    _summary = value;
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="argParent">hibProcess</param>
            /// <param name="argName">Name</param>
            public Pattern(hibProcess argParent, string argName) : base(argParent)
            {
                //Set values
                _name = argName;
            }

            /// <summary>
            /// Destructor
            /// </summary>
            ~Pattern()
            {
                //Remove from list
                lock (Parent.Patterns.Patterns) { if (Parent.Patterns.Patterns.Contains(this)) Parent.Patterns.Patterns.Remove(this); }
            }

            /// <summary>
            /// Set StaticOffsets from a string format like "A5 FF 78 23 F4 ?? ?? E9 46".
            /// </summary>
            /// <remarks>?? equal to a unknow byte</remarks>
            /// <param name="argBytes">String</param>
            /// <returns>Return true if succeed , throw an exception on failure.</returns>
            public bool SetStaticOffsetsFromString(string argBytes)
            {
                //Split
                List<ByteInfo> list = new List<ByteInfo>();
                int index = 0;
                foreach (string s in argBytes.Split(' '))
                {
                    if (s != "??")
                    {
                        list.Add(new ByteInfo(index, Converter.HexaStringToDec32(s)));
                    }
                    index += 1;
                }

                //Set _staticOffsets
                _staticOffsets = list;

                //Return
                return true;
            }
        }

        /// <summary>
        /// ByteInfo
        /// </summary>
        public class ByteInfo
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// Position
            /// </summary>
            private int _position;

            /// <summary>
            /// Position
            /// </summary>
            public int Postion
            {
                get
                {
                    //Return
                    return _position;
                }
                set
                {
                    //Empty
                }
            }

            /// <summary>
            /// Value
            /// </summary>
            private int _value;

            /// <summary>
            /// Value
            /// </summary>
            public int Value
            {
                get
                {
                    //Return
                    return _value;
                }
                set
                {
                    //Empty
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="argPosition">Offset position</param>
            /// <param name="argValue">Offset data</param>
            public ByteInfo(int argPosition, int argValue)
            {
                _position = argPosition;
                _value = argValue;
            }
        }


        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// Patterns
        /// </summary>
        private List<Pattern> _patterns = new List<Pattern>();

        /// <summary>
        /// Patterns
        /// </summary>
        public List<Pattern> Patterns
        {
            get
            {
                //Return
                return _patterns;
            }
            set
            {
                //Empty
            }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public PatternsMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Create a new pattern.
        /// </summary>
        /// <param name="argName">Name</param>
        /// <returns>Return pattern if succeed , throw an exception on failure.</returns>
        public Pattern CreatePattern(string argName)
        {
            //Create pattern
            Pattern pat = new Pattern(Parent, argName);

            //Add it to the list
            lock (_patterns)
            {
                _patterns.Add(pat);
            }

            //Return
            return pat;
        }

        /// <summary>
        /// Retrieve a specific pattern from his name.
        /// </summary>
        /// <param name="argName">Name</param>
        /// <returns>Return pattern found, null if not.</returns>
        public Pattern GetPatternByName(string argName)
        {
            //Browse patterns
            lock (_patterns)
            {
                foreach (Pattern Pa in _patterns)
                {
                    if (Pa.Name == argName)
                    {
                        //Return
                        return Pa;
                    }
                }
            }

            //Return
            return null;
        }

        /// <summary>
        /// Scan a specific region with a specific scan mode.
        /// </summary>
        /// <param name="argRegion">Region</param>
        /// <param name="argMode">Scan mode</param>
        /// <returns>Return true if succeed , false on failure.</returns>
        public bool ScanRegion(RegionsMgr.Region argRegion, ScanMode argMode)
        {
            //Return
            return ScanRegion(argRegion, argMode, _patterns);
        }

        /// <summary>
        /// Scan a specific region with a specific scan mode and put the result into a specific patterns list.
        /// </summary>
        /// <param name="argRegion">Region</param>
        /// <param name="argMode">Scan mode</param>
        /// <param name="argPatterns">Patterns</param>
        /// <returns>Return true if succeed , false on failure.</returns>
        public bool ScanRegion(RegionsMgr.Region argRegion, ScanMode argMode, List<Pattern> argPatterns)
        {
            try
            {
                //Scan
                if (argMode == ScanMode.StaticsOffsets)
                {
                    ScanStaticsOffsets(argRegion, argPatterns);
                }

                //Return
                return true;
            }
            catch
            {
                //Return
                return false;
            }
        }

        /// <summary>
        /// Scan commited regions.
        /// </summary>
        /// <returns>Return true if succeed , false on failure.</returns>
        public bool ScanRegions()
        {
            return ScanRegions(ScanMode.StaticsOffsets);
        }

        /// <summary>
        /// Scan commited regions with a specific scan mode.
        /// </summary>
        /// <param name="argMode">Scan mode</param>
        /// <returns>Return true if succeed , false on failure.</returns>
        public bool ScanRegions(ScanMode argMode)
        {
            //Return
            return ScanRegions(argMode, Import.MemoryState.MEM_COMMIT, 0);
        }

        /// <summary>
        /// Scan specifics regions with a specific scan mode.
        /// </summary>
        /// <param name="argMode">Scan mode</param>
        /// <param name="argRegionState">Region State required</param>
        /// <param name="argRegionProtection">Region Protection required</param>
        /// <returns>Return true if succeed , false on failure.</returns>
        public bool ScanRegions(ScanMode argMode, Import.MemoryState argRegionState, Import.MemoryProtect argRegionProtection)
        {
            //Return
            return ScanRegions(argMode, Import.MemoryState.MEM_COMMIT, 0, _patterns);
        }

        /// <summary>
        /// Scan specifics regions with a specific scan mode.
        /// </summary>
        /// <param name="argMode">Scan mode</param>
        /// <param name="argRegionState">Region State required</param>
        /// <param name="argRegionProtection">Region Protection required</param>
        /// <param name="argPatterns">Patterns</param>
        /// <returns>Return true if succeed , false on failure.</returns>
        public bool ScanRegions(ScanMode argMode, Import.MemoryState argRegionState, Import.MemoryProtect argRegionProtection, List<Pattern> argPatterns)
        {
            //Filters
            bool Filter_State_Enable = false;
            bool Filter_Protect_Enable = false;
            if (argRegionState != 0) Filter_State_Enable = true;
            if (argRegionProtection != 0) Filter_Protect_Enable = true;

            //Scan
            foreach (RegionsMgr.Region Mem in Parent.Regions.All)
            {
                //Check Filter
                if (Filter_State_Enable && Mem.State != argRegionState)
                {
                    continue;
                }
                if (Filter_Protect_Enable && Mem.Protect != argRegionProtection)
                {
                    continue;
                }

                //Scan region
                ScanRegion(Mem, argMode, argPatterns);

                //Check if all patterns found
                bool AllFound = true;
                foreach (Pattern p in argPatterns)
                {
                    if (p.Adress == IntPtr.Zero) AllFound = false;
                }
                if (AllFound)
                {
                    break;
                }

            }

            //Return True
            return true;
        }

        /// <summary>
        /// Scan a module with a specific scan mode.
        /// </summary>
        /// <param name="argModule">Module</param>
        /// <returns>Return true if succeed , false on failure.</returns>
        public bool ScanModule(ModulesMgr.Module argModule)
        {
            //Return
            return ScanModule(argModule, ScanMode.StaticsOffsets);
        }

        /// <summary>
        /// Scan a module with a specific scan mode.
        /// </summary>
        /// <param name="argModule">Module</param>
        /// <param name="argMode">Scan mode</param>
        /// <returns>Return true if succeed , false on failure.</returns>
        public bool ScanModule(ModulesMgr.Module argModule, ScanMode argMode)
        {
            //Return
            return ScanModule(argModule, argMode, _patterns);
        }

        /// <summary>
        /// Scan a module with a specific scan mode and put the result into a specific patterns list.
        /// </summary>
        /// <param name="argModule">Module</param>
        /// <param name="argMode">Scan mode</param>
        /// <param name="argPatterns">Patterns</param>
        /// <returns>Return true if succeed , false on failure.</returns>
        public bool ScanModule(ModulesMgr.Module argModule, ScanMode argMode, List<Pattern> argPatterns)
        {
            try
            {
                //Scan
                foreach (RegionsMgr.Region r in argModule.Regions)
                {
                    //Scan
                    ScanRegion(r, argMode, argPatterns);

                    //Check if all patterns found
                    bool AllFound = true;
                    foreach (Pattern p in argPatterns)
                    {
                        if (p.Adress == IntPtr.Zero) AllFound = false;
                    }
                    if (AllFound)
                    {
                        break;
                    }
                }

                //Return
                return true;
            }
            catch
            {
                //Return
                return false;
            }
        }

        /// <summary>
        /// Search patterns with a static offsets search.
        /// </summary>
        /// <param name="argRegion">Region</param>
        /// <param name="argPatterns">Patterns</param>
        public void ScanStaticsOffsets(RegionsMgr.Region argRegion, List<Pattern> argPatterns)
        {
            //Read memory
            byte[] data = argRegion.Read();

            //Scan
            try
            {
                for (int i = 0; i < data.Length; i++)
                {
                    //Check Pattern
                    foreach (Pattern p in argPatterns)
                    {
                        //Check Adress is in Range
                        if ((p.Adress == IntPtr.Zero))
                        {
                            //Set Bool Value
                            bool Valid = true;

                            //Check for each offsets
                            foreach (ByteInfo NewByte in p.StaticOffsets)
                            {
                                if (i + NewByte.Postion > data.Length)
                                {
                                    Valid = false;
                                    break;
                                }
                                if (data[i + NewByte.Postion] != NewByte.Value)
                                {
                                    Valid = false;
                                    break;
                                }
                            }

                            //Check it's valid
                            if (Valid == true)
                            {
                                p.Adress = argRegion.BaseAddress + i + p.Summary;
                            }
                        }
                    }

                }
            }
            catch
            {
            }
            finally
            {
                //Dispose data
                data = null;
            }
        }
    }

    /// <summary>
    /// Keyboard manager
    /// </summary>
    public class KeyboardMgr : hibClass
    {
        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public KeyboardMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Send a string with SendKey.
        /// </summary>
        /// <param name="argKeys">Keys</param>
        public void SendKeys_SendKey(string argKeys)
        {
            System.Windows.Forms.SendKeys.Send(argKeys);
        }

        /// <summary>
        /// Press a key with Keybd_Event.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void KeybdEvent_KeyPress(Keys argKey)
        {
            Import.keybd_event((byte)argKey, 0x45, 0, (UIntPtr)0);
            Import.keybd_event((byte)argKey, 0x45, (uint)Import.KEYEVENTF.KEYUP, (UIntPtr)0);
        }

        /// <summary>
        /// Press a key with Keybd_Event.
        /// </summary>
        /// <param name="argVirtualKey">VirtualKey</param>
        public void KeybdEvent_KeyPress(Import.VirtualKeys argVirtualKey)
        {
            Import.keybd_event((byte)argVirtualKey, 0x45, 0, (UIntPtr)0);
            Import.keybd_event((byte)argVirtualKey, 0x45, (uint)Import.KEYEVENTF.KEYUP, (UIntPtr)0);
        }

        /// <summary>
        /// Down a key down with Keybd_Event.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void KeybdEvent_KeyDown(Keys argKey)
        {
            Import.keybd_event((byte)argKey, 0x45, 0, (UIntPtr)0);
        }

        /// <summary>
        /// Down a key down with Keybd_Event.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void KeybdEvent_KeyDown(Import.VirtualKeys argKey)
        {
            Import.keybd_event((byte)argKey, 0x45, 0, (UIntPtr)0);
        }

        /// <summary>
        /// Up a key up with Keybd_Event.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void KeybdEvent_KeyUp(Keys argKey)
        {
            Import.keybd_event((byte)argKey, 0x45, (uint)Import.KEYEVENTF.KEYUP, (UIntPtr)0);
        }

        /// <summary>
        /// Up a key up with Keybd_Event.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void KeybdEvent_KeyUp(Import.VirtualKeys argKey)
        {
            Import.keybd_event((byte)argKey, 0x45, (uint)Import.KEYEVENTF.KEYUP, (UIntPtr)0);
        }

        /// <summary>
        /// Press a Key with SendInput.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void SendInput_KeyPress(Import.VirtualKeys argKey)
        {
            Import.INPUT input0 = new Import.INPUT();
            input0.type = Import.InputType.INPUT_KEYBOARD;
            input0.ki.wVk = argKey;
            input0.ki.dwFlags = (int)Import.KEYEVENTF.KEYDOWN;
            input0.ki.wScan = 0;
            input0.ki.dwExtraInfo = Import.GetMessageExtraInfo();

            Import.INPUT input1 = new Import.INPUT();
            input1.type = Import.InputType.INPUT_KEYBOARD;
            input1.ki.wVk = argKey;
            input1.ki.dwFlags = Import.KEYEVENTF.KEYUP;
            input1.ki.wScan = 0;
            input1.ki.dwExtraInfo = Import.GetMessageExtraInfo();

            Import.INPUT[] pInputs = new Import.INPUT[] { input0, input1 };

            Import.SendInput(2, pInputs, Marshal.SizeOf(input0));
        }

        /// <summary>
        /// Down a Key down with SendInput.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void SendInput_KeyDown(Import.VirtualKeys argKey)
        {
            Import.INPUT input0 = new Import.INPUT();
            input0.type = Import.InputType.INPUT_KEYBOARD;
            input0.ki.wVk = argKey;
            input0.ki.dwFlags = (int)Import.KEYEVENTF.KEYDOWN;
            input0.ki.wScan = 0;
            input0.ki.dwExtraInfo = Import.GetMessageExtraInfo();

            Import.INPUT[] pInputs = new Import.INPUT[] { input0 };

            Import.SendInput(1, pInputs, Marshal.SizeOf(input0));
        }

        /// <summary>
        /// Up a Key up with SendInput.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void SendInput_KeyUp(Import.VirtualKeys argKey)
        {
            Import.INPUT input0 = new Import.INPUT();
            input0.type = Import.InputType.INPUT_KEYBOARD;
            input0.ki.wVk = argKey;
            input0.ki.dwFlags = Import.KEYEVENTF.KEYUP;
            input0.ki.wScan = 0;
            input0.ki.dwExtraInfo = Import.GetMessageExtraInfo();

            Import.INPUT[] pInputs = new Import.INPUT[] { input0 };

            Import.SendInput(1, pInputs, Marshal.SizeOf(input0));
        }

        /// <summary>
        /// Press a Key with SendMessage.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void SendMessage_KeyPress(Import.VirtualKeys argKey)
        {
            //Key down
            Import.SendMessage(Parent.Windows.MainWindow.Handle, (uint)Import.VirtualMessages.WM_KEYDOWN, (IntPtr)argKey, IntPtr.Zero);

            //Sleep
            Thread.Sleep(50);

            //Key up
            Import.SendMessage(Parent.Windows.MainWindow.Handle, (uint)Import.VirtualMessages.WM_KEYUP, (IntPtr)argKey, IntPtr.Zero);
        }

        /// <summary>
        /// Down a Key down with SendMessage.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void SendMessage_KeyDown(Import.VirtualKeys argKey)
        {
            //Key Down
            Import.SendMessage(Parent.Windows.MainWindow.Handle, (uint)Import.VirtualMessages.WM_KEYDOWN, (IntPtr)argKey, IntPtr.Zero);
        }

        /// <summary>
        /// Up a Key up with SendMessage.
        /// </summary>
        /// <param name="argKey">Key</param>
        public void SendMessage_KeyUp(Import.VirtualKeys argKey)
        {
            //Key Up
            Import.SendMessage(Parent.Windows.MainWindow.Handle, (uint)Import.VirtualMessages.WM_KEYUP, (IntPtr)argKey, IntPtr.Zero);
        }
    }

    /// <summary>
    /// Mouse manager
    /// </summary>
    public class MouseMgr : hibClass
    {
        //-----------------------------------------
        //--------------- Objects -----------------
        /// <summary>
        /// Represents an ordered pair of double-x and y-coordinates that defines a point in a two-dimensional plane.
        /// </summary>
        public struct DPoint
        {
            /// <summary>
            /// X
            /// </summary>
            public double X;

            /// <summary>
            /// Y
            /// </summary>
            public double Y;
        }

        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// Mouse position from desktop.
        /// </summary>
        public Point PositionFromDesktop
        {
            get { return new Point(Cursor.Position.X, Cursor.Position.Y); }
            set { }
        }

        /// <summary>
        /// Mouse position ratio from desktop.
        /// </summary>
        public DPoint PositionRatioFromDesktop
        {
            get
            {
                DPoint newDPoint = new DPoint();
                newDPoint.X = Math.Round((double)Cursor.Position.X / Screen.PrimaryScreen.Bounds.Width, 3);
                newDPoint.Y = Math.Round((double)Cursor.Position.Y / Screen.PrimaryScreen.Bounds.Height, 3);
                return newDPoint;
            }
            set { }
        }

        /// <summary>
        /// Mouse position from main window.
        /// </summary>
        public Point PositionFromMainWindow
        {
            get
            {
                return GetPositionFromWindow(Parent.Windows.MainWindow);
            }
            set { }
        }

        /// <summary>
        /// Mouse position ratio from main window.
        /// </summary>
        public DPoint PositionRatioFromMainWindow
        {
            get
            {
                return GetPositionRatioFromWindow(Parent.Windows.MainWindow);
            }
            set { }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public MouseMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// GetPositionFromWindow
        /// </summary>
        /// <param name="argWindow">Window</param>
        public Point GetPositionFromWindow(WindowsMgr.Window argWindow)
        {
            int posx = Cursor.Position.X - argWindow.X;
            int posy = Cursor.Position.Y - argWindow.Y;
            if (posx < 0) posx = 0;
            if (posy < 0) posy = 0;
            return new Point(posx, posy);
        }

        /// <summary>
        /// GetPositionRatioFromWindow
        /// </summary>
        /// <param name="argWindow">Window</param>
        public DPoint GetPositionRatioFromWindow(WindowsMgr.Window argWindow)
        {
            DPoint newDPoint = new DPoint();
            Point mposition = GetPositionFromWindow(argWindow);
            newDPoint.X = Math.Round((double)mposition.X / argWindow.Width, 3);
            newDPoint.Y = Math.Round((double)mposition.Y / argWindow.Height, 3);
            return newDPoint;
        }

        /// <summary>
        /// GetRelativePositionFromRatioAndWindow
        /// </summary>
        /// <param name="argWindow">Window</param>
        /// <param name="argPositionRatio">Position ratio</param>
        public Point GetRelativePositionFromRatioAndWindow(WindowsMgr.Window argWindow, DPoint argPositionRatio)
        {
            Point newPoint = new Point();
            newPoint.X = Convert.ToInt32(argWindow.Width * argPositionRatio.X);
            newPoint.Y = Convert.ToInt32(argWindow.Height * argPositionRatio.Y);
            return newPoint;
        }

        /// <summary>
        /// Set cursor position with SetCursorPos.
        /// </summary>
        /// <param name="argPosition">Position</param>
        public void SetCursorPos(Point argPosition)
        {
            Import.SetCursorPos(argPosition.X, argPosition.Y);
        }

        /// <summary>
        /// Action the mouse with mouse_event.
        /// </summary>
        /// <param name="argEvent">Mouse Event</param>
        public void MouseEvent(Import.MouseEventFlags argEvent)
        {
            Import.mouse_event((uint)(argEvent), 0, 0, 0, UIntPtr.Zero);
        }

        /// <summary>
        /// Left click with mouse_event.
        /// </summary>
        public void MouseEvent_LeftClick()
        {
            Import.mouse_event((uint)(Import.MouseEventFlags.LEFTDOWN), 0, 0, 0, UIntPtr.Zero);
            Import.mouse_event((uint)(Import.MouseEventFlags.LEFTUP), 0, 0, 0, UIntPtr.Zero);
        }

        /// <summary>
        /// Right click with mouse_event.
        /// </summary>
        public void MouseEvent_RightClick()
        {
            Import.mouse_event((uint)(Import.MouseEventFlags.RIGHTDOWN), 0, 0, 0, UIntPtr.Zero);
            Import.mouse_event((uint)(Import.MouseEventFlags.RIGHTUP), 0, 0, 0, UIntPtr.Zero);
        }

        /// <summary>
        /// Set cursor position with SendInput.
        /// </summary>
        /// <param name="argPosition">Position</param>
        private void SendInput_SetCursorPos(Point argPosition)
        {
            //Create array
            Import.INPUT[] inp = new Import.INPUT[1];

            //Create and add event
            Import.INPUT eventOne = new Import.INPUT();
            eventOne.type = Import.InputType.INPUT_MOUSE;
            eventOne.mi = new Import.MOUSEINPUT();
            eventOne.mi.dx = argPosition.X;
            eventOne.mi.dy = argPosition.Y;
            eventOne.mi.mouseData = 0;
            eventOne.mi.time = 0;
            eventOne.mi.dwFlags = Import.MOUSEEVENTF.MOVE;
            inp[0] = eventOne;

            //Send
            Import.SendInput((uint)inp.Length, inp, Marshal.SizeOf(inp[0].GetType()));
        }

        /// <summary>
        /// Left click with SendMessage.
        /// </summary>
        /// <param name="argPosition">Position</param>
        public void SendMessage_LeftClick(Point argPosition)
        {
            //Make LParam
            int LParam = ((argPosition.Y << 16) | (argPosition.X & 0xffff));

            //SendMessage
            Import.SendMessage(Parent.Windows.MainWindow.Handle, (uint)Import.VirtualMessages.WM_LBUTTONDOWN, IntPtr.Zero, (IntPtr)LParam);
            Import.SendMessage(Parent.Windows.MainWindow.Handle, (uint)Import.VirtualMessages.WM_LBUTTONUP, IntPtr.Zero, (IntPtr)LParam);
        }

        /// <summary>
        /// Right click with SendMessage.
        /// </summary>
        /// <param name="argPosition">Position</param>
        public void SendMessage_RightClick(Point argPosition)
        {
            //Make LParam
            int LParam = ((argPosition.Y << 16) | (argPosition.X & 0xffff));

            //SendMessage
            Import.SendMessage(Parent.Windows.MainWindow.Handle, (uint)Import.VirtualMessages.WM_RBUTTONDOWN, IntPtr.Zero, (IntPtr)LParam);
            Import.SendMessage(Parent.Windows.MainWindow.Handle, (uint)Import.VirtualMessages.WM_RBUTTONUP, IntPtr.Zero, (IntPtr)LParam);
        }
    }

    /// <summary>
    /// Windows manager
    /// </summary>
    public class WindowsMgr : hibClass
    {
        //-----------------------------------------
        //--------------- Objects -----------------
        /// <summary>
        /// Window
        /// </summary>
        public class Window : hibClass
        {
            //-----------------------------------------
            //--------------- Objects -----------------
            /// <summary>
            /// WindowState
            /// </summary>
            public enum WindowState : uint
            {
                /// <summary>
                /// Normal
                /// </summary>
                Normal = 1,

                /// <summary>
                /// Minimized
                /// </summary>
                Minimized = 2,

                /// <summary>
                /// Maximized
                /// </summary>
                Maximized = 3
            }

            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// Handle
            /// </summary>
            private IntPtr _handle = IntPtr.Zero;

            /// <summary>
            /// Handle
            /// </summary>
            public IntPtr Handle
            {
                get { return _handle; }
                set { }
            }

            /// <summary>
            /// ClassName
            /// </summary>
            public string ClassName
            {
                get { return Import.GetClassName(_handle); }
                set { }
            }

            /// <summary>
            /// Title
            /// </summary>
            public string Title
            {
                get
                {
                    StringBuilder s = new StringBuilder(256);
                    int Length;
                    if ((Length = Import._GetWindowText(_handle, s, 256)) > 0)
                        return s.ToString(0, Length);
                    return "";
                }
                set { }
            }

            /// <summary>
            /// Rect
            /// </summary>
            public Import.WINDOWPLACEMENT WindowPlacement
            {
                get
                {
                    Import.WINDOWPLACEMENT wp = new Import.WINDOWPLACEMENT();
                    wp.length = (uint)Marshal.SizeOf(wp);
                    Import.GetWindowPlacement(_handle, ref wp);
                    return wp;
                }
                set { }
            }

            /// <summary>
            /// Rect
            /// </summary>
            public Import.RECT Rect
            {
                get { return WindowPlacement.rcNormalPosition; }
                set { }
            }

            /// <summary>
            /// State
            /// </summary>
            public WindowState State
            {
                get { return (WindowState)(uint)WindowPlacement.showCmd; }
                set { }
            }

            /// <summary>
            /// X
            /// </summary>
            public int X
            {
                get { return Rect.Left; }
                set { }
            }

            /// <summary>
            /// Y
            /// </summary>
            public int Y
            {
                get { return Rect.Top; }
                set { }
            }

            /// <summary>
            /// Width
            /// </summary>
            public int Width
            {
                get { return Rect.Right - Rect.Left; }
                set { }
            }

            /// <summary>
            /// Height
            /// </summary>
            public int Height
            {
                get { return Rect.Bottom - Rect.Top; }
                set { }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="argParent">hibProcess</param>
            /// <param name="argHandle">handle</param>
            public Window(hibProcess argParent, IntPtr argHandle) : base(argParent)
            {
                //Set _handle
                _handle = argHandle;
            }
        }

        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// Lock object for enumering windows
        /// </summary>
        private static object lWindowsLock = new object();

        /// <summary>
        /// List windows for statics voids
        /// </summary>
        private static List<IntPtr> lWindows;

        /// <summary>
        /// Main windows
        /// </summary>
        public Window MainWindow
        {
            get { return new Window(Parent, Parent.Process.MainWindowHandle); }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public WindowsMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Callback for EnumWindows.
        /// </summary>
        private static bool EnumWindowsCallback(IntPtr hWnd, IntPtr lParam)
        {
            lWindows.Add(hWnd);
            return true;
        }

        /// <summary>
        /// Gets all open windows, be they child or parent.
        /// </summary>
        private static bool _EnumWindows()
        {
            lWindows = new List<IntPtr>();

            Import.EnumWindowsProc callback = new Import.EnumWindowsProc(EnumWindowsCallback);
            return Import.EnumWindows(callback, IntPtr.Zero);
        }

        /// <summary>
        /// Gets all open windows, be they child or parent.
        /// </summary>
        /// <returns>Returns an array of window handles.</returns>
        public static IntPtr[] EnumWindows()
        {
            lock (lWindowsLock)
            {
                if (!_EnumWindows()) return null;

                return lWindows.ToArray();
            }
        }

        /// <summary>
        /// Gets all open main windows.
        /// </summary>
        /// <returns>Returns an array of window handles.</returns>
        public static IntPtr[] EnumMainWindows()
        {
            List<IntPtr> hWnds = new List<IntPtr>();
            Process[] procs = Process.GetProcesses();

            foreach (Process proc in procs)
                hWnds.Add(proc.MainWindowHandle);

            return hWnds.ToArray();
        }

        /// <summary>
        /// Returns the title of a window.
        /// </summary>
        /// <param name="hWnd">The window handle of the window in question.</param>
        /// <param name="nMaxCount">Maximum number of characters in the window title.</param>
        /// <returns>Returns null on failure.</returns>
        public static string GetWindowTitle(IntPtr hWnd, int nMaxCount)
        {
            StringBuilder s = new StringBuilder(nMaxCount);
            int Length;
            if ((Length = Import._GetWindowText(hWnd, s, nMaxCount)) > 0)
                return s.ToString(0, Length);
            return null;
        }

        /// <summary>
        /// Returns the title of a window.
        /// </summary>
        /// <param name="hWnd">The window handle of the window in question.</param>
        /// <returns>Returns null on failure.</returns>
        public static string GetWindowTitle(IntPtr hWnd)
        {
            return GetWindowTitle(hWnd, 256);
        }

        /// <summary>
        /// Finds all windows, parent and child, that match the supplied classname or window title.
        /// </summary>
        /// <param name="Classname">Classname of the window(s) to match.</param>
        /// <param name="WindowTitle">Window title of the window(s) to match.</param>
        /// <returns>Returns an array of window handles.</returns>
        public static IntPtr[] FindWindows(string Classname, string WindowTitle)
        {
            if (Classname == null) Classname = String.Empty;
            if (WindowTitle == null) WindowTitle = String.Empty;

            List<IntPtr> hWnds = new List<IntPtr>();

            lock (lWindowsLock)
            {
                if (!_EnumWindows()) return null;

                foreach (IntPtr hWnd in lWindows)
                    if ((WindowTitle.Length > 0 && GetWindowTitle(hWnd) == WindowTitle) ||
                        (Classname.Length > 0 && Import.GetClassName(hWnd) == Classname))
                        hWnds.Add(hWnd);
            }

            return hWnds.ToArray();
        }

        /// <summary>
        /// Finds the first window, parent and child, that match the supplied classname or window title.
        /// </summary>
        /// <param name="Classname">Classname of the window(s) to match.</param>
        /// <param name="WindowTitle">Window title of the window(s) to match.</param>
        /// <returns>Returns a window handle.</returns>
        public static IntPtr FindWindow(string Classname, string WindowTitle)
        {
            if (Classname == null) Classname = String.Empty;
            if (WindowTitle == null) WindowTitle = String.Empty;

            lock (lWindowsLock)
            {
                if (!_EnumWindows()) return IntPtr.Zero;


                foreach (IntPtr hWnd in lWindows)
                    if ((WindowTitle.Length > 0 && GetWindowTitle(hWnd) == WindowTitle) ||
                        (Classname.Length > 0 && Import.GetClassName(hWnd) == Classname))
                        return hWnd;
            }

            return IntPtr.Zero;
        }

        /// <summary>
        /// Finds all top-level windows that match the supplied classname or window title.
        /// </summary>
        /// <param name="Classname">Classname of the window(s) to match.</param>
        /// <param name="WindowTitle">Window title of the window(s) to match.</param>
        /// <returns>Returns an array of window handles.</returns>
        public static IntPtr[] FindMainWindows(string Classname, string WindowTitle)
        {
            if (Classname == null) Classname = String.Empty;
            if (WindowTitle == null) WindowTitle = String.Empty;

            List<IntPtr> hWnds = new List<IntPtr>();
            Process[] procs = Process.GetProcesses();

            foreach (Process proc in procs)
                if (proc.MainWindowHandle != IntPtr.Zero)
                    if ((WindowTitle.Length > 0 && proc.MainWindowTitle == WindowTitle) ||
                        (Classname.Length > 0 && Import.GetClassName(proc.MainWindowHandle) == Classname))
                        hWnds.Add(proc.MainWindowHandle);

            return hWnds.ToArray();
        }

        /// <summary>
        /// Finds the first top-level window that matches the supplied classname or window title.
        /// </summary>
        /// <param name="Classname">Classname of the window(s) to match.</param>
        /// <param name="WindowTitle">Window title of the window(s) to match.</param>
        /// <returns>Returns a window handle.</returns>
        public static IntPtr FindMainWindow(string Classname, string WindowTitle)
        {
            if (Classname == null) Classname = String.Empty;
            if (WindowTitle == null) WindowTitle = String.Empty;

            Process[] procs = Process.GetProcesses();

            foreach (Process proc in procs)
                if (proc.MainWindowHandle != IntPtr.Zero)
                    if ((WindowTitle.Length > 0 && proc.MainWindowTitle == WindowTitle) ||
                        (Classname.Length > 0 && Import.GetClassName(proc.MainWindowHandle) == Classname))
                        return proc.MainWindowHandle;

            return IntPtr.Zero;
        }

        /// <summary>
        /// Finds all windows, parent and child, that contain the supplied classname or window title.
        /// </summary>
        /// <param name="Classname">Classname of the window(s) to match.</param>
        /// <param name="WindowTitle">Window title of the window(s) to match.</param>
        /// <returns>Returns an array of window handles.</returns>
        public static IntPtr[] FindWindowsContains(string Classname, string WindowTitle)
        {
            if (Classname == null) Classname = String.Empty;
            if (WindowTitle == null) WindowTitle = String.Empty;

            List<IntPtr> hWnds = new List<IntPtr>();

            lock (lWindowsLock)
            {
                if (!_EnumWindows()) return null;

                foreach (IntPtr hWnd in lWindows)
                    if ((WindowTitle.Length > 0 && GetWindowTitle(hWnd).Contains(WindowTitle)) ||
                        (Classname.Length > 0 && Import.GetClassName(hWnd).Contains(Classname)))
                        hWnds.Add(hWnd);
            }

            return hWnds.ToArray();
        }

        /// <summary>
        /// Finds the first window, parent and child, that contains either of the supplied classname or window title.
        /// </summary>
        /// <param name="Classname">Classname of the window(s) to match.</param>
        /// <param name="WindowTitle">Window title of the window(s) to match.</param>
        /// <returns>Returns a window handle.</returns>
        public static IntPtr FindWindowContains(string Classname, string WindowTitle)
        {
            if (Classname == null) Classname = String.Empty;
            if (WindowTitle == null) WindowTitle = String.Empty;

            lock (lWindowsLock)
            {
                if (!_EnumWindows()) return IntPtr.Zero;


                foreach (IntPtr hWnd in lWindows)
                    if ((WindowTitle.Length > 0 && GetWindowTitle(hWnd).Contains(WindowTitle)) ||
                        (Classname.Length > 0 && Import.GetClassName(hWnd).Contains(Classname)))
                        return hWnd;
            }

            return IntPtr.Zero;
        }

        /// <summary>
        /// Finds all top-level windows that contain the supplied classname or window title.
        /// </summary>
        /// <param name="Classname">Classname of the window(s) to match.</param>
        /// <param name="WindowTitle">Window title of the window(s) to match.</param>
        /// <returns>Returns an array of window handles.</returns>
        public static IntPtr[] FindMainWindowsContains(string Classname, string WindowTitle)
        {
            if (Classname == null) Classname = String.Empty;
            if (WindowTitle == null) WindowTitle = String.Empty;

            List<IntPtr> hWnds = new List<IntPtr>();
            Process[] procs = Process.GetProcesses();

            foreach (Process proc in procs)
                if (proc.MainWindowHandle != IntPtr.Zero)
                    if ((WindowTitle.Length > 0 && proc.MainWindowTitle.Contains(WindowTitle)) ||
                        (Classname.Length > 0 && Import.GetClassName(proc.MainWindowHandle).Contains(Classname)))
                        hWnds.Add(proc.MainWindowHandle);

            return hWnds.ToArray();
        }

        /// <summary>
        /// Finds the first top-level window that contains the supplied classname or window title.
        /// </summary>
        /// <param name="Classname">Classname of the window(s) to match.</param>
        /// <param name="WindowTitle">Window title of the window(s) to match.</param>
        /// <returns>Returns a window handle.</returns>
        public static IntPtr FindMainWindowContains(string Classname, string WindowTitle)
        {
            if (Classname == null) Classname = String.Empty;
            if (WindowTitle == null) WindowTitle = String.Empty;

            Process[] procs = Process.GetProcesses();

            foreach (Process proc in procs)
                if (proc.MainWindowHandle != IntPtr.Zero)
                    if ((WindowTitle.Length > 0 && proc.MainWindowTitle.Contains(WindowTitle)) ||
                        (Classname.Length > 0 && Import.GetClassName(proc.MainWindowHandle).Contains(Classname)))
                        return proc.MainWindowHandle;

            return IntPtr.Zero;
        }

        /// <summary>
        /// Finds the main window of the provided process.
        /// </summary>
        /// <param name="ProcessName">Name of the process executable.</param>
        /// <returns>Returns a window handle.</returns>
        /// <remarks>ProcessName may contain the trailing extension or not, though it would be less problematic if any file extension were omitted (i.e. '.exe').</remarks>
        public static IntPtr FindWindowByProcessName(string ProcessName)
        {
            if (ProcessName.EndsWith(".exe"))
                ProcessName = ProcessName.Remove(ProcessName.Length - 4, 4);

            Process[] procs = Process.GetProcessesByName(ProcessName);
            if (procs == null || procs.Length == 0)
                return IntPtr.Zero;

            return procs[0].MainWindowHandle;
        }

        /// <summary>
        /// Finds all main windows that match the provided process name.
        /// </summary>
        /// <param name="ProcessName">Name of the process executable.</param>
        /// <returns>Returns an array of window handles.</returns>
        /// <remarks>ProcessName may contain the trailing extension or not, though it would be less problematic if any file extension were omitted (i.e. '.exe').</remarks>
        public static IntPtr[] FindWindowsByProcessName(string ProcessName)
        {
            List<IntPtr> hWnds = new List<IntPtr>();

            if (ProcessName.EndsWith(".exe"))
                ProcessName = ProcessName.Remove(ProcessName.Length - 4, 4);

            Process[] procs = Process.GetProcessesByName(ProcessName);
            if (procs == null || procs.Length == 0)
                return null;

            foreach (Process proc in procs)
                hWnds.Add(proc.MainWindowHandle);

            return hWnds.ToArray();
        }

        /// <summary>
        /// Finds the main window of the provided process.
        /// </summary>
        /// <param name="dwProcessId">The process Id of the process in question.</param>
        /// <returns>Returns a window handle.</returns>
        public static IntPtr FindWindowByProcessId(int dwProcessId)
        {
            Process proc = Process.GetProcessById(dwProcessId);
            return proc.MainWindowHandle;
        }
    }

    /// <summary>
    /// Hooks manager
    /// </summary>
    public class HooksMgr : hibClass
    {
        //-----------------------------------------
        //--------------- Objects -----------------
        /// <summary>
        /// Hook
        /// </summary>
        public class Hook : hibClass
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// Name
            /// </summary>
            private string _name = "";

            /// <summary>
            /// Name
            /// </summary>
            public string Name
            {
                get
                {
                    //Return
                    return _name;
                }
                set
                {
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Create a hook.
            /// </summary>
            /// <param name="argName">Name</param>
            /// <param name="argParent">hibProcess</param>
            public Hook(hibProcess argParent, string argName) : base(argParent)
            {
                //Set values
                _name = argName;
            }
        }

        /// <summary>
        /// InlineHook
        /// </summary>
        public class InlineHook : Hook
        {
            //--------------------------------------------
            //----------------- Defines ------------------
            /// <summary>
            /// Address
            /// </summary>
            private IntPtr _address;

            /// <summary>
            /// Original instructions.
            /// </summary>
            private byte[] _originalInstructions;

            /// <summary>
            /// Allocation with the custom asm code.
            /// </summary>
            private RegionsMgr.Allocation _allocation;

            /// <summary>
            /// Define if the detour is enable.
            /// </summary>
            private bool _isEnable = false;

            /// <summary>
            /// Define if data are writed.
            /// </summary>
            private bool _writed = false;

            /// <summary>
            /// Define if detourned function is disabled on dispose.
            /// </summary>
            private bool _freeOnDispose = true;

            /// <summary>
            /// Address
            /// </summary>
            public IntPtr Address
            {
                get
                {
                    return _address;
                }
                set
                {
                }
            }

            /// <summary>
            /// Original instructions.
            /// </summary>
            public byte[] OriginalInstructions
            {
                get
                {
                    return _originalInstructions;
                }
                set
                {
                }
            }

            /// <summary>
            /// Allocation with the custom asm code.
            /// </summary>
            public RegionsMgr.Allocation Allocation
            {
                get
                {
                    //Return
                    return _allocation;
                }
                set
                {
                }
            }

            /// <summary>
            /// Define if the detour is enable.
            /// </summary>
            public bool IsEnable
            {
                get
                {
                    //Return
                    return _isEnable;
                }
                set
                {
                }
            }

            /// <summary>
            /// Define if data are writed.
            /// </summary>
            public bool Writed
            {
                get
                {
                    //Return
                    return _writed;
                }
                set
                {
                }
            }

            /// <summary>
            /// Define if detourned function is disabled on dispose.
            /// </summary>
            public bool FreeOnDispose
            {
                get
                {
                    return _freeOnDispose;
                }
                set
                {
                    _freeOnDispose = value;
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Create a inline hook.
            /// </summary>
            /// <param name="argParent">hibProcess</param>
            /// <param name="argName">Name</param>
            /// <param name="argAdress">Address</param>
            /// <param name="argInstructionsSize">Size of detourned instructions.</param>
            public InlineHook(hibProcess argParent, string argName, IntPtr argAddress, UIntPtr argInstructionsSize) : base(argParent, argName)
            {
                //Set values
                _address = argAddress;
                _originalInstructions = Parent.Read.Bytes(_address, (uint)argInstructionsSize);

                //Return
                return;
            }

            /// <summary>
            /// Destructor
            /// </summary>
            ~InlineHook()
            {
                //Remove from list
                if (Parent.Hooks.InlinesHooks.Contains(this)) Parent.Hooks.InlinesHooks.Remove(this);

                //Check _freeOnDispose
                if (_freeOnDispose)
                {
                    //Disable
                    Disable();

                    //Free
                    _allocation.Free();
                }
            }

            /// <summary>
            /// Create a new allocation.
            /// </summary>
            /// <param name="argSize">Size</param>
            /// <returns>Returns true on success, false on failure.</returns>
            public bool NewAllocation(UIntPtr argSize)
            {
                //Check _void
                if (_allocation != null)
                {
                    _allocation.Free();
                    _allocation = null;
                }

                //Create _void
                if (_allocation == null)
                {
                    //Alloc
                    _allocation = Parent.Regions.CreateAllocation((UIntPtr)argSize);

                    //Check _allocation
                    if (_allocation == null) return false;

                    //Set FreeOnDispose
                    _allocation.FreeOnDispose = false;
                }

                //Return
                return true;
            }

            /// <summary>
            /// Write
            /// </summary>
            /// <param name="argBytes">Custom asm code as bytes array.</param>
            /// <param name="argKeepOriginalInstructions">Define if original instructions are rewrited after the custom code before the return jump.</param>
            /// <returns>Returns true on success, false on failure.</returns>
            /// <remarks>if you need to know the location of the allocation for the detour to make the code, use .NewAllocation(UIntPtr argSize) to initialize it !</remarks>
            public bool Write(byte[] argBytes, bool argKeepOriginalInstructions)
            {
                //Check _isEnable
                if (_isEnable) return false;

                //Define allocation size with custom code size
                ulong Sized = (ulong)argBytes.Length;

                //Add original code size if necessary
                if (argKeepOriginalInstructions) Sized = Sized + (ulong)_originalInstructions.Length;

                //Add return jump size
                if (Parent.IsX64)
                {
                    Sized = Sized + 9;
                }
                else
                {
                    Sized = Sized + 5;
                }


                //Check _void
                if (_allocation != null)
                {
                    if ((ulong)_allocation.RegionSize < Sized)
                    {
                        NewAllocation((UIntPtr)Sized);
                    }
                }
                else
                {
                    NewAllocation((UIntPtr)Sized);
                }

                //Generate Code
                List<byte> Data = new List<byte>();
                foreach (byte b in argBytes)
                {
                    Data.Add(b);
                }
                if (argKeepOriginalInstructions)
                {
                    foreach (byte b in _originalInstructions)
                    {
                        Data.Add(b);
                    }
                }
                if (Parent.IsX64)
                {
                    Data.Add(0xE9);
                    UInt64 RelocAddr = (ulong)(((_address.ToInt64() + 9) - (_allocation.BaseAddress.ToInt64() + Data.Count) + 1 - 9) + (_originalInstructions.Length - 9));
                    foreach (byte b in BitConverter.GetBytes(RelocAddr))
                    {
                        Data.Add(b);
                    }
                }
                else
                {
                    Data.Add(0xE9);
                    UInt32 RelocAddr = (uint)(((_address.ToInt32() + 5) - (_allocation.BaseAddress.ToInt32() + Data.Count) + 1 - 5) + (_originalInstructions.Length - 5));
                    foreach (byte b in BitConverter.GetBytes(RelocAddr))
                    {
                        Data.Add(b);
                    }
                }

                //Poke Code
                _allocation.Write(Data.ToArray());

                //Set Flag
                _writed = true;

                //Return
                return true;
            }

            /// <summary>
            /// Enable
            /// </summary>
            /// <returns>Returns true on success, false on failure.</returns>
            public bool Enable()
            {
                //Checks
                if (_isEnable) return false;
                if (!_writed) return false;

                //Set Jump
                if (Parent.IsX64)
                {
                    List<byte> Jump = new List<byte>();
                    Jump.Add(0xE9);
                    UInt64 RelocAddr = (ulong)_allocation.BaseAddress.ToInt64() - (ulong)_address - 9;
                    foreach (byte b in BitConverter.GetBytes(RelocAddr))
                    {
                        Jump.Add(b);
                    }
                    if ((ulong)_originalInstructions.Length > 9)
                    {
                        uint NopCount = (uint)_originalInstructions.Length - 9;
                        for (int i = 1; i <= NopCount; i++)
                        {
                            Jump.Add(0x90);
                        }
                    }
                    uint OldProtection;
                    Parent.Regions.VirtualProtectEx(_address, (int)_originalInstructions.Length, (uint)Import.MemoryProtect.PAGE_EXECUTE_WRITECOPY, out OldProtection);
                    Parent.Write.Bytes(_address, Jump.ToArray());
                    uint OldOldProtection;
                    Parent.Regions.VirtualProtectEx(_address, (int)_originalInstructions.Length, (uint)OldProtection, out OldOldProtection);
                }
                else
                {
                    List<byte> Jump = new List<byte>();
                    Jump.Add(0xE9);
                    UInt32 RelocAddr = (uint)_allocation.BaseAddress.ToInt32() - (uint)_address - 5;
                    foreach (byte b in BitConverter.GetBytes(RelocAddr))
                    {
                        Jump.Add(b);
                    }
                    if ((ulong)_originalInstructions.Length > 5)
                    {
                        uint NopCount = (uint)_originalInstructions.Length - 5;
                        for (int i = 1; i <= NopCount; i++)
                        {
                            Jump.Add(0x90);
                        }
                    }
                    uint OldProtection;
                    Parent.Regions.VirtualProtectEx(_address, (int)_originalInstructions.Length, (uint)Import.MemoryProtect.PAGE_EXECUTE_WRITECOPY, out OldProtection);
                    Parent.Write.Bytes(_address, Jump.ToArray());
                    uint OldOldProtection;
                    Parent.Regions.VirtualProtectEx(_address, (int)_originalInstructions.Length, (uint)OldProtection, out OldOldProtection);
                }

                //SetFlag
                _isEnable = true;

                //Return
                return true;
            }

            /// <summary>
            /// Disable
            /// </summary>
            /// <returns>Returns true on success, false on failure.</returns>
            public bool Disable()
            {
                //Checks
                if (!_isEnable) return false;
                if (!_writed) return false;

                //Set Original Data
                uint OldProtection;
                Parent.Regions.VirtualProtectEx(_address, (int)_originalInstructions.Length, (uint)Import.MemoryProtect.PAGE_EXECUTE_WRITECOPY, out OldProtection);
                Parent.Write.Bytes(_address, _originalInstructions);
                uint OldOldProtection;
                Parent.Regions.VirtualProtectEx(_address, (int)_originalInstructions.Length, (uint)OldProtection, out OldOldProtection);

                //Return
                return true;
            }
        }


        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// A list with all inline hooks created for the current process.
        /// </summary>
        private List<InlineHook> _inlineHooks = new List<InlineHook>();

        /// <summary>
        /// A list with all inline hooks created for the current process.
        /// </summary>
        public List<InlineHook> InlinesHooks
        {
            get
            {
                //Return
                return _inlineHooks;
            }
            set
            {
            }
        }

        /// <summary>
        /// A list with all hooks created for the current process.
        /// </summary>
        public List<Hook> Hooks
        {
            get
            {
                //Create list
                List<Hook> hooks = new List<Hook>();

                //Browse _inlineHooks
                lock (_inlineHooks)
                {
                    foreach (Hook h in _inlineHooks)
                    {
                        hooks.Add(h);
                    }
                }

                //Return
                return hooks;
            }
            set
            {
            }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public HooksMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Create a inline hook.
        /// </summary>
        /// <param name="argName">Name</param>
        /// <param name="argAddress">Address</param>
        /// <param name="argInstructionsSize">Instruction size define count of bytes copied to create a detour without override an existing instruction.On x32, minimum 5, on x64 minimum 9.</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return created InlineHook.</returns>
        public InlineHook CreateInlineHook(string argName, IntPtr argAddress, UIntPtr argInstructionsSize)
        {
            //Verify argInstructionsSize
            if (Parent.IsX64)
            {
                if ((long)argInstructionsSize < 9)
                {
                    throw new Exception("You can't create a detour on x64 process without a minimum of 9 bytes as instructions size.");
                }
            }
            else
            {
                if ((int)argInstructionsSize < 5)
                {
                    throw new Exception("You can't create a detour on x32 process without a minimum of 5 bytes as instructions size.");
                }
            }

            //Create new InlineHook
            InlineHook ih = new InlineHook(Parent, argName, argAddress, argInstructionsSize);

            //Add it the list
            lock (_inlineHooks)
            {
                _inlineHooks.Add(ih);
            }

            //Return
            return ih;
        }

        /// <summary>
        /// Retrieve InlineHook froms his name.
        /// </summary>
        /// <param name="argName">Name</param>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        /// <returns>Return InlineHook found, null if nothing found.</returns>
        public InlineHook GetInlineHookFromName(string argName)
        {
            //Browse _inlineHooks
            lock (_inlineHooks)
            {
                foreach (InlineHook e in _inlineHooks)
                {
                    if (e.Name == argName)
                    {
                        //Return
                        return e;
                    }
                }
            }

            //Return
            return null;
        }
    }

    /// <summary>
    /// Prefabs manager
    /// </summary>
    public class PrefabsMgr : hibClass
    {
        //-----------------------------------------
        //---------------- Enums ------------------
        /// <summary>
        /// TargetType
        /// </summary>
        public enum eTargetType : uint
        {
            winLib = 1,
            externalLib = 1,
            undefined = 0xFFFF
        }

        /// <summary>
        /// ActionType
        /// </summary>
        public enum eActionType : uint
        {
            filter = 1,
            sniffer = 2,
            bypass = 3,
            undefined = 0xFFFF
        }


        //-----------------------------------------
        //--------------- Objects -----------------
        /// <summary>
        /// Baseclass for a prefab.
        /// </summary>
        public class Prefab : hibClass
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// Define if the prefab is enable.
            /// </summary>
            private bool _isEnable = false;

            /// <summary>
            /// Define if the prefab is enable.
            /// </summary>
            public bool IsEnable
            {
                get
                {
                    //Return
                    return _isEnable;
                }
                set
                {
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Get name of the prefab.
            /// </summary>
            /// <returns>Return prefab name as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual string GetName()
            {
                //Return
                return "undefined";
            }

            /// <summary>
            /// Get author of the prefab.
            /// </summary>
            /// <returns>Return author name as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual string GetAuthor()
            {
                //Return
                return "undefined";
            }

            /// <summary>
            /// Get version of the prefab.
            /// </summary>
            /// <returns>Return version as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual string GetVersion()
            {
                //Return
                return "undefined";
            }

            /// <summary>
            /// Get history of the prefab.
            /// </summary>
            /// <returns>Return history as dictionary, version as key.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual Dictionary<string, string> GetHistory()
            {
                //Return
                return null;
            }

            /// <summary>
            /// Get eTargetType of the prefab.
            /// </summary>
            /// <returns>Return eTargetType.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual eTargetType GetTargetType()
            {
                //Return
                return eTargetType.undefined;
            }

            /// <summary>
            /// Get target library of the prefab.
            /// </summary>
            /// <returns>Return target library as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual string GetTargetLibrary()
            {
                //Return
                return "undefined";
            }

            /// <summary>
            /// Get target library function of the prefab.
            /// </summary>
            /// <returns>Return target library function as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual string GetTargetLibraryFunction()
            {
                //Return
                return "undefined";
            }

            /// <summary>
            /// Get eActionType of the prefab.
            /// </summary>
            /// <returns>Return eActionType.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual eActionType GetActionType()
            {
                //Return
                return eActionType.undefined;
            }

            /// <summary>
            /// Get description of the prefab.
            /// </summary>
            /// <returns>Return description as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual string GetDescription()
            {
                //Return
                return "undefined";
            }

            /// <summary>
            /// Get availability on the current target.
            /// </summary>
            /// <returns>Return true if prebaf is available, false if not.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual bool GetAvailability()
            {
                //Return
                return false;
            }

            /// <summary>
            /// Create a new prefab.
            /// </summary>
            /// <param name="argParent">hibProcess</param>
            public Prefab(hibProcess argParent) : base(argParent)
            {
            }

            /// <summary>
            /// Enable
            /// </summary>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual void Enable()
            {
                //Set _isEnable
                _isEnable = true;
            }

            /// <summary>
            /// Disable
            /// </summary>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual void Disable()
            {
                //Set _isEnable
                _isEnable = false;
            }
        }

        /// <summary>
        /// WS2_32_DLL__3c255xs
        /// </summary>
        public class WS2_32_DLL__3c255xs : Prefab
        {
            //-----------------------------------------
            //-------------- Variables ----------------
            /// <summary>
            /// Define foreign modules.
            /// </summary>
            /// <remarks>Maximum = 50</remarks>
            private List<ProcessModule> _modulesBlacklist = new List<ProcessModule>();

            /// <summary>
            /// Define foreign return addresses.
            /// </summary>
            /// <remarks>Maximum = 100</remarks>
            private List<IntPtr> _returnAddressesBlacklist = new List<IntPtr>();

            /// <summary>
            /// Detour
            /// </summary>
            private HooksMgr.InlineHook _detour = null;

            /// <summary>
            /// Define foreign modules.
            /// </summary>
            /// <remarks>Maximum = 50</remarks>
            public List<ProcessModule> ModulesBlacklist
            {
                get
                {
                    //Return
                    return _modulesBlacklist;
                }
                set
                {
                }
            }

            /// <summary>
            /// Define foreign return addresses.
            /// </summary>
            /// <remarks>Maximum = 100</remarks>
            public List<IntPtr> ReturnAddressesBlacklist
            {
                get
                {
                    //Return
                    return _returnAddressesBlacklist;
                }
                set
                {
                }
            }


            //-----------------------------------------
            //-------------- Functions ----------------
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="argParent">hibProcess</param>
            public WS2_32_DLL__3c255xs(hibProcess argParent) : base(argParent)
            {
            }

            /// <summary>
            /// Get name of the prefab.
            /// </summary>
            /// <returns>Return prefab name as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public override string GetName()
            {
                //Return
                return "WS2_32.dll-sendto-3c255xs";
            }

            /// <summary>
            /// Get author of the prefab.
            /// </summary>
            /// <returns>Return author name as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public override string GetAuthor()
            {
                //Return
                return "hibernos";
            }

            /// <summary>
            /// Get version of the prefab.
            /// </summary>
            /// <returns>Return version as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public override string GetVersion()
            {
                //Return
                return "0.0.0.1";
            }

            /// <summary>
            /// Get history of the prefab.
            /// </summary>
            /// <returns>Return history as dictionary, version as key.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public override Dictionary<string, string> GetHistory()
            {
                //Create dictionary
                Dictionary<string, string> di = new Dictionary<string, string>();
                di.Add("0.0.0.1", "Created");

                //Return
                return di;
            }

            /// <summary>
            /// Get eTargetType of the prefab.
            /// </summary>
            /// <returns>Return eTargetType.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public override eTargetType GetTargetType()
            {
                //Return
                return eTargetType.winLib;
            }

            /// <summary>
            /// Get target library of the prefab.
            /// </summary>
            /// <returns>Return target library as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public override string GetTargetLibrary()
            {
                //Return
                return "WS2_32.dll";
            }

            /// <summary>
            /// Get target library function of the prefab.
            /// </summary>
            /// <returns>Return target library function as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public virtual string GetTargetLibraryFunction()
            {
                //Return
                return "sendto";
            }

            /// <summary>
            /// Get eActionType of the prefab.
            /// </summary>
            /// <returns>Return eActionType.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public override eActionType GetActionType()
            {
                //Return
                return eActionType.filter;
            }

            /// <summary>
            /// Get description of the prefab.
            /// </summary>
            /// <returns>Return description as string.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public override string GetDescription()
            {
                //Return
                return "Inline hook on 'sendto' function to provide a fake send for blacklisted modules(max=50) and return addresses(max=100).";
            }

            /// <summary>
            /// Get availability on the current target.
            /// </summary>
            /// <returns>Return true if prebaf is available, false if not.</returns>
            /// <remarks>Throw an exception on failure.</remarks>
            public override bool GetAvailability()
            {
                //Verify if module exist
                if (Parent.Modules.GetModuleFromName("WS2_32.dll") == null)
                {
                    //Return
                    return false;
                }

                //Verify if parent contain pattern
                if (Parent.Patterns.GetPatternByName("WS2_32.dll-sendto") == null)
                {
                    //Create pattern
                    PatternsMgr.Pattern pattern = Parent.Patterns.CreatePattern("WS2_32.dll-sendto");
                    pattern.SetStaticOffsetsFromString("8B FF 55 8B EC 83 EC 10 56 57 33 FF 81 3D 48 70 1A 76 29 2E 18 76 0F 85 81 00 00 00 39 3D 70 70 1A 76");
                    pattern.Summary = 0x00;
                }

                //Scan
                Parent.Patterns.ScanModule(Parent.Modules.GetModuleFromName("WS2_32.dll"));

                //Verify
                if (Parent.Patterns.GetPatternByName("WS2_32.dll-sendto").Adress == IntPtr.Zero)
                {
                    //Return
                    return false;
                }

                //Return
                return true;
            }

            /// <summary>
            /// Enable
            /// </summary>
            /// <remarks>Throw an exception on failure.</remarks>
            public override void Enable()
            {
                //Verify if detour exist
                if (_detour == null)
                {
                    //Create detour
                    _detour = Parent.Hooks.CreateInlineHook("", Parent.Patterns.GetPatternByName("").Adress, (UIntPtr)5);
                }

                //Code
                List<byte> code = new List<byte>();

                //Jump


                //Modules array
                for (int i = 1; i <= 400; i++)
                {
                    code.Add(0x90);
                }

                //Return addresses array
                for (int i = 1; i <= 400; i++)
                {
                    code.Add(0x90);
                }

                //Set as enable
                base.Enable();
            }
        }


        //-----------------------------------------
        //-------------- Variables ----------------
        /// <summary>
        /// A list with all prefabs created for the current process.
        /// </summary>
        private List<Prefab> _prefabs = new List<Prefab>();

        /// <summary>
        /// A list with all prefabs created for the current process.
        /// </summary>
        public List<Prefab> Prefabs
        {
            get
            {
                //Return
                return _prefabs;
            }
            set
            {
            }
        }


        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public PrefabsMgr(hibProcess argParent) : base(argParent)
        {
        }
    }

    /// <summary>
    /// Bypasser manager
    /// </summary>
    public class BypassersMgr
    {
        //-----------------------------------------
        //--------------- Objects -----------------
        #region RegionBypasser_base

        ///// <summary>
        ///// RegionBypasser_base
        ///// Warning : With the LagReducer you can't add a new detourned part after you detourned a instruction !
        ///// You must detour each parts you need before !
        ///// </summary>
        //public class RegionBypasser_base
        //{
        //    //----------------------
        //    //----- Defines --------
        //    /// <summary>
        //    /// Define if the ByPasser is enable.
        //    /// </summary>
        //    public bool IsEnable
        //    {
        //        get
        //        {
        //            return m_IsEnable;
        //        }
        //        set
        //        {
        //        }
        //    }
        //    bool m_IsEnable = false;

        //    /// <summary>
        //    /// Define if the Lag Reducer is enable.
        //    /// Lag reducer 'll increase the execution speed of the part mode.
        //    /// But you must add each protected parts before detourne voids !
        //    /// </summary>
        //    public bool LagReducer
        //    {
        //        get
        //        {
        //            return m_LagReducer;
        //        }
        //        set
        //        {
        //        }
        //    }
        //    bool m_LagReducer = false;

        //    /// <summary>
        //    /// Process ID
        //    /// </summary>
        //    public int PID
        //    {
        //        get
        //        {
        //            return iPID;
        //        }
        //        set
        //        {
        //        }
        //    }
        //    int iPID;

        //    /// <summary>
        //    /// Define if it's a X64 Process.
        //    /// </summary>
        //    bool IsX64;

        //    /// <summary>
        //    /// Content Array
        //    /// </summary>
        //    Allocations.Allocation Array;

        //    /// <summary>
        //    /// List of detourned Parts.
        //    /// </summary>
        //    List<Part> DetournedParts = new List<Part>();

        //    /// <summary>
        //    /// List of detourned Instruction.
        //    /// </summary>
        //    List<Assembler.DetournedInstruction> DetournedInstructions = new List<Assembler.DetournedInstruction>();


        //    //-------------------------------
        //    //------ Enums/Subclass ---------
        //    /// <summary>
        //    /// Register
        //    /// </summary>
        //    public enum Register : uint
        //    {
        //        eax = 4,
        //        ebx = 8,
        //        ecx = 12,
        //        edx = 24,
        //        esi = 48,
        //        edi = 64,
        //        ebp = 128,
        //        esp = 256,
        //        none = 512
        //    }

        //    /// <summary>
        //    /// Part
        //    /// </summary>
        //    public class Part
        //    {
        //        //----------------------
        //        //----- Defines --------
        //        /// <summary>
        //        /// BaseAdress
        //        /// </summary>
        //        public IntPtr Address;

        //        /// <summary>
        //        /// Length
        //        /// </summary>
        //        public UIntPtr Length;

        //        /// <summary>
        //        /// Allocation
        //        /// </summary>
        //        public Allocations.Allocation Alloc;


        //        //----------------------
        //        //----- Voids ----------
        //        /// <summary>
        //        /// Constructor
        //        /// </summary>
        //        public Part(int ProcessID, IntPtr Address, UIntPtr Length)
        //        {
        //            try
        //            {
        //                //Check PID
        //                if (!ProcessMgr.CheckPidProcessRunning(ProcessID))
        //                {
        //                    return;
        //                }

        //                //Alloc
        //                Alloc = new Allocations.Allocation(ProcessID, (IntPtr)(ulong)Length);

        //                //Read
        //                IntPtr pHandle = OpenProcess(ProcessID);
        //                byte[] Data = Read.Bytes(pHandle, (IntPtr)(ulong)Address, (uint)(ulong)Length);
        //                CloseHandle(pHandle);

        //                //Set Data
        //                Alloc.SetData(Data);

        //                //Set Flags
        //                this.Address = (IntPtr)((ulong)Address);
        //                this.Length = Length;
        //            }
        //            catch
        //            {
        //                //Return
        //                return;
        //            }
        //        }

        //    }


        //    //-------------------------------
        //    //----------- Voids -------------
        //    /// <summary>
        //    /// Constructor
        //    /// </summary>
        //    public RegionBypasser_base(int ProcessID, bool Is64BitsProcess, bool LagReducer)
        //    {
        //        try
        //        {
        //            //Set Config
        //            this.iPID = ProcessID;
        //            this.IsX64 = Is64BitsProcess;
        //            this.m_LagReducer = LagReducer;

        //            //Update Array
        //            UpdateArray();
        //        }
        //        catch
        //        {
        //        }
        //    }

        //    /// <summary>
        //    /// Destructor
        //    /// </summary>
        //    ~RegionBypasser_base()
        //    {
        //        try
        //        {
        //            //Check PID
        //            if (ProcessMgr.CheckPidProcessRunning(PID))
        //            {
        //                Array.SetData(new byte[1] { 0x00 });
        //            }
        //        }
        //        catch
        //        {
        //        }
        //    }

        //    /// <summary>
        //    /// Secure each adress(PatternPatch) of a PatternList.
        //    /// </summary>
        //    public bool SecurePatternList(ProcessMgr.Scan.PatternList PL)
        //    {
        //        try
        //        {
        //            //Check PID
        //            if (!ProcessMgr.CheckPidProcessRunning(PID))
        //            {
        //                return false;
        //            }

        //            //Check PatternList
        //            if (PL == null) return false;

        //            //Region Mode
        //            foreach (ProcessMgr.Scan.Pattern Pattern in PL.Data)
        //            {
        //                //Check if it's a PatternPatch
        //                if (Pattern is ProcessMgr.Patch.PatternPatch)
        //                {
        //                    //Check if Pattern IsUsable
        //                    if (Pattern.IsUsable)
        //                    {
        //                        if (((ProcessMgr.Patch.PatternPatch)Pattern).PatchedData.Length < 5)
        //                        {
        //                            if (IsX64)
        //                            {
        //                                DetourPart(Pattern.Adress, (UIntPtr)8);
        //                            }
        //                            else
        //                            {
        //                                DetourPart(Pattern.Adress, (UIntPtr)4);
        //                            }
        //                        }
        //                        else
        //                        {
        //                            DetourPart(Pattern.Adress, (UIntPtr)((ProcessMgr.Patch.PatternPatch)Pattern).PatchedData.Length);
        //                        }
        //                    }
        //                }
        //            }

        //            //Return
        //            return true;
        //        }
        //        catch
        //        {
        //            //Return
        //            return false;
        //        }
        //    }

        //    /// <summary>
        //    /// Detour a Memory Part for detourned instructions.
        //    /// Length must be >=4 on x32!
        //    /// Length must be >=8 on x64!
        //    /// </summary>
        //    public bool DetourPart(IntPtr Adress, UIntPtr Length)
        //    {
        //        try
        //        {
        //            //Check PID
        //            if (!ProcessMgr.CheckPidProcessRunning(PID))
        //            {
        //                return false;
        //            }

        //            //Map Process
        //            Allocations.Map Map = new Allocations.Map();
        //            Map.MapProcess(PID);

        //            //Detour
        //            bool AlreadyDetourned = false;
        //            foreach (Part p in DetournedParts)
        //            {
        //                if (((long)Adress >= (long)p.Address) && ((long)Adress < (long)p.Address + (long)p.Length - 4))
        //                {
        //                    AlreadyDetourned = true;
        //                    break;
        //                }
        //            }
        //            if (!AlreadyDetourned)
        //            {
        //                Part NewPart;
        //                if (IsX64)
        //                {
        //                    NewPart = new Part(PID, Adress - 8, Length + 8 + 8); //+8
        //                }
        //                else
        //                {
        //                    NewPart = new Part(PID, Adress - 4, Length + 4 + 4); //+4
        //                }
        //                DetournedParts.Add(NewPart);
        //                UpdateArray();
        //            }
        //            else
        //            {
        //                //Return
        //                return false;
        //            }

        //            //Return
        //            return true;
        //        }
        //        catch
        //        {
        //            //Return
        //            return false;
        //        }
        //    }

        //    /// <summary>
        //    /// Update the Array , or create it if necessary.
        //    /// </summary>
        //    bool UpdateArray()
        //    {
        //        try
        //        {
        //            //Check PID
        //            if (!ProcessMgr.CheckPidProcessRunning(PID))
        //            {
        //                return false;
        //            }

        //            //Generate Content
        //            List<byte> ContentArray = new List<byte>();
        //            if (IsX64)
        //            {
        //            }
        //            else
        //            {
        //                //Count
        //                int Count = 0;
        //                foreach (Part p in DetournedParts)
        //                {
        //                    Count = Count + 1;
        //                }

        //                //Add Count
        //                foreach (byte b in BitConverter.GetBytes((int)Count))
        //                {
        //                    ContentArray.Add(b);
        //                }

        //                //Add Each detourned parts
        //                foreach (Part p in DetournedParts)
        //                {
        //                    //Add Original region Base adress
        //                    foreach (byte b in BitConverter.GetBytes((int)p.Address))
        //                    {
        //                        ContentArray.Add(b);
        //                    }

        //                    //Add Original region last adress
        //                    foreach (byte b in BitConverter.GetBytes((int)p.Address + (int)p.Length - 4))
        //                    {
        //                        ContentArray.Add(b);
        //                    }

        //                    //Add Copy region base adress
        //                    foreach (byte b in BitConverter.GetBytes((int)p.Alloc.BaseAddress))
        //                    {
        //                        ContentArray.Add(b);
        //                    }
        //                }
        //            }

        //            //Poke
        //            if (Array == null)
        //            {
        //                Array = new Allocations.Allocation(PID, (IntPtr)ContentArray.ToArray().Length);
        //                Array.FreeOnDispose = false;
        //                Array.SetData(ContentArray.ToArray());
        //            }
        //            else
        //            {
        //                Array.SetData(ContentArray.ToArray());
        //            }

        //            //Return
        //            return true;
        //        }
        //        catch
        //        {
        //            //Return
        //            return false;
        //        }
        //    }

        //    /// <summary>
        //    /// Detour an instruction.
        //    /// JumpLength must be >=5 on x32!
        //    /// JumpLength must be >=9 on x64!
        //    /// </summary>
        //    public bool DetourInstruction(IntPtr Adress, Register AdressReg, UIntPtr InstructionLength, UIntPtr JumpLength)
        //    {
        //        try
        //        {
        //            //-------------------
        //            //Checks
        //            if (!ProcessMgr.CheckPidProcessRunning(PID)) return false;
        //            if (Array == null) return false;
        //            if (IsX64)
        //            {
        //                if (JumpLength.ToUInt64() < 9) return false;
        //            }
        //            else
        //            {
        //                if (JumpLength.ToUInt32() < 5) return false;
        //            }

        //            //-------------------
        //            //Detourn Region or Part
        //            DetourPart(Adress, JumpLength);

        //            //Initialize
        //            Assembler.DetournedInstruction NEWDI = new Assembler.DetournedInstruction(PID, Adress, (UIntPtr)JumpLength, false, null, IsX64);

        //            //-------------------
        //            //Generate Void
        //            List<byte> AsmVoid = new List<byte>();
        //            if (IsX64)
        //            {
        //            }
        //            else
        //            {
        //                //LagReducer
        //                if (m_LagReducer)
        //                {
        //                    List<List<IntPtr>> Lists = new List<List<IntPtr>>();
        //                    uint MaxLength = 0;
        //                    foreach (Part P in DetournedParts)
        //                    {
        //                        if ((uint)P.Length - 4 > MaxLength) MaxLength = (uint)P.Length - 4;
        //                        bool Added = false;
        //                        foreach (List<IntPtr> SL in Lists)
        //                        {
        //                            List<IntPtr> GoodList = null;
        //                            foreach (IntPtr Ad in SL)
        //                            {
        //                                ulong Range;
        //                                if ((ulong)Ad > (ulong)P.Address)
        //                                {
        //                                    Range = (ulong)Ad - (ulong)P.Address;
        //                                }
        //                                else
        //                                {
        //                                    Range = (ulong)P.Address - (ulong)Ad;
        //                                }
        //                                if (Range <= 0x500000)
        //                                {
        //                                    GoodList = SL;
        //                                    break;
        //                                }
        //                            }
        //                            if (GoodList != null)
        //                            {
        //                                GoodList.Add(P.Address);
        //                                Added = true;
        //                            }
        //                            if (Added) break;
        //                        }
        //                        if (!Added)
        //                        {
        //                            List<IntPtr> NewList = new List<IntPtr>();
        //                            NewList.Add(P.Address);
        //                            Lists.Add(NewList);
        //                        }
        //                    }
        //                    if (Lists.Count != 0)
        //                    {
        //                        AsmVoid.Add((byte)0x50); //push eax
        //                        AsmVoid.Add((byte)0x9C); //pushfd
        //                        //AsmVoid.Add((byte)0x66); //pushf
        //                        //AsmVoid.Add((byte)0x9C);
        //                        if (AdressReg == Register.eax)
        //                        {
        //                            AsmVoid.Add((byte)0x90); //nop nop
        //                            AsmVoid.Add((byte)0x90);
        //                        }
        //                        else if (AdressReg == Register.ebp)
        //                        {
        //                            AsmVoid.Add((byte)0x8B); //mov eax,ebp
        //                            AsmVoid.Add((byte)0xC5);
        //                        }
        //                        else if (AdressReg == Register.ebx)
        //                        {
        //                            AsmVoid.Add((byte)0x8B); //mov eax,ebx
        //                            AsmVoid.Add((byte)0xC3);
        //                        }
        //                        else if (AdressReg == Register.ecx)
        //                        {
        //                            AsmVoid.Add((byte)0x8B); //mov eax,ecx
        //                            AsmVoid.Add((byte)0xC1);
        //                        }
        //                        else if (AdressReg == Register.edi)
        //                        {
        //                            AsmVoid.Add((byte)0x8B); //mov eax,edi
        //                            AsmVoid.Add((byte)0xC7);
        //                        }
        //                        else if (AdressReg == Register.edx)
        //                        {
        //                            AsmVoid.Add((byte)0x8B); //mov eax,edx
        //                            AsmVoid.Add((byte)0xC2);
        //                        }
        //                        else if (AdressReg == Register.esi)
        //                        {
        //                            AsmVoid.Add((byte)0x8B); //mov eax,esi
        //                            AsmVoid.Add((byte)0xC6);
        //                        }
        //                        else if (AdressReg == Register.esp)
        //                        {
        //                            AsmVoid.Add((byte)0x8B); //mov eax,esp
        //                            AsmVoid.Add((byte)0xC4);
        //                        }

        //                        uint count = 1;
        //                        foreach (List<IntPtr> SL in Lists)
        //                        {
        //                            uint MinAdress = UInt32.MaxValue;
        //                            uint MaxAdress = UInt32.MinValue;
        //                            foreach (IntPtr In in SL)
        //                            {
        //                                if ((uint)In < MinAdress) MinAdress = (uint)In;
        //                                if ((uint)In > MaxAdress) MaxAdress = (uint)In;
        //                            }
        //                            AsmVoid.Add((byte)0x3D);//cmp eax,STARTPART
        //                            foreach (byte b in BitConverter.GetBytes((MinAdress)))
        //                            {
        //                                AsmVoid.Add(b);
        //                            }
        //                            AsmVoid.Add((byte)0x7C); //jnge NEXT
        //                            AsmVoid.Add((byte)0x0E);
        //                            AsmVoid.Add((byte)0x3D);//cmp eax,ENDPART
        //                            foreach (byte b in BitConverter.GetBytes((MaxAdress + MaxLength)))
        //                            {
        //                                AsmVoid.Add(b);
        //                            }
        //                            AsmVoid.Add((byte)0x7F); //jg NEXT
        //                            AsmVoid.Add((byte)0x07);
        //                            AsmVoid.Add((byte)0x9D); //popfd
        //                            AsmVoid.Add((byte)0x58); //pop eax
        //                            AsmVoid.Add((byte)0xE9);//jump STARTVOID
        //                            uint ActualAddress = (uint)NEWDI.Void.BaseAddress + 4 + (count * 21) - 5;
        //                            uint AddressVoid = (uint)NEWDI.Void.BaseAddress + 4 + ((uint)Lists.Count * 21) + 2 + (uint)NEWDI.OriginalData.Length + 5;
        //                            uint Reloc = AddressVoid - ActualAddress + 5;
        //                            foreach (byte b in BitConverter.GetBytes(Reloc))
        //                            {
        //                                AsmVoid.Add(b);
        //                            }
        //                            count = count + 1;
        //                        }
        //                        //AsmVoid.Add((byte)0x66); //popf
        //                        //AsmVoid.Add((byte)0x9D);
        //                        AsmVoid.Add((byte)0x9D); //popfd
        //                        AsmVoid.Add((byte)0x58); //pop eax
        //                        foreach (byte b in NEWDI.OriginalData) //Original Data
        //                        {
        //                            AsmVoid.Add(b);
        //                        }
        //                        uint AA = (uint)NEWDI.Void.BaseAddress + 4 + ((uint)Lists.Count * 21) + 2 + (uint)NEWDI.OriginalData.Length;
        //                        uint Rel = ((uint)NEWDI.Adress) - AA;
        //                        AsmVoid.Add((byte)0xE9);//jump DETOUR
        //                        foreach (byte b in BitConverter.GetBytes(Rel))
        //                        {
        //                            AsmVoid.Add(b);
        //                        }
        //                    }
        //                }

        //                //Set Buffer Adress
        //                uint Buff1 = (uint)NEWDI.Void.BaseAddress + (uint)AsmVoid.Count + 2;
        //                uint Buff2 = (uint)NEWDI.Void.BaseAddress + (uint)AsmVoid.Count + 6;

        //                //Jump to Analyse Register
        //                AsmVoid.Add((byte)0xEB); //jmp
        //                AsmVoid.Add((byte)0x08);

        //                //Buffer1
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);

        //                //Buffer2
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);

        //                //Push Flags
        //                AsmVoid.Add((byte)0x9C); //pushfd
        //                //AsmVoid.Add((byte)0x66); //pushf
        //                //AsmVoid.Add((byte)0x9C);

        //                //Push Registers
        //                AsmVoid.Add((byte)0x50); //push eax
        //                AsmVoid.Add((byte)0x51); //push ecx
        //                AsmVoid.Add((byte)0x52); //push edx
        //                AsmVoid.Add((byte)0x57); //push edi

        //                //Mov Register buffer2,Mov register EAX
        //                if (AdressReg == Register.eax)
        //                {
        //                }
        //                else if (AdressReg == Register.ebp)
        //                {
        //                    AsmVoid.Add((byte)0x8B); //mov eax,ebp
        //                    AsmVoid.Add((byte)0xC5);
        //                }
        //                else if (AdressReg == Register.ebx)
        //                {
        //                    AsmVoid.Add((byte)0x8B); //mov eax,ebx
        //                    AsmVoid.Add((byte)0xC3);
        //                }
        //                else if (AdressReg == Register.ecx)
        //                {
        //                    AsmVoid.Add((byte)0x8B); //mov eax,ecx
        //                    AsmVoid.Add((byte)0xC1);
        //                }
        //                else if (AdressReg == Register.edi)
        //                {
        //                    AsmVoid.Add((byte)0x8B); //mov eax,edi
        //                    AsmVoid.Add((byte)0xC7);
        //                }
        //                else if (AdressReg == Register.edx)
        //                {
        //                    AsmVoid.Add((byte)0x8B); //mov eax,edx
        //                    AsmVoid.Add((byte)0xC2);
        //                }
        //                else if (AdressReg == Register.esi)
        //                {
        //                    AsmVoid.Add((byte)0x8B); //mov eax,esi
        //                    AsmVoid.Add((byte)0xC6);
        //                }
        //                else if (AdressReg == Register.esp)
        //                {
        //                    AsmVoid.Add((byte)0x8B); //mov eax,esp
        //                    AsmVoid.Add((byte)0xC4);
        //                }

        //                AsmVoid.Add((byte)0xB9); //mov ecx,buffer2
        //                foreach (byte b in BitConverter.GetBytes(Buff2))
        //                {
        //                    AsmVoid.Add(b);
        //                }
        //                AsmVoid.Add((byte)0x89); //mov [ecx],eax
        //                AsmVoid.Add((byte)0x01);

        //                AsmVoid.Add((byte)0xB9);//mov ecx,00000000
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);

        //                AsmVoid.Add((byte)0xBF);//mov edi,ARRAY
        //                foreach (byte b in BitConverter.GetBytes(Array.BaseAddress.ToInt32()))
        //                {
        //                    AsmVoid.Add(b);
        //                }

        //                AsmVoid.Add((byte)0xBA);//mov edx,ARRAY
        //                foreach (byte b in BitConverter.GetBytes(Array.BaseAddress.ToInt32()))
        //                {
        //                    AsmVoid.Add(b);
        //                }

        //                AsmVoid.Add((byte)0x3B);//cmp ecx,[ARRAY]
        //                AsmVoid.Add((byte)0x0D);
        //                foreach (byte b in BitConverter.GetBytes(Array.BaseAddress.ToInt32()))
        //                {
        //                    AsmVoid.Add(b);
        //                }

        //                AsmVoid.Add((byte)0x74);//je FIN
        //                AsmVoid.Add((byte)0x36);

        //                AsmVoid.Add((byte)0x8B);//mov edi,edx
        //                AsmVoid.Add((byte)0xFA);

        //                AsmVoid.Add((byte)0x81);//add edi,00000004
        //                AsmVoid.Add((byte)0xC7);
        //                AsmVoid.Add((byte)0x04);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);

        //                AsmVoid.Add((byte)0x3B);//cmp eax,[edi]
        //                AsmVoid.Add((byte)0x07);

        //                AsmVoid.Add((byte)0x7C);//jnge 076D005D
        //                AsmVoid.Add((byte)0x1C);

        //                AsmVoid.Add((byte)0x81);//add edi,00000004
        //                AsmVoid.Add((byte)0xC7);
        //                AsmVoid.Add((byte)0x04);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);

        //                AsmVoid.Add((byte)0x3B);//cmp eax,[edi]
        //                AsmVoid.Add((byte)0x07);

        //                AsmVoid.Add((byte)0x7D);//jnl 076D005D
        //                AsmVoid.Add((byte)0x12);

        //                AsmVoid.Add((byte)0x81);//sub edi,00000004
        //                AsmVoid.Add((byte)0xEF);
        //                AsmVoid.Add((byte)0x04);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);

        //                AsmVoid.Add((byte)0x2B);//sub eax,[edi]
        //                AsmVoid.Add((byte)0x07);

        //                AsmVoid.Add((byte)0x81);//add edi,00000008
        //                AsmVoid.Add((byte)0xC7);
        //                AsmVoid.Add((byte)0x08);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);

        //                AsmVoid.Add((byte)0x03);//add eax,[edi]
        //                AsmVoid.Add((byte)0x07);


        //                AsmVoid.Add((byte)0xEB);//jmp 076D006B
        //                AsmVoid.Add((byte)0x0E);

        //                AsmVoid.Add((byte)0x81);//add edx,0000000C
        //                AsmVoid.Add((byte)0xC2);
        //                AsmVoid.Add((byte)0x0C);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);

        //                AsmVoid.Add((byte)0x81);//add ecx,00000001
        //                AsmVoid.Add((byte)0xC1);
        //                AsmVoid.Add((byte)0x01);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);
        //                AsmVoid.Add((byte)0x00);

        //                AsmVoid.Add((byte)0xEB);//jmp 076D0027
        //                AsmVoid.Add((byte)0xC2);

        //                //Set Buffer1
        //                AsmVoid.Add((byte)0xB9); //mov ecx,buffer1
        //                foreach (byte b in BitConverter.GetBytes(Buff1))
        //                {
        //                    AsmVoid.Add(b);
        //                }
        //                AsmVoid.Add((byte)0x89); //mov [ecx],eax
        //                AsmVoid.Add((byte)0x01);

        //                //Pop Registers
        //                AsmVoid.Add((byte)0x5F); //pop edi
        //                AsmVoid.Add((byte)0x5A); //pop edx
        //                AsmVoid.Add((byte)0x59); //pop ecx
        //                AsmVoid.Add((byte)0x58); //pop eax
        //                //AsmVoid.Add((byte)0x66); //popf
        //                //AsmVoid.Add((byte)0x9D);
        //                AsmVoid.Add((byte)0x9D); //popfd

        //                //Set Buffer1 on the register
        //                if (AdressReg == Register.eax)
        //                {
        //                    AsmVoid.Add((byte)0xB8); //mov eax,buffer1
        //                    foreach (byte b in BitConverter.GetBytes(Buff1))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                    AsmVoid.Add((byte)0x8B); //mov eax,[eax]
        //                    AsmVoid.Add((byte)0x00);
        //                }
        //                else if (AdressReg == Register.ebp)
        //                {
        //                    AsmVoid.Add((byte)0xBD); //mov ebp,buffer1
        //                    foreach (byte b in BitConverter.GetBytes(Buff1))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                    AsmVoid.Add((byte)0x8B); //mov ebp,[ebp+00]
        //                    AsmVoid.Add((byte)0x6D);
        //                    AsmVoid.Add((byte)0x00);
        //                }
        //                else if (AdressReg == Register.ebx)
        //                {
        //                    AsmVoid.Add((byte)0xBB); //mov ebx,buffer1
        //                    foreach (byte b in BitConverter.GetBytes(Buff1))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                    AsmVoid.Add((byte)0x8B); //mov ebx,[ebx]
        //                    AsmVoid.Add((byte)0x1B);
        //                }
        //                else if (AdressReg == Register.ecx)
        //                {
        //                    AsmVoid.Add((byte)0xB9); //mov ecx,buffer1
        //                    foreach (byte b in BitConverter.GetBytes(Buff1))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                    AsmVoid.Add((byte)0x8B); //mov ecx,[ecx]
        //                    AsmVoid.Add((byte)0x09);
        //                }
        //                else if (AdressReg == Register.edi)
        //                {
        //                    AsmVoid.Add((byte)0xBF); //mov edi,buffer1
        //                    foreach (byte b in BitConverter.GetBytes(Buff1))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                    AsmVoid.Add((byte)0x8B); //mov edi,[edi]
        //                    AsmVoid.Add((byte)0x3F);
        //                }
        //                else if (AdressReg == Register.edx)
        //                {
        //                    AsmVoid.Add((byte)0xBA); //mov edx,buffer1
        //                    foreach (byte b in BitConverter.GetBytes(Buff1))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                    AsmVoid.Add((byte)0x8B); //mov edx,[edx]
        //                    AsmVoid.Add((byte)0x12);
        //                }
        //                else if (AdressReg == Register.esi)
        //                {
        //                    AsmVoid.Add((byte)0xBE); //mov esi,buffer1
        //                    foreach (byte b in BitConverter.GetBytes(Buff1))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                    AsmVoid.Add((byte)0x8B); //mov esi,[esi]
        //                    AsmVoid.Add((byte)0x36);
        //                }
        //                else if (AdressReg == Register.esp)
        //                {
        //                    AsmVoid.Add((byte)0xBC); //mov esp,buffer1
        //                    foreach (byte b in BitConverter.GetBytes(Buff1))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                    AsmVoid.Add((byte)0x8B); //mov esp,[esp+esp]
        //                    AsmVoid.Add((byte)0x24);
        //                    AsmVoid.Add((byte)0x24);
        //                }

        //                //Get data
        //                IntPtr pHandle = OpenProcess(PID);
        //                byte[] OriginalData = Read.Bytes(pHandle, Adress, (uint)JumpLength);
        //                CloseHandle(pHandle);

        //                //Instruction
        //                for (int i = 1; i <= (uint)InstructionLength; i++)
        //                {
        //                    AsmVoid.Add(OriginalData[i - 1]);
        //                }

        //                //Restore Register
        //                if (AdressReg == Register.eax)
        //                {
        //                    AsmVoid.Add((byte)0xB8); //mov eax,buffer2
        //                    foreach (byte b in BitConverter.GetBytes(Buff2))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                }
        //                else if (AdressReg == Register.ebp)
        //                {
        //                    AsmVoid.Add((byte)0xBD); //mov ebp,buffer2
        //                    foreach (byte b in BitConverter.GetBytes(Buff2))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                }
        //                else if (AdressReg == Register.ebx)
        //                {
        //                    AsmVoid.Add((byte)0xBB); //mov ebx,buffer2
        //                    foreach (byte b in BitConverter.GetBytes(Buff2))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                }
        //                else if (AdressReg == Register.ecx)
        //                {
        //                    AsmVoid.Add((byte)0xB9); //mov ecx,buffer2
        //                    foreach (byte b in BitConverter.GetBytes(Buff2))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                }
        //                else if (AdressReg == Register.edi)
        //                {
        //                    AsmVoid.Add((byte)0xBF); //mov edi,buffer2
        //                    foreach (byte b in BitConverter.GetBytes(Buff2))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                }
        //                else if (AdressReg == Register.edx)
        //                {
        //                    AsmVoid.Add((byte)0xBA); //mov edx,buffer2
        //                    foreach (byte b in BitConverter.GetBytes(Buff2))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                }
        //                else if (AdressReg == Register.esi)
        //                {
        //                    AsmVoid.Add((byte)0xBE); //mov esi,buffer2
        //                    foreach (byte b in BitConverter.GetBytes(Buff2))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                }
        //                else if (AdressReg == Register.esp)
        //                {
        //                    AsmVoid.Add((byte)0xBC); //mov esp,buffer2
        //                    foreach (byte b in BitConverter.GetBytes(Buff2))
        //                    {
        //                        AsmVoid.Add(b);
        //                    }
        //                }

        //                //Others Instructions
        //                for (int i = ((int)InstructionLength + 1); i <= (uint)JumpLength; i++)
        //                {
        //                    AsmVoid.Add(OriginalData[i - 1]);
        //                }

        //            }

        //            //Initialize
        //            NEWDI.WriteData(AsmVoid.ToArray());

        //            //Log
        //            NEWDI.Enable();
        //            DetournedInstructions.Add(NEWDI);

        //            //Return
        //            return true;
        //        }
        //        catch
        //        {
        //            //Return
        //            return false;
        //        }
        //    }

        //    /// <summary>
        //    /// Enable the ByPasser.
        //    /// </summary>
        //    public virtual bool Enable()
        //    {
        //        //Set Flag
        //        m_IsEnable = true;

        //        //Return
        //        return true;
        //    }

        //    /// <summary>
        //    /// Disable the ByPasser.
        //    /// </summary>
        //    public virtual bool Disable()
        //    {
        //        //Set Flag
        //        m_IsEnable = false;

        //        //Return
        //        return true;
        //    }


        //}

        #endregion RegionBypasser_base

        //---------------------------------
        //------- Ready To Work -----------
        #region Xlive

        /// <summary>
        /// XLive Bypass
        /// ByPasser for XLive
        /// Up1:22/01/2012
        /// </summary>
        public class XLive
        {
            //----------------------
            //------- Voids --------
            /// <summary>
            /// XLive Bypasser
            /// WARNING : XLive ByPass is not enable by default !
            /// </summary>
            public XLive(int ProcessID)
            {
                //Up1:22/01/2012
                //PatternPatch Pattern_22122012 = new ProcessMgr.Patch.PatternPatch();
                //Pattern_22122012.Id = 0;
                //Pattern_22122012.Name = "22122012";
                //Pattern_22122012.Description = "Up1:22/01/2012";
                //Pattern_22122012.StaticOffsets = new List<ProcessMgr.Scan.ByteInfo>();
                //Pattern_22122012.StaticOffsets.Add(new ProcessMgr.Scan.ByteInfo(0x02, 0xFF));
                //Pattern_22122012.StaticOffsets.Add(new ProcessMgr.Scan.ByteInfo(0x05, 0x8B));
                //Pattern_22122012.StaticOffsets.Add(new ProcessMgr.Scan.ByteInfo(0x07, 0xFF));
                //Pattern_22122012.StaticOffsets.Add(new ProcessMgr.Scan.ByteInfo(0x0B, 0xE8));
                //Pattern_22122012.StaticOffsets.Add(new ProcessMgr.Scan.ByteInfo(0x1D, 0xE8));
                //Pattern_22122012.StaticOffsets.Add(new ProcessMgr.Scan.ByteInfo(0x2F, 0xE8));
                //Pattern_22122012.StaticOffsets.Add(new ProcessMgr.Scan.ByteInfo(0x36, 0x8D));
                //Pattern_22122012.StaticOffsets.Add(new ProcessMgr.Scan.ByteInfo(0x3C, 0xE8));
                //Pattern_22122012.PatchedData = new byte[2] { 0xEB, 0x14 };
                //PatternsList.Data.Add(Pattern_22122012);
            }


        }

        #endregion Xlive


    }

    /// <summary>
    /// Pixels manager
    /// </summary>
    public class PixelsMgr : hibClass
    {
        //-----------------------------------------
        //---------------- Enums ------------------

        //-----------------------------------------
        //-------------- Variables ----------------

        //-----------------------------------------
        //-------------- Functions ----------------
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="argParent">hibProcess</param>
        public PixelsMgr(hibProcess argParent) : base(argParent)
        {
        }

        /// <summary>
        /// Get a pixel color from desktop.
        /// </summary>
        /// <param name="argX">X</param>
        /// <param name="argY">Y</param>
        /// <returns>Return color</returns>
        /// <exception cref="Exception">Throws general exception on failure.</exception>
        public Color GetPixelColorFromDesktop(int argX, int argY)
        {
            
            IntPtr desk = Import.GetDesktopWindow();
            IntPtr dc = Import.GetWindowDC(desk);
            int a = (int)Import.GetPixel(dc, argX, argY);
            Import.ReleaseDC(desk, dc);
            return Color.FromArgb(255, (a >> 0) & 0xff, (a >> 8) & 0xff, (a >> 16) & 0xff);
        }
    }
}

