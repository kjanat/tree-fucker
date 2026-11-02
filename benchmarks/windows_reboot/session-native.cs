using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class SessionNative {
    [StructLayout(LayoutKind.Sequential)]
    struct WtsSession { public int Id; public IntPtr Station; public int State; }
    public sealed class Session { public int Id; public string User; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct Startup {
        public int Size; public string Reserved; public string Desktop; public string Title;
        public int X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        public short Show, ReservedSize; public IntPtr ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInfo { public IntPtr Process, Thread; public int ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    struct SecurityAttributes { public int Size; public IntPtr Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential)]
    struct Capabilities { public IntPtr Sid, Entries; public int Count, Reserved; }
    [StructLayout(LayoutKind.Sequential)]
    struct Extended { public Startup Startup; public IntPtr Attributes; }
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int CreateAppContainerProfile(string name, string display, string description, IntPtr capabilities, uint count, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int DeleteAppContainerProfile(string name);
    [DllImport("advapi32.dll")]
    static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity,
        bool inherit, int flags, IntPtr environment, string directory, ref Extended startup, out ProcessInfo process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string path, uint access, uint share, ref SecurityAttributes security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSQuerySessionInformationW(IntPtr server, int session, int info, out IntPtr buffer, out int length);
    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr buffer);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSQueryUserToken(int session, out IntPtr token);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSLogoffSession(IntPtr server, int session, bool wait);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int info, IntPtr value, int length, out int returned);
    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
    [DllImport("userenv.dll")]
    static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessAsUserW(IntPtr token, string application, StringBuilder command,
        IntPtr processSecurity, IntPtr threadSecurity, bool inherit, int flags, IntPtr environment,
        string directory, ref Startup startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr handle, out uint code);

    static void Check(bool success) { if (!success) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public static Session[] Sessions() {
        IntPtr buffer; int count;
        Check(WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out buffer, out count));
        try {
            var sessions = new List<Session>();
            int size = Marshal.SizeOf(typeof(WtsSession));
            for (int i = 0; i < count; i++) {
                var item = (WtsSession)Marshal.PtrToStructure(IntPtr.Add(buffer, i * size), typeof(WtsSession));
                if (item.Id == 0 || item.State != 0) continue;
                IntPtr name; int length;
                Check(WTSQuerySessionInformationW(IntPtr.Zero, item.Id, 5, out name, out length));
                try { sessions.Add(new Session { Id = item.Id, User = Marshal.PtrToStringUni(name) }); }
                finally { WTSFreeMemory(name); }
            }
            return sessions.ToArray();
        } finally { WTSFreeMemory(buffer); }
    }
    public static void Logoff(int session) { Check(WTSLogoffSession(IntPtr.Zero, session, true)); }
    static bool Elevated(IntPtr token) {
        IntPtr value = Marshal.AllocHGlobal(4);
        try { int length; Check(GetTokenInformation(token, 20, value, 4, out length)); return Marshal.ReadInt32(value) != 0; }
        finally { Marshal.FreeHGlobal(value); }
    }
    static IntPtr Linked(IntPtr token) {
        IntPtr value = Marshal.AllocHGlobal(IntPtr.Size);
        try { int length; Check(GetTokenInformation(token, 19, value, IntPtr.Size, out length)); return Marshal.ReadIntPtr(value); }
        finally { Marshal.FreeHGlobal(value); }
    }
    static string Quote(string value) {
        if (value.IndexOf('"') >= 0 || value.EndsWith("\\")) throw new ArgumentException("Invalid fixture argument");
        return "\"" + value + "\"";
    }
    public sealed class Worker : IDisposable {
        IntPtr handle;
        internal Worker(IntPtr process) { handle = process; }
        public bool Running {
            get {
                uint result = WaitForSingleObject(handle, 0);
                if (result == 0) return false;
                if (result == 258) return true;
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        public uint Wait() {
            uint result = WaitForSingleObject(handle, 30000);
            if (result != 0) throw new InvalidOperationException("Session worker did not exit: " + result);
            uint code; Check(GetExitCodeProcess(handle, out code)); return code;
        }
        public void Dispose() { if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; } }
    }
    public static Worker Launch(int session, bool elevated, string name, string mode, string scope) {
        IntPtr token;
        Check(WTSQueryUserToken(session, out token));
        IntPtr linked = IntPtr.Zero, environment = IntPtr.Zero;
        try {
            IntPtr selected = token;
            if (Elevated(token) != elevated) { linked = Linked(token); selected = linked; }
            if (Elevated(selected) != elevated) throw new InvalidOperationException("Requested elevation unavailable");
            Check(CreateEnvironmentBlock(out environment, selected, false));
            string exe = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            var command = new StringBuilder(Quote(exe) + @" -NoProfile -ExecutionPolicy Bypass -File C:\OEM\session-child.ps1 -Name " + Quote(name) + " -Mode " + Quote(mode) + " -Scope " + Quote(scope));
            var startup = new Startup { Size = Marshal.SizeOf(typeof(Startup)), Desktop = @"winsta0\default" };
            ProcessInfo process;
            // No inherited handles cross the session boundary. The child opens
            // its own report files after its real user environment is installed.
            Check(CreateProcessAsUserW(selected, exe, command, IntPtr.Zero, IntPtr.Zero, false,
                0x08000400, environment, @"C:\OEM", ref startup, out process));
            CloseHandle(process.Thread);
            return new Worker(process.Process);
        } finally {
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (linked != IntPtr.Zero) CloseHandle(linked);
            CloseHandle(token);
        }
    }

    // Called by the ordinary user's launcher, in that user's real session.
    public static uint RunContainer(string log) {
        string name = "tree-fucker-" + Guid.NewGuid().ToString("N");
        IntPtr sid;
        Marshal.ThrowExceptionForHR(CreateAppContainerProfile(name, name, "Disposable coordination acceptance", IntPtr.Zero, 0, out sid));
        IntPtr attributes = IntPtr.Zero, caps = IntPtr.Zero, handles = IntPtr.Zero;
        IntPtr output = IntPtr.Zero, input = IntPtr.Zero;
        bool initialized = false;
        try {
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
            if (size == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            attributes = Marshal.AllocHGlobal(size);
            Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref size));
            initialized = true;
            caps = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Capabilities)));
            Marshal.StructureToPtr(new Capabilities { Sid = sid }, caps, false);
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20009), caps,
                new IntPtr(Marshal.SizeOf(typeof(Capabilities))), IntPtr.Zero, IntPtr.Zero));
            var security = new SecurityAttributes { Size = Marshal.SizeOf(typeof(SecurityAttributes)), Inherit = 1 };
            output = CreateFileW(log, 0x40000000, 3, ref security, 2, 0x80, IntPtr.Zero);
            Check(output != new IntPtr(-1));
            input = CreateFileW("NUL", 0x80000000, 3, ref security, 3, 0x80, IntPtr.Zero);
            Check(input != new IntPtr(-1));
            handles = Marshal.AllocHGlobal(2 * IntPtr.Size);
            Marshal.WriteIntPtr(handles, 0, input);
            Marshal.WriteIntPtr(handles, IntPtr.Size, output);
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handles,
                new IntPtr(2 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
            var startup = new Extended {
                Startup = new Startup { Size = Marshal.SizeOf(typeof(Extended)), Flags = 0x100, Input = input, Output = output, Error = output },
                Attributes = attributes,
            };
            string exe = @"C:\OEM\coordination_power.exe";
            var command = new StringBuilder(Quote(exe) + " --exact windows_sessions::interactive_session_fixture --ignored --nocapture");
            ProcessInfo process;
            // Standard handles are explicitly inherited within this session;
            // no other launcher handle crosses into the AppContainer.
            Check(CreateProcessW(exe, command, IntPtr.Zero, IntPtr.Zero, true, 0x08080400,
                IntPtr.Zero, @"C:\coordination-sessions", ref startup, out process));
            CloseHandle(process.Thread);
            try {
                if (WaitForSingleObject(process.Process, 30000) != 0) {
                    TerminateProcess(process.Process, 1);
                    WaitForSingleObject(process.Process, 5000);
                    throw new InvalidOperationException("AppContainer fixture timed out");
                }
                uint code; Check(GetExitCodeProcess(process.Process, out code)); return code;
            } finally { CloseHandle(process.Process); }
        } finally {
            if (input != IntPtr.Zero && input != new IntPtr(-1)) CloseHandle(input);
            if (output != IntPtr.Zero && output != new IntPtr(-1)) CloseHandle(output);
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (caps != IntPtr.Zero) Marshal.FreeHGlobal(caps);
            if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
            FreeSid(sid);
            Marshal.ThrowExceptionForHR(DeleteAppContainerProfile(name));
        }
    }
}
