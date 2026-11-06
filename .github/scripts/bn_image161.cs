// Windows-only CI fixture. SEC_IMAGE maps image pages without calling a DLL
// entry point, TLS callback, export, or any other vendor code. Authenticate the
// test asset against its manifest before constructing NativeImage161.
// Compatible with Windows PowerShell 5.1 Add-Type (.NET Framework/C# 5).
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public sealed class NativeMove161Result
{
    public bool Success { get; private set; }
    public int Win32Error { get; private set; }

    internal NativeMove161Result(bool success, int error)
    {
        Success = success;
        Win32Error = error;
    }
}

public sealed class NativeImage161 : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint ReadAttributes = 0x00000080;
    private const uint ShareAll = 0x00000007;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint AttributeDirectory = 0x00000010;
    private const uint AttributeReparsePoint = 0x00000400;
    private const uint PageReadOnly = 0x00000002;
    private const uint SecImage = 0x01000000;
    private const uint FileMapRead = 0x00000004;
    private const int FileAttributeTagInfo = 9;
    private const int FileIdInfo = 18;
    private static readonly IntPtr InvalidHandle = new IntPtr(-1);
    private readonly object gate = new object();
    private IntPtr file;
    private IntPtr section;
    private IntPtr view;
    private bool disposed;

    public NativeImage161(string path)
    {
        try
        {
            file = OpenFile(path, GenericRead, false);
            section = CreateFileMappingW(file, IntPtr.Zero,
                PageReadOnly | SecImage, 0, 0, null);
            if (section == IntPtr.Zero)
                ThrowLastError("CreateFileMappingW(SEC_IMAGE)");
            view = MapViewOfFile(section, FileMapRead, 0, 0, UIntPtr.Zero);
            if (view == IntPtr.Zero)
                ThrowLastError("MapViewOfFile(SEC_IMAGE)");
            ushort machine = MappedMachine;
            ushort magic = MappedOptionalMagic;
            bool supported = (machine == 0x014c && magic == 0x010b) ||
                (machine == 0x8664 && magic == 0x020b);
            if (ReadUInt16(ReadMapped(0, 64), 0) != 0x5a4d ||
                MappedSignature != 0x00004550 || !supported)
                throw new InvalidDataException("The mapped fixture must be an x86 PE32 or AMD64 PE32+ image.");
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    // These getters read the held file object or mapped address again. They do
    // not return values cached before a rename/replacement by the launcher.
    public string Hash
    {
        get { lock (gate) { EnsureOpen(); return HashHandle(file); } }
    }

    // Receipt identity format is 32 bytes: FILE_ID_INFO's native 24 bytes
    // (volume serial uint64, FILE_ID_128) followed by eight zero padding bytes.
    public byte[] Identity
    {
        get { lock (gate) { EnsureOpen(); return IdentityHandle(file); } }
    }

    public long Length
    {
        get { lock (gate) { EnsureOpen(); return LengthHandle(file); } }
    }

    public bool IsMapped
    {
        get { lock (gate) { return !disposed && view != IntPtr.Zero; } }
    }

    public byte[] MappedHeader
    {
        get { lock (gate) { EnsureOpen(); return ReadMapped(0, 64); } }
    }

    public uint MappedSignature
    {
        get { lock (gate) { EnsureOpen(); return ReadUInt32(ReadMapped(PeOffset(), 4), 0); } }
    }

    public ushort MappedMachine
    {
        get { lock (gate) { EnsureOpen(); return ReadUInt16(ReadMapped(PeOffset() + 4, 2), 0); } }
    }

    public ushort MappedOptionalMagic
    {
        get { lock (gate) { EnsureOpen(); return ReadUInt16(ReadMapped(PeOffset() + 24, 2), 0); } }
    }

    public static string HashFile(string path)
    {
        IntPtr handle = OpenFile(path, GenericRead, false);
        try { return HashHandle(handle); }
        finally { CloseHandle(handle); }
    }

    // Opens the current pathname afresh, independently of a held image object.
    public static byte[] FileIdentity(string path)
    {
        IntPtr handle = OpenFile(path, ReadAttributes, false);
        try { return IdentityHandle(handle); }
        finally { CloseHandle(handle); }
    }

    public static byte[] ParentIdentity(string filePath)
    {
        string parent = Path.GetDirectoryName(Path.GetFullPath(filePath));
        if (String.IsNullOrEmpty(parent))
            throw new ArgumentException("A file with a parent directory is required.", "filePath");
        IntPtr handle = OpenFile(parent, ReadAttributes, true);
        try { return IdentityHandle(handle); }
        finally { CloseHandle(handle); }
    }

    // DESTRUCTIVE on success: use only separate copies in the controlled test
    // directory. This is exactly the old REPLACE_EXISTING | WRITE_THROUGH call.
    public static NativeMove161Result ProbeOldMove(string stage, string target)
    {
        bool success = MoveFileExW(Path.GetFullPath(stage), Path.GetFullPath(target), 9);
        int error = success ? 0 : Marshal.GetLastWin32Error();
        return new NativeMove161Result(success, error);
    }

    private static IntPtr OpenFile(string path, uint access, bool directory)
    {
        IntPtr handle = CreateFileW(Path.GetFullPath(path), access, ShareAll,
            IntPtr.Zero, OpenExisting,
            OpenReparsePoint | (directory ? BackupSemantics : 0), IntPtr.Zero);
        if (handle == InvalidHandle)
            ThrowLastError("CreateFileW");
        try
        {
            byte[] info = new byte[8];
            if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, info, info.Length))
                ThrowLastError("GetFileInformationByHandleEx(FileAttributeTagInfo)");
            uint attributes = ReadUInt32(info, 0);
            if ((attributes & AttributeReparsePoint) != 0 ||
                ((attributes & AttributeDirectory) != 0) != directory)
                throw new InvalidDataException("Unexpected fixture file type or reparse point.");
            return handle;
        }
        catch
        {
            CloseHandle(handle);
            throw;
        }
    }

    private static byte[] IdentityHandle(IntPtr handle)
    {
        byte[] native = new byte[24];
        if (!GetFileInformationByHandleEx(handle, FileIdInfo, native, native.Length))
            ThrowLastError("GetFileInformationByHandleEx(FileIdInfo)");
        byte[] receipt = new byte[32];
        Buffer.BlockCopy(native, 0, receipt, 0, native.Length);
        return receipt;
    }

    private static long LengthHandle(IntPtr handle)
    {
        long length;
        if (!GetFileSizeEx(handle, out length))
            ThrowLastError("GetFileSizeEx");
        return length;
    }

    private static string HashHandle(IntPtr handle)
    {
        long ignored;
        if (!SetFilePointerEx(handle, 0, out ignored, 0))
            ThrowLastError("SetFilePointerEx");
        long expectedLength = LengthHandle(handle);
        long total = 0;
        byte[] buffer = new byte[65536];
        using (SHA256 hash = SHA256.Create())
        {
            for (;;)
            {
                uint read;
                if (!ReadFile(handle, buffer, (uint)buffer.Length, out read, IntPtr.Zero))
                    ThrowLastError("ReadFile");
                if (read == 0)
                    break;
                hash.TransformBlock(buffer, 0, (int)read, buffer, 0);
                total += read;
            }
            hash.TransformFinalBlock(new byte[0], 0, 0);
            if (total != expectedLength || LengthHandle(handle) != expectedLength)
                throw new IOException("Fixture file length changed while hashing.");
            return BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant();
        }
    }

    private int PeOffset()
    {
        int offset = (int)ReadUInt32(ReadMapped(0, 64), 0x3c);
        // ReadProcessMemory below checks address readability without invoking
        // mapped code. The raw-file bound also rejects malformed PE offsets.
        long rawLength = LengthHandle(file);
        if (offset < 64 || offset > rawLength - 26 || offset > Int32.MaxValue - 26)
            throw new InvalidDataException("The mapped PE header offset is invalid.");
        return offset;
    }

    private byte[] ReadMapped(int offset, int length)
    {
        if (view == IntPtr.Zero || offset < 0 || length <= 0)
            throw new InvalidOperationException("No readable image mapping is held.");
        byte[] bytes = new byte[length];
        UIntPtr read;
        if (!ReadProcessMemory(new IntPtr(-1), IntPtr.Add(view, offset), bytes,
            new UIntPtr((uint)length), out read))
            ThrowLastError("ReadProcessMemory(mapped headers)");
        if (read.ToUInt64() != (ulong)length)
            throw new IOException("The mapped header read was incomplete.");
        return bytes;
    }

    private static ushort ReadUInt16(byte[] bytes, int offset)
    {
        return (ushort)(bytes[offset] | (bytes[offset + 1] << 8));
    }

    private static uint ReadUInt32(byte[] bytes, int offset)
    {
        return (uint)(bytes[offset] | (bytes[offset + 1] << 8) |
            (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24));
    }

    private void EnsureOpen()
    {
        if (disposed || file == IntPtr.Zero || file == InvalidHandle)
            throw new ObjectDisposedException("NativeImage161");
    }

    private static void ThrowLastError(string operation)
    {
        int error = Marshal.GetLastWin32Error();
        throw new Win32Exception(error, operation + " failed (Win32 " + error + ").");
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
                return;
            disposed = true;
            if (view != IntPtr.Zero) { UnmapViewOfFile(view); view = IntPtr.Zero; }
            if (section != IntPtr.Zero) { CloseHandle(section); section = IntPtr.Zero; }
            if (file != IntPtr.Zero && file != InvalidHandle) { CloseHandle(file); file = IntPtr.Zero; }
        }
        GC.SuppressFinalize(this);
    }

    ~NativeImage161() { Dispose(); }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string path, uint access, uint sharing,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileMappingW(IntPtr file, IntPtr security,
        uint protect, uint maximumSizeHigh, uint maximumSizeLow, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr MapViewOfFile(IntPtr section, uint access,
        uint offsetHigh, uint offsetLow, UIntPtr bytes);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnmapViewOfFile(IntPtr address);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(IntPtr handle, int kind,
        [Out] byte[] information, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileSizeEx(IntPtr handle, out long length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFilePointerEx(IntPtr handle, long distance,
        out long position, uint method);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(IntPtr handle, [Out] byte[] buffer,
        uint count, out uint read, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr address,
        [Out] byte[] buffer, UIntPtr count, out UIntPtr read);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(string source, string destination, uint flags);
}
