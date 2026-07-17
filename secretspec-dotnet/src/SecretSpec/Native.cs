using System.Reflection;
using System.Runtime.InteropServices;

namespace Cachix.SecretSpec;

internal static class Native
{
    private const string LibraryName = "secretspec_ffi";

    static Native()
    {
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, ResolveLibrary);
    }

    internal static string Resolve(string requestJson)
    {
        IntPtr response = IntPtr.Zero;
        try
        {
            response = secretspec_resolve(requestJson);
            if (response == IntPtr.Zero)
                throw new SecretSpecException("ffi", "secretspec_resolve returned null");
            return Marshal.PtrToStringUTF8(response)
                ?? throw new SecretSpecException("ffi", "secretspec_resolve returned invalid UTF-8");
        }
        catch (Exception error) when (
            error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            throw new SecretSpecException("load", error.Message, error);
        }
        finally
        {
            if (response != IntPtr.Zero)
                secretspec_free(response);
        }
    }

    internal static string AbiVersion()
    {
        try
        {
            var pointer = secretspec_abi_version();
            return Marshal.PtrToStringUTF8(pointer)
                ?? throw new SecretSpecException("ffi", "secretspec_abi_version returned null");
        }
        catch (Exception error) when (
            error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            throw new SecretSpecException("load", error.Message, error);
        }
    }

    private static IntPtr ResolveLibrary(
        string libraryName,
        Assembly assembly,
        DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName)
            return IntPtr.Zero;

        var explicitPath = Environment.GetEnvironmentVariable("SECRETSPEC_FFI_LIB");
        if (!string.IsNullOrWhiteSpace(explicitPath))
            return NativeLibrary.Load(explicitPath);

        // Prefer the runtime-specific NuGet asset (or a library on the platform's
        // normal loader search path); the source-checkout scan below is a
        // development fallback that must not stat ancestor directories, or shadow
        // the packaged asset, in a deployed application.
        if (NativeLibrary.TryLoad(libraryName, assembly, searchPath, out var packaged))
            return packaged;

        var fileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "secretspec_ffi.dll"
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? "libsecretspec_ffi.dylib"
                : "libsecretspec_ffi.so";

        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
            {
                // Within the nearest ancestor target/, pick the most recently
                // built library rather than always preferring one profile: a
                // stale build must not shadow the one the developer just
                // produced. Mirrors the Go and PHP SDK discovery rule.
                string? newest = null;
                var newestTime = DateTime.MinValue;
                foreach (var profile in new[] { "release", "debug" })
                {
                    var candidate = new FileInfo(
                        Path.Combine(directory.FullName, "target", profile, fileName));
                    if (candidate.Exists && candidate.LastWriteTimeUtc >= newestTime)
                    {
                        newest = candidate.FullName;
                        newestTime = candidate.LastWriteTimeUtc;
                    }
                }
                if (newest is not null)
                    return NativeLibrary.Load(newest);
            }
        }

        return IntPtr.Zero;
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr secretspec_resolve(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void secretspec_free(IntPtr pointer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr secretspec_abi_version();
}
