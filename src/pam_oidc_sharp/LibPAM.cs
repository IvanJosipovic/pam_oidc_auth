using System.Runtime.InteropServices;

namespace pam_oidc_sharp;

internal partial class LibPAM
{
    [LibraryImport("libpam.so.0", EntryPoint = "pam_get_authtok", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int pam_get_authtok(
        IntPtr pamh,            // pam_handle_t*
        int item,               // which token to retrieve (e.g. PAM_AUTHTOK)
        out IntPtr authtok,     // const char** → out IntPtr (points to C-string)
        string? prompt          // const char* prompt
    );

    [LibraryImport("libpam.so.0", EntryPoint = "pam_get_user", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int pam_get_user(
        IntPtr pamh,            // pam_handle_t*
        out IntPtr user,        // const char** → out IntPtr (points to C-string)
        string? prompt          // const char* prompt
    );


    internal const int LOG_NOTICE = 5;  // from <syslog.h>

    [DllImport("libpam.so.0", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void pam_syslog(
        IntPtr pamh,
        int priority,
        [MarshalAs(UnmanagedType.LPStr)] string fmt,
        string arg1
    );
}
