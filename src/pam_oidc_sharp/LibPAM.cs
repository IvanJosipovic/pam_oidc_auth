using System.Runtime.InteropServices;

namespace pam_oidc_sharp;

internal partial class Libpam
{
    /// <summary>
    /// Get authentication token
    /// </summary>
    /// <param name="pamh">pam_handle_t*</param>
    /// <param name="item">which token to retrieve (e.g. PAM_AUTHTOK)</param>
    /// <param name="authtok">const char** → out IntPtr (points to C-string)</param>
    /// <param name="prompt">const char* prompt</param>
    /// <returns></returns>
    [LibraryImport("libpam.so.0", EntryPoint = "pam_get_authtok", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int pam_get_authtok(
        IntPtr pamh,
        int item,
        out IntPtr authtok,
        string? prompt = null
    );

    /// <summary>
    /// Get user name
    /// </summary>
    /// <param name="pamh">pam_handle_t*</param>
    /// <param name="user">const char** → out IntPtr (points to C-string)</param>
    /// <param name="prompt">const char* prompt</param>
    /// <returns></returns>
    [LibraryImport("libpam.so.0", EntryPoint = "pam_get_user", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int pam_get_user(
        IntPtr pamh,
        out IntPtr user,
        string? prompt = null
    );

    /// <summary>
    /// Send messages to the system logger
    /// </summary>
    /// <param name="pamh">pam_handle_t*</param>
    /// <param name="priority">log priority</param>
    /// <param name="fmt">log string</param>
    /// <param name="arg1">first argument</param>
    [LibraryImport("libpam.so.0", EntryPoint = "pam_syslog", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial void pam_syslog(
        IntPtr pamh,
        int priority,
        [MarshalAs(UnmanagedType.LPStr)] string fmt,
        string? arg1 = null
    );
}
