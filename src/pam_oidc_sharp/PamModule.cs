using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;

namespace pam_oidc_sharp;

public static class PamModule
{
    // Export pam_sm_authenticate
    [UnmanagedCallersOnly(EntryPoint = "pam_sm_authenticate", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static int Authenticate(
        IntPtr pamh,
        int flags,
        int argc,
        IntPtr argv)
    {
        // 1) Retrieve username
        if (LibPAM.pam_get_user(pamh, out IntPtr userPtr, null) != (int)PamStatus.PAM_SUCCESS)
            return (int)PamStatus.PAM_AUTHINFO_UNAVAIL;

        string user = Marshal.PtrToStringAnsi(userPtr)!;
        LibPAM.pam_syslog(pamh, LibPAM.LOG_NOTICE, "pam_sm_authenticate: starting auth for user %s", user);

        // 2) Retrieve JWT/password
        if (LibPAM.pam_get_authtok(pamh, (int)PamItemTypes.PAM_AUTHTOK, out IntPtr tokPtr, null) != (int)PamStatus.PAM_SUCCESS)
            return (int)PamStatus.PAM_AUTHINFO_UNAVAIL;

        string token = Marshal.PtrToStringAnsi(tokPtr)!;

        // 3) Parse module arguments
        string[] args = GetArguments(argv, argc);
        var opts = ParseOptions(args);

        if (!opts.TryGetValue("discovery_url", out string? discoveryUrl))
            return (int)PamStatus.PAM_AUTHINFO_UNAVAIL;

        if (!opts.TryGetValue("audience", out string? audience))
            return (int)PamStatus.PAM_AUTHINFO_UNAVAIL;

        // 4) Validate JWT
        bool valid = ValidateJwt(token, audience, discoveryUrl);
        return valid ? (int)PamStatus.PAM_SUCCESS : (int)PamStatus.PAM_PERM_DENIED;
    }

    // Export pam_sm_setcred
    [UnmanagedCallersOnly(EntryPoint = "pam_sm_setcred", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static int SetCredentials(
        IntPtr pamh,
        int flags,
        int argc,
        IntPtr argv)
        => (int)PamStatus.PAM_IGNORE;

    // Helper: read argv into string[]
    private static string[] GetArguments(IntPtr argv, int argc)
    {
        var result = new string[argc];
        for (int i = 0; i < argc; i++)
        {
            IntPtr ptr = Marshal.ReadIntPtr(argv, i * IntPtr.Size);
            result[i] = Marshal.PtrToStringAnsi(ptr)!;
        }
        return result;
    }

    // Helper: parse key=value args
    private static Dictionary<string, string> ParseOptions(string[] args)
    {
        var opts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string arg in args)
        {
            var parts = arg.Split('=', 2);
            var key = parts[0].Trim();
            var val = parts.Length > 1 ? parts[1].Trim() : string.Empty;
            opts[key] = val;
        }
        return opts;
    }

    // JWT validation using OIDC configuration
    private static bool ValidateJwt(string token, string audience, string discoveryUrl)
    {
        // Load OIDC configuration via library
        var http = new HttpDocumentRetriever { RequireHttps = discoveryUrl.StartsWith("https://") };
        var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(discoveryUrl, new OpenIdConnectConfigurationRetriever(), http);

        OpenIdConnectConfiguration config;

        try
        {
            config = configManager.GetConfigurationAsync().GetAwaiter().GetResult();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = config.SigningKeys,
                ValidIssuer = config.Issuer,
                ValidAudience = audience,
                ClockSkew = TimeSpan.FromSeconds(30)
            };

            new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out _);

            return true;
        }
        catch
        {
            return false;
        }
    }
}

/// <summary>
/// The PAM return values.
/// </summary>
public enum PamStatus
{
    /// <summary>
    /// Successful function return.
    /// </summary>
    PAM_SUCCESS = 0,

    /// <summary>
    /// dlopen() failure when dynamically
    /// loading a service module.
    /// </summary>
    PAM_OPEN_ERR = 1,

    /// <summary>
    /// Symbol not found.
    /// </summary>
    PAM_SYMBOL_ERR = 2,

    /// <summary>
    /// Error in service module.
    /// </summary>
    PAM_SERVICE_ERR = 3,

    /// <summary>
    /// System error.
    /// </summary>
    PAM_SYSTEM_ERR = 4,

    /// <summary>
    /// Memory buffer error.
    /// </summary>
    PAM_BUF_ERR = 5,

    /// <summary>
    /// Permission denied.
    /// </summary>
    PAM_PERM_DENIED = 6,

    /// <summary>
    /// Authentication failure.
    /// </summary>
    PAM_AUTH_ERR = 7,

    /// <summary>
    /// Can not access authentication data
    /// due to insufficient credentials.
    /// </summary>
    PAM_CRED_INSUFFICIENT = 8,

    /// <summary>
    /// Underlying authentication service
    /// can not retrieve authentication
    /// information.
    /// </summary>
    PAM_AUTHINFO_UNAVAIL = 9,

    /// <summary>
    /// User not known to the underlying authentication module.
    /// </summary>
    PAM_USER_UNKNOWN = 10,

    /// <summary>
    /// An authentication service has
    /// maintained a retry count which has
    /// been reached.  No further retries
    /// should be attempted.
    /// </summary>
    PAM_MAXTRIES = 11,

    /// <summary>
    /// New authentication token required.
    /// This is normally returned if the
    /// machine security policies require
    /// that the password should be changed
    /// because the password is NULL or it
    /// has aged.
    /// </summary>
    PAM_NEW_AUTHTOK_REQD = 12,

    /// <summary>
    /// User account has expired.
    /// </summary>
    PAM_ACCT_EXPIRED = 13,

    /// <summary>
    /// Can not make/remove an entry for
    /// the specified session.
    /// </summary>
    PAM_SESSION_ERR = 14,

    /// <summary>
    /// Underlying authentication service
    /// can not retrieve user credentials
    /// unavailable.
    /// </summary>
    PAM_CRED_UNAVAIL = 15,

    /// <summary>
    /// User credentials expired
    /// </summary>
    PAM_CRED_EXPIRED = 16,

    /// <summary>
    /// Failure setting user credentials.
    /// </summary>
    PAM_CRED_ERR = 17,

    /// <summary>
    /// No module specific data is present.
    /// </summary>
    PAM_NO_MODULE_DATA = 18,

    /// <summary>
    /// Conversation error.
    /// </summary>
    PAM_CONV_ERR = 19,

    /// <summary>
    /// Authentication token manipulation error.
    /// </summary>
    PAM_AUTHTOK_ERR = 20,

    /// <summary>
    /// Authentication information cannot be recovered.
    /// </summary>
    PAM_AUTHTOK_RECOVERY_ERR = 21,

    /// <summary>
    /// Authentication token lock busy.
    /// </summary>
    PAM_AUTHTOK_LOCK_BUSY = 22,

    /// <summary>
    /// Authentication token aging disabled.
    /// </summary>
    PAM_AUTHTOK_DISABLE_AGING = 23,

    /// <summary>
    /// Preliminary check by password service.
    /// </summary>
    PAM_TRY_AGAIN = 24,

    /// <summary>
    /// Ignore underlying account module
    /// regardless of whether the control
    /// flag is required, optional, or sufficient.
    /// </summary>
    PAM_IGNORE = 25,

    /// <summary>
    /// Critical error (?module fail now request).
    /// </summary>
    PAM_ABORT = 26,

    /// <summary>
    /// User's authentication token has expired.
    /// </summary>
    PAM_AUTHTOK_EXPIRED = 27,

    /// <summary>
    /// Module is not known.
    /// </summary>
    PAM_MODULE_UNKNOWN = 28,

    /// <summary>
    /// Bad item passed to pam_*_item().
    /// </summary>
    PAM_BAD_ITEM = 29,

    /// <summary>
    /// Conversation function is event driven
    /// and data is not available yet.
    /// </summary>
    PAM_CONV_AGAIN = 30,

    /// <summary>
    /// Please call this function again to
    /// complete authentication stack. Before
    /// calling again, verify that conversation
    /// is completed.
    /// </summary>
    PAM_INCOMPLETE = 31,
}

/// <summary>
/// The PAM item types.
/// </summary>
public enum PamItemTypes
{
    /// <summary>
    /// The service name (which identifies that PAM stack that the PAM functions will use to authenticate the program)
    /// </summary>
    PAM_SERVICE = 1,

    /// <summary>
    /// The username of the entity under whose identity service will be given
    /// </summary>
    PAM_USER = 2,

    /// <summary>
    /// The terminal name
    /// </summary>
    PAM_TTY = 3,

    /// <summary>
    /// The requesting hostname
    /// </summary>
    PAM_RHOST = 4,

    /// <summary>
    /// The pam_conv structure
    /// </summary>
    PAM_CONV = 5,

    /// <summary>
    /// The authentication token (often a password)
    /// </summary>
    PAM_AUTHTOK = 6,

    /// <summary>
    /// The old authentication token
    /// </summary>
    PAM_OLDAUTHTOK = 7,

    /// <summary>
    /// The requesting user name
    /// </summary>
    PAM_RUSER = 8,

    /// <summary>
    /// The string used when prompting for a user's name
    /// </summary>
    PAM_USER_PROMPT = 9,

    /// <summary>
    /// A function pointer to redirect centrally managed failure delays
    /// </summary>
    PAM_FAIL_DELAY = 10,

    /// <summary>
    /// The name of the X display
    /// </summary>
    PAM_XDISPLAY = 11,

    /// <summary>
    /// A pointer to a structure containing the X authentication data
    /// required to make a connection to the display specified by PAM_XDISPLAY
    /// </summary>
    PAM_XAUTHDATA = 12,

    /// <summary>
    /// Authentication token type
    /// </summary>
    /// <remarks>
    /// The default action is for the module to use the following prompts when requesting
    /// passwords: &quot;New UNIX password: &quot; and &quot;Retype UNIX password: &quot;.
    /// The example word UNIX can be replaced with this item, by default it is empty.
    /// </remarks>
    PAM_AUTHTOK_TYPE = 13,
}