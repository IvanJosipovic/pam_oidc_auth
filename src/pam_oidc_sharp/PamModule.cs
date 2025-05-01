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
    [UnmanagedCallersOnly(EntryPoint = "pam_sm_authenticate")]
    public static int Authenticate(
        IntPtr pamh,
        int flags,
        int argc,
        IntPtr argv)
    {
        // 1) Retrieve username
        if (LibPAM.pam_get_user(pamh, out IntPtr userPtr) != (int)PamStatus.PAM_SUCCESS)
            return (int)PamStatus.PAM_AUTHINFO_UNAVAIL;

        string user = Marshal.PtrToStringAnsi(userPtr)!;
        LibPAM.pam_syslog(pamh, (int)SyslogPriority.LOG_NOTICE, "starting auth for user %s", user);

        // 2) Retrieve JWT/password
        if (LibPAM.pam_get_authtok(pamh, (int)PamItemTypes.PAM_AUTHTOK, out IntPtr tokPtr) != (int)PamStatus.PAM_SUCCESS)
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
    [UnmanagedCallersOnly(EntryPoint = "pam_sm_setcred")]
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
        try
        {
            var http = new HttpDocumentRetriever { RequireHttps = discoveryUrl.StartsWith("https://") };

            var config = OpenIdConnectConfigurationRetriever.GetAsync(discoveryUrl, http, CancellationToken.None).GetAwaiter().GetResult();

            config.

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = config.SigningKeys,
                ValidIssuer = config.Issuer,
                ValidAudience = audience,
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
