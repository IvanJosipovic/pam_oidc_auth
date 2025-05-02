using System.Runtime.InteropServices;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;

namespace pam_oidc_auth;

public static class PamModule
{
    [UnmanagedCallersOnly(EntryPoint = "pam_sm_authenticate")]
    public static int pam_sm_authenticate(IntPtr pamh, int flags, int argc, IntPtr argv)
    {
        // 1) Retrieve username
        if (Libpam.pam_get_user(pamh, out IntPtr userPtr) != (int)PamStatus.PAM_SUCCESS)
            return (int)PamStatus.PAM_CRED_INSUFFICIENT;

        string user = Marshal.PtrToStringAnsi(userPtr)!;
        Libpam.pam_syslog(pamh, (int)SyslogPriority.LOG_NOTICE, "starting auth for user %s", user);

        // 2) Retrieve JWT/password
        if (Libpam.pam_get_authtok(pamh, (int)PamItemTypes.PAM_AUTHTOK, out IntPtr tokPtr) != (int)PamStatus.PAM_SUCCESS)
            return (int)PamStatus.PAM_CRED_INSUFFICIENT;

        string token = Marshal.PtrToStringAnsi(tokPtr)!;

        // 3) Parse module arguments
        string[] args = GetArguments(argv, argc);
        var opts = ParseOptions(args);

        if (!opts.TryGetValue("discovery_url", out string? discoveryUrl))
            return (int)PamStatus.PAM_AUTHINFO_UNAVAIL;

        if (!opts.TryGetValue("audience", out string? audience))
            return (int)PamStatus.PAM_AUTHINFO_UNAVAIL;

        if (!opts.TryGetValue("username_claim", out string? usernameClaim))
            usernameClaim = "preferred_username";

        // 4) Validate JWT
        bool valid = ValidateJwt(token, audience, user, usernameClaim, discoveryUrl);
        return valid ? (int)PamStatus.PAM_SUCCESS : (int)PamStatus.PAM_AUTH_ERR;
    }

    [UnmanagedCallersOnly(EntryPoint = "pam_sm_setcred")]
    public static int pam_sm_setcred(IntPtr pamh, int flags, int argc, IntPtr argv) => (int)PamStatus.PAM_SUCCESS;

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
    public static bool ValidateJwt(string token, string audience, string username, string usernameClaim, string discoveryUrl)
    {
        try
        {
            var http = new HttpDocumentRetriever { RequireHttps = discoveryUrl.StartsWith("https://") };

            var config = OpenIdConnectConfigurationRetriever.GetAsync(discoveryUrl, http, CancellationToken.None)
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();

            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = config.SigningKeys,
                ValidateIssuerSigningKey = true,
                ValidAudience = audience,
                ValidIssuer = config.Issuer,
            };

            var principal = new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out _);

            var nameClaim = principal.FindFirst(usernameClaim);

            return nameClaim is not null && string.Equals(nameClaim.Value, username, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
