using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;

namespace pam_oidc_sharp;

public static class PamModule
{
    // PAM return codes
    private const int PAM_SUCCESS = 0;
    private const int PAM_AUTH_ERR = 1;
    private const int PAM_AUTHTOK = 6;
    private const int PAM_SERVICE_ERR = 3;
    private const int PAM_IGNORE = 5;
    private const int PAM_PERM_DENIED = 6;

    // Export pam_sm_authenticate
    [UnmanagedCallersOnly(EntryPoint = "pam_sm_authenticate", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static int Authenticate(
        IntPtr pamh,
        int flags,
        int argc,
        IntPtr argv)
    {
        // 1) Retrieve username
        if (LibPAM.pam_get_user(pamh, out IntPtr userPtr, null) != PAM_SUCCESS)
            return PAM_SERVICE_ERR;

        string user = Marshal.PtrToStringAnsi(userPtr)!;
        LibPAM.pam_syslog(pamh, LibPAM.LOG_NOTICE, "pam_sm_authenticate: starting auth for user %s", user);

        // 2) Retrieve JWT/password
        if (LibPAM.pam_get_authtok(pamh, PAM_AUTHTOK, out IntPtr tokPtr, null) != PAM_SUCCESS)
            return PAM_SERVICE_ERR;

        string token = Marshal.PtrToStringAnsi(tokPtr)!;

        // 3) Parse module arguments
        string[] args = GetArguments(argv, argc);
        var opts = ParseOptions(args);

        if (!opts.TryGetValue("discovery_url", out string? discoveryUrl))
            return PAM_SERVICE_ERR;

        if (!opts.TryGetValue("audience", out string? audience))
            return PAM_SERVICE_ERR;

        // 4) Validate JWT
        bool valid = ValidateJwt(token, audience, discoveryUrl);
        return valid ? PAM_SUCCESS : PAM_PERM_DENIED;
    }

    // Export pam_sm_setcred
    [UnmanagedCallersOnly(EntryPoint = "pam_sm_setcred", CallConvs = new[] { typeof(CallConvCdecl) })]
    public static int SetCredentials(
        IntPtr pamh,
        int flags,
        int argc,
        IntPtr argv)
        => PAM_IGNORE;

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
