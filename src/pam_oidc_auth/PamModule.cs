using System.Runtime.InteropServices;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

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
            usernameClaim = "sub";

        // 4) Validate JWT
        bool valid = ValidateJwt(token, audience, user, usernameClaim, discoveryUrl);
        return valid ? (int)PamStatus.PAM_SUCCESS : (int)PamStatus.PAM_AUTH_ERR;
    }

    [UnmanagedCallersOnly(EntryPoint = "pam_sm_acct_mgmt")]
    public static int pam_sm_acct_mgmt(IntPtr pamh, int flags, int argc, IntPtr argv) => (int)PamStatus.PAM_SUCCESS;

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
            var disc = HttpGet(discoveryUrl);
            var config = new OpenIdConnectConfiguration(disc);

            var jwkeys = HttpGet(config.JwksUri);
            var keys = JsonWebKeySet.Create(jwkeys);

            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = keys.GetSigningKeys(),
                ValidateIssuerSigningKey = true,
                ValidAudience = audience,
                ValidIssuer = config.Issuer,
            };

            new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;

            var nameClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == usernameClaim);

            return nameClaim is not null && string.Equals(nameClaim.Value, username, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static string HttpGet(string url)
    {
        Uri uri = new(url);
        using var client = new TcpClient();
        client.Connect(uri.Host, uri.Port);

        Stream stream = client.GetStream();

        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            var ssl = new SslStream(stream, false);
            ssl.AuthenticateAsClient(uri.Host);
            stream = ssl;
        }

        var reqBytes = Encoding.ASCII.GetBytes($"GET {uri.AbsolutePath} HTTP/1.1\r\nHost: {uri.Host}:{uri.Port}\r\nConnection: close\r\n\r\n");
        stream.Write(reqBytes);
        stream.Flush();

        using var reader = new StreamReader(stream, Encoding.ASCII);

        // Read and parse headers
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? statusLine = reader.ReadLine(); // HTTP/1.1 200 OK
        string? line;

        while (!string.IsNullOrEmpty(line = reader.ReadLine()))
        {
            int colonIndex = line.IndexOf(':');
            if (colonIndex > 0)
            {
                var name = line.Substring(0, colonIndex).Trim();
                var value = line.Substring(colonIndex + 1).Trim();
                headers[name] = value;
            }
        }

        // Decide how to read the body
        if (headers.TryGetValue("Transfer-Encoding", out var encoding) && encoding.Equals("chunked", StringComparison.OrdinalIgnoreCase))
        {
            return ReadChunkedBody(reader);
        }
        else
        {
            return reader.ReadToEnd(); // content-length or connection: close
        }
    }

    public static string ReadChunkedBody(StreamReader reader)
    {
        var result = new StringBuilder();

        while (true)
        {
            // Read the chunk size (in hex)
            var sizeLine = reader.ReadLine();
            if (sizeLine == null)
                throw new IOException("Unexpected end of stream while reading chunk size");

            // Parse chunk size
            if (!int.TryParse(sizeLine, System.Globalization.NumberStyles.HexNumber, null, out int chunkSize))
                throw new IOException($"Invalid chunk size: '{sizeLine}'");

            if (chunkSize == 0)
            {
                // Read final empty line after 0-size chunk
                reader.ReadLine();
                break;
            }

            // Read exactly chunkSize characters
            char[] buffer = new char[chunkSize];
            int read = 0;
            while (read < chunkSize)
            {
                int r = reader.Read(buffer, read, chunkSize - read);
                if (r == 0) throw new IOException("Unexpected end of stream while reading chunk data");
                read += r;
            }

            result.Append(buffer);

            // Read and discard the trailing \r\n after each chunk
            var trailing = reader.ReadLine();
            if (trailing == null)
                throw new IOException("Unexpected end of stream after chunk");
        }

        return result.ToString();
    }
}
