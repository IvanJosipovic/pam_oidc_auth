using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;

namespace pam_oidc_auth;

public class PamModule
{
    static async Task Main(string[] args)
    {
        // PAM_RHOST, PAM_RUSER, PAM_SERVICE, PAM_TTY, PAM_USER and PAM_TYPE

        //var PARM_TYPE = Environment.GetEnvironmentVariable("PAM_TYPE") ?? string.Empty;
        var PAM_USER = Environment.GetEnvironmentVariable("PAM_USER") ?? string.Empty;
        Console.WriteLine("PAM_USER: " + PAM_USER);
        //if (PAM_TYPE == PamItemTypes.PAM_AUTHTOK_TYPE)
        //{

        //}

        string? token = Console.ReadLine();
        string? token2 = Console.ReadLine();

        Console.WriteLine("Token: " + token);
        Console.WriteLine("Token2: " + token2);


        var result = await ValidateJwt(token!, "some-app", "someuser@company.com", "sub", "http://oidc-server-mock:8080/.well-known/openid-configuration");

        if (result)
        {
            Environment.Exit(0);
            return;
        }

        Environment.Exit(1);
        return;
    }

    // JWT validation using OIDC configuration
    public static async Task<bool> ValidateJwt(string token, string audience, string username, string usernameClaim, string discoveryUrl)
    {
        try
        {
            var http = new HttpDocumentRetriever { RequireHttps = discoveryUrl.StartsWith("https://") };

            var config = await OpenIdConnectConfigurationRetriever.GetAsync(discoveryUrl, http, CancellationToken.None).ConfigureAwait(false);

            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = config.SigningKeys,
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
}
