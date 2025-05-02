using Shouldly;
using System.Text;
using System.Text.Json;

namespace pam_oidc_auth_tests;

public class Tests
{
    private async Task<string> GetToken(string clientid = "client-credentials-mock-client", string clientSecret = "client-credentials-mock-client-secret", string scope = "some-app-scope-1")
    {
        using var client = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Post, "http://oidc-server-mock:8080/connect/token")
        {
            Content = new StringContent(
                $"grant_type=client_credentials&client_id={clientid}&client_secret={clientSecret}&scope={scope}",
                Encoding.UTF8,
                "application/x-www-form-urlencoded")
        };

        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var responseContent = await response.Content.ReadAsStringAsync();
        JsonDocument json = JsonDocument.Parse(responseContent);
        json.RootElement.TryGetProperty("access_token", out JsonElement tokenElement);
        return tokenElement.GetString();
    }

    [Fact]
    public async Task Valid()
    {
        var token = await GetToken();
        pam_oidc_auth.PamModule.ValidateJwt(token, "some-app", "someuser@company.com", "preferred_username", "http://oidc-server-mock:8080/.well-known/openid-configuration").ShouldBeTrue();
    }

    [Fact]
    public void BadToken()
    {
        pam_oidc_auth.PamModule.ValidateJwt("fake", "some-app", "someuser@company.com", "preferred_username", "http://oidc-server-mock:8080/.well-known/openid-configuration").ShouldBeFalse();
    }

    [Fact]
    public async Task BadUserName()
    {
        var token = await GetToken();
        pam_oidc_auth.PamModule.ValidateJwt(token, "some-app", "someuser2@company.com", "preferred_username", "http://oidc-server-mock:8080/.well-known/openid-configuration").ShouldBeFalse();
    }

    [Fact]
    public async Task BadAudience()
    {
        var token = await GetToken();
        pam_oidc_auth.PamModule.ValidateJwt(token, "some-app2", "someuser@company.com", "preferred_username", "http://oidc-server-mock:8080/.well-known/openid-configuration").ShouldBeFalse();
    }
}
