using Shouldly;
using System.Text;
using System.Text.Json;
using Ductus.FluentDocker.Builders;
using Ductus.FluentDocker.Services;
using Ductus.FluentDocker.Model.Common;
using Ductus.FluentDocker.Extensions;
using Ductus.FluentDocker.Services.Extensions;

namespace pam_oidc_auth_tests;

/// <summary>
/// Note, tests require a hosts file entry oidc-server-mock 127.0.0.1
/// </summary>
public class Tests : IClassFixture<TestFixture>
{
    TestFixture fixture;

    public Tests(TestFixture fixture)
    {
        this.fixture = fixture;
    }

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

    [Fact]
    public async Task EndToEndUbuntu()
    {
        var token = await GetToken();

        // Build ubuntu image
        new Builder()
          .DefineImage("testing.loc/ubuntu")
          .FromFile("Dockerfile.ubuntu")
          .Build()
          .Start();

        var container = new Builder()
           .UseContainer()
           .UseImage("testing.loc/ubuntu")
           .WithEnvironment("TEST_TOKEN=" + token)
           .UseNetwork(fixture.GetNetwork())
           .Build()
           .Start();

        container.WaitForStopped();

        container.Logs().Read().ShouldContain("pamtester: successfully authenticated");

        container.Dispose();
    }
}
