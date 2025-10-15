using Shouldly;
using System.Text;
using System.Text.Json;
using Ductus.FluentDocker.Builders;
using Ductus.FluentDocker.Model.Common;
using Ductus.FluentDocker.Extensions;
using Ductus.FluentDocker.Services.Extensions;

namespace pam_oidc_auth_tests;

/// <summary>
/// Note, tests require a hosts file entry 127.0.0.1 oidc-server-mock
/// </summary>
public class Tests : IClassFixture<TestFixture>
{
    private readonly TestFixture fixture;

    public Tests(TestFixture fixture)
    {
        this.fixture = fixture;
    }

    private static async Task<string> GetToken(string clientid = "client-credentials-mock-client", string clientSecret = "client-credentials-mock-client-secret", string scope = "some-app-scope-1")
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
        return tokenElement.GetString() ?? throw new Exception("Unable to get token");
    }

    [Fact]
    public async Task Valid()
    {
        var token = await GetToken();
        pam_oidc_auth.PamModule.ValidateJwt(token, "some-app", "someuser@company.com", "sub", "http://oidc-server-mock:8080/.well-known/openid-configuration").ShouldBeTrue();
    }

    [Fact]
    public void BadToken()
    {
        pam_oidc_auth.PamModule.ValidateJwt("fake", "some-app", "someuser@company.com", "sub", "http://oidc-server-mock:8080/.well-known/openid-configuration").ShouldBeFalse();
    }

    [Fact]
    public async Task BadUserName()
    {
        var token = await GetToken();
        pam_oidc_auth.PamModule.ValidateJwt(token, "some-app", "someuser2@company.com", "sub", "http://oidc-server-mock:8080/.well-known/openid-configuration").ShouldBeFalse();
    }

    [Fact]
    public async Task BadAudience()
    {
        var token = await GetToken();
        pam_oidc_auth.PamModule.ValidateJwt(token, "some-app2", "someuser@company.com", "sub", "http://oidc-server-mock:8080/.well-known/openid-configuration").ShouldBeFalse();
    }

    [Theory]
    [InlineData("ubuntu")]
    [InlineData("debian")]
    [InlineData("postgres")]
    public async Task EndToEnd(string name)
    {
        var token = await GetToken();

        var path = Path.GetDirectoryName(GetType().Assembly.Location);
        var filePath = Path.Combine(path!, "Dockerfile." + name);

        new Builder()
          .DefineImage("testing.loc/" + name)
          .FromFile(filePath)
          .WorkingFolder(new TemplateString(path, true))
          .Build()
          .Start();

        var container = new Builder()
           .UseContainer()
           .UseImage("testing.loc/" + name)
           .WithEnvironment("TEST_TOKEN=" + token)
           .WithEnvironment("POSTGRES_PASSWORD=test123")
           .ExposePort(5432, 5432)
           .UseNetwork(fixture.GetNetwork())
           .Build()
           .Start();

        container.WaitForStopped();

        container.Logs(token: TestContext.Current.CancellationToken).Read().ShouldContain("pamtester: successfully authenticated");

        container.Dispose();
    }
}
