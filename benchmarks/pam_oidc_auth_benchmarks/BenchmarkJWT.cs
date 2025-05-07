using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using pam_oidc_auth;
using System.Text;
using System.Text.Json;

namespace pam_oidc_auth_benchmarks;

[JsonExporterAttribute.FullCompressed]
[MemoryDiagnoser]
public class BenchmarkJWT
{
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
        return tokenElement.GetString();
    }

    private string token = string.Empty;

    [GlobalSetup]
    public async Task GlobalSetup()
    {
        token = await GetToken();
    }

    [Benchmark]
    public void Auth()
    {
        PamModule.ValidateJwt(token, "some-app", "someuser@company.com", "sub", "http://oidc-server-mock:8080/.well-known/openid-configuration");
    }
}
