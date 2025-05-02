using Ductus.FluentDocker.Builders;
using Ductus.FluentDocker.Services;

namespace pam_oidc_auth_tests;

public class TestFixture : IDisposable
{
    public ICompositeService compositeService;

    public TestFixture()
    {
        var file = Path.Combine(Directory.GetCurrentDirectory(), "docker-compose.yaml");

        compositeService = new Builder()
            .UseContainer()
            .UseCompose()
            .FromFile(file)
            .RemoveOrphans()
            .AssumeComposeVersion(Ductus.FluentDocker.Model.Compose.ComposeVersion.V2)
            .ForceRecreate()
            .WaitForHttp("oidc-server-mock", "http://oidc-server-mock:8080/.well-known/openid-configuration", continuation: (resp, cnt) => resp.Body.Contains("jwks_uri") ? 0 : 500)
            .Build()
            .Start();

        // Unsure why this is needed, but it is. The container is not ready until this delay is over.
        Task.Delay(1000).Wait();
    }

    public INetworkService GetNetwork()
    {
        return compositeService.Containers.First(x => x.Name == "server").GetNetworks()[0];
    }

    public void Dispose()
    {
        compositeService.Dispose();
    }
}
