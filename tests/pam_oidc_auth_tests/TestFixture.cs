using Ductus.FluentDocker.Builders;
using Ductus.FluentDocker.Services;
using Ductus.FluentDocker.Services.Extensions;

namespace pam_oidc_auth_tests;

public class TestFixture : IDisposable
{
    public ICompositeService compositeService;

    public TestFixture()
    {
        compositeService = new Builder()
            .UseContainer()
            .UseCompose()
            .FromFile("docker-compose.yaml")
            .RemoveOrphans()
            .AssumeComposeVersion(Ductus.FluentDocker.Model.Compose.ComposeVersion.V2)
            .ForceRecreate()
            //.WaitForPort("oidc-server-mock", "8080/tcp")
            .WaitForHttp("server", "http://oidc-server-mock:8080/.well-known/openid-configuration", continuation: (resp, cnt) => resp.Body.Contains("jwks_uri") ? 0 : 500)
            .Build()
            .Start();

        var cont = compositeService.Containers.First(x => x.Name == "server");
        //cont.WaitForPort("8080/tcp");
        //cont.WaitForHttp("http://oidc-server-mock:8080/.well-known/openid-configuration", continuation: (resp, cnt) => resp.Body.Contains("jwks_uri") ? 0 : 500);

        // Unsure why this is needed, but it is. The container is not ready until this delay is over.
        //Task.Delay(10000).Wait();
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
