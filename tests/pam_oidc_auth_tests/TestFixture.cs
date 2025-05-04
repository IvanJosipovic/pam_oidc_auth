using Ductus.FluentDocker.Builders;
using Ductus.FluentDocker.Model.Common;
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
            .WaitForHttp("server", "http://oidc-server-mock:8080/.well-known/openid-configuration", continuation: (resp, cnt) => resp.Body.Contains("jwks_uri") ? 0 : 500)
            .Build()
            .Start();


        var dir = Directory.GetCurrentDirectory();

        var path = Path.Combine("..", "..", "..", "..", "..", "src", "pam_oidc_auth");

        var name = "pam_oidc_auth";

        new Builder()
          .DefineImage("testing.loc/" + name)
          .FromFile(Path.Combine(path, "Dockerfile"))
          .WorkingFolder(new TemplateString(path, true))
          .Build()
          .Start();

        using (new Builder()
            .UseContainer()
            .UseImage("testing.loc/" + name)
            .Build()
            .Start()
            .CopyFrom("/app/publish/pam_oidc_auth.so", Path.Combine(path, "pam_oidc_auth.so"))) { }
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
