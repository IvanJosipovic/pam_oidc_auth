using BenchmarkDotNet.Running;

namespace pam_oidc_auth_benchmarks;

class Program
{
    public static void Main(string[] args)
    {
        BenchmarkRunner.Run<BenchmarkJWT>();
    }
}