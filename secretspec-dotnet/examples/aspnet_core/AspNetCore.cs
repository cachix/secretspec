using Cachix.SecretSpec;

using var secrets = SecretSpec.Builder()
    .WithProfile(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"))
    .WithReason("ASP.NET Core boot")
    .Load();

secrets.SetAsEnv();

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.Run();
