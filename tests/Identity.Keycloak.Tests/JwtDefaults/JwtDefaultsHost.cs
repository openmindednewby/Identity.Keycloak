using System.Security.Claims;
using Identity.Keycloak.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Identity.Keycloak.Tests.JwtDefaults;

internal sealed class JwtDefaultsHost : IAsyncDisposable
{
    public const string SecurePath = "/secure";

    public const string RolesPath = "/roles";

    private readonly WebApplication _app;

    private JwtDefaultsHost(WebApplication app, HttpClient client, CapturingLoggerProvider logs)
    {
        _app = app;
        Client = client;
        Logs = logs;
    }

    public HttpClient Client { get; }

    public CapturingLoggerProvider Logs { get; }

    public IServiceProvider Services => _app.Services;

    public static async Task<JwtDefaultsHost> StartAsync(
        IDictionary<string, string?> settings,
        string environmentName = "Production",
        Action<IServiceCollection>? services = null,
        bool authenticationEnabled = true)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environmentName });
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Configuration.AddInMemoryCollection(settings);
        var logs = new CapturingLoggerProvider();
        builder.Logging.AddProvider(logs);
        builder.Services.AddKeycloakJwtDefaults(builder.Configuration, builder.Environment, authenticationEnabled);
        builder.Services.AddAuthorization(options => options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
        services?.Invoke(builder.Services);

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet(SecurePath, () => "secret");
        app.MapGet(RolesPath, (ClaimsPrincipal user) => user.FindAll(ClaimTypes.Role).Select(claim => claim.Value).ToArray());
        await app.StartAsync();

        var address = app.Services.GetRequiredService<IServer>().Features
            .GetRequiredFeature<IServerAddressesFeature>().Addresses.First();
        return new JwtDefaultsHost(app, new HttpClient { BaseAddress = new Uri(address) }, logs);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync();
    }
}
