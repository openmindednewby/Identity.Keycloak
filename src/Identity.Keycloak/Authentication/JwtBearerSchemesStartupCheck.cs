using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Identity.Keycloak.Authentication;

internal sealed class JwtBearerSchemesStartupCheck : IHostedLifecycleService
{
    private readonly IAuthenticationSchemeProvider _schemes;

    private readonly IOptionsMonitor<JwtBearerOptions> _options;

    public JwtBearerSchemesStartupCheck(IAuthenticationSchemeProvider schemes, IOptionsMonitor<JwtBearerOptions> options)
    {
        _schemes = schemes;
        _options = options;
    }

    public async Task StartingAsync(CancellationToken cancellationToken)
    {
        var schemes = await _schemes.GetAllSchemesAsync();
        foreach (var scheme in schemes.Where(scheme => typeof(JwtBearerHandler).IsAssignableFrom(scheme.HandlerType)))
        {
            _options.Get(scheme.Name);
        }
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
