using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Keycloak.Authentication;

internal sealed class KeycloakJwtBearerEvents : JwtBearerEvents
{
    private const string AccessTokenQueryKey = "access_token";

    private const string LoggerCategory = "Identity.Keycloak.JwtBearer";

    private static readonly Func<MessageReceivedContext, Task> QueryStringTokenReader = ReadQueryStringTokenAsync;

    private static readonly Func<AuthenticationFailedContext, Task> AuthenticationFailedLogger = LogAuthenticationFailedAsync;

    private static readonly Func<JwtBearerChallengeContext, Task> ChallengeLogger = LogChallengeAsync;

    public KeycloakJwtBearerEvents()
    {
        OnMessageReceived = QueryStringTokenReader;
        OnAuthenticationFailed = AuthenticationFailedLogger;
        OnChallenge = ChallengeLogger;
    }

    private static Task ReadQueryStringTokenAsync(MessageReceivedContext context)
    {
        var prefixes = context.HttpContext.RequestServices.GetService<IOptions<KeycloakQueryStringTokenOptions>>()?.Value.PathPrefixes ?? [];
        var token = context.Request.Query[AccessTokenQueryKey].ToString();
        if (token.Length > 0 && prefixes.Exists(prefix => context.Request.Path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase)))
        {
            context.Token = token;
        }

        return Task.CompletedTask;
    }

    private static Task LogAuthenticationFailedAsync(AuthenticationFailedContext context)
    {
        LoggerOf(context.HttpContext.RequestServices).LogWarning(
            "jwt_authentication_failed path={Path} exceptionType={ExceptionType}",
            context.HttpContext.Request.Path.Value,
            context.Exception.GetType().FullName);
        return Task.CompletedTask;
    }

    private static Task LogChallengeAsync(JwtBearerChallengeContext context)
    {
        LoggerOf(context.HttpContext.RequestServices).LogWarning(
            "jwt_challenge_issued path={Path} error={Error} description={Description}",
            context.HttpContext.Request.Path.Value,
            context.Error,
            context.ErrorDescription);
        return Task.CompletedTask;
    }

    private static ILogger LoggerOf(IServiceProvider services) =>
        services.GetRequiredService<ILoggerFactory>().CreateLogger(LoggerCategory);
}
