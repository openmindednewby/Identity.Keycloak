using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Identity.Keycloak.Authentication;

public static class KeycloakQueryStringTokenExtensions
{
    /// <summary>Accepts an access_token query-string token on requests under the given path prefixes, for SignalR.</summary>
    public static AuthenticationBuilder AllowQueryStringToken(this AuthenticationBuilder authentication, params string[] pathPrefixes)
    {
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(pathPrefixes);
        if (pathPrefixes.Length == 0 || Array.Exists(pathPrefixes, prefix => string.IsNullOrWhiteSpace(prefix) || !prefix.StartsWith('/') || prefix.Trim('/').Length == 0))
        {
            throw new ArgumentException("Each path prefix must start with a slash and name at least one segment.", nameof(pathPrefixes));
        }

        authentication.Services.Configure<KeycloakQueryStringTokenOptions>(options =>
            options.PathPrefixes.AddRange(pathPrefixes.Select(prefix => new PathString(prefix))));
        return authentication;
    }
}
