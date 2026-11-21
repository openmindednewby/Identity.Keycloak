using Microsoft.AspNetCore.Http;

namespace Identity.Keycloak.Authentication;

internal sealed class KeycloakQueryStringTokenOptions
{
    internal List<PathString> PathPrefixes { get; } = [];
}
