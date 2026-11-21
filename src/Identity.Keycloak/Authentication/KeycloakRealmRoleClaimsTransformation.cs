using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Security.Claims.Claims;

namespace Identity.Keycloak.Authentication;

/// <summary>Adds Keycloak realm roles as role claims to the identity issued by the Keycloak JWT scheme.</summary>
public sealed class KeycloakRealmRoleClaimsTransformation : IClaimsTransformation
{
    private readonly KeycloakRoleMappingOptions _options;

    public KeycloakRealmRoleClaimsTransformation(IOptions<KeycloakRoleMappingOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
    }

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var identity = principal.Identities.FirstOrDefault(candidate =>
            string.Equals(candidate.AuthenticationType, KeycloakJwtDefaults.IdentityAuthenticationType, StringComparison.Ordinal));
        var realm = RealmExtensions.ExtractRealmFromIssuer(identity?.FindFirst("iss")?.Value);
        if (identity is not null && realm is not null && _options.AllowedRealms.Contains(realm, StringComparer.OrdinalIgnoreCase))
        {
            PrivilegedRoleFilter.AddRealmRoleClaims(identity, _options);
        }

        return Task.FromResult(principal);
    }
}
