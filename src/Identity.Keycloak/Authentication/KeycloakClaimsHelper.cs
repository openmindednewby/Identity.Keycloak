using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Identity.Keycloak.Authentication;

/// <summary>Maps Keycloak realm roles to role claims and derives the server URL from a realm authority.</summary>
public static class KeycloakClaimsHelper
{
    /// <summary>Adds a role claim per realm_access.roles entry of the validated principal.</summary>
    public static void MapKeycloakRoleClaims(TokenValidatedContext context)
    {
        if (context.Principal is not null)
        {
            AddRealmRoleClaims(context.Principal);
        }
    }

    /// <summary>Extracts the Keycloak server URL from a realm authority URL; null for a blank input.</summary>
    public static string? DeriveServerUrl(string? authority)
    {
        if (string.IsNullOrWhiteSpace(authority))
        {
            return null;
        }
        var idx = authority.IndexOf("/realms/", StringComparison.OrdinalIgnoreCase);
        return idx > 0 ? authority.Substring(0, idx) : authority.TrimEnd('/');
    }

    internal static void AddRealmRoleClaims(ClaimsPrincipal principal)
    {
        if (principal.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        var realmAccessClaim = principal.FindFirst("realm_access");
        if (realmAccessClaim is null)
        {
            return;
        }

        using var realmAccess = JsonDocument.Parse(realmAccessClaim.Value);
        if (!realmAccess.RootElement.TryGetProperty("roles", out var roles)
            || roles.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var role in roles.EnumerateArray())
        {
            var roleValue = role.GetString();
            if (!string.IsNullOrWhiteSpace(roleValue)
                && !identity.HasClaim(ClaimTypes.Role, roleValue))
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, roleValue));
            }
        }
    }
}
