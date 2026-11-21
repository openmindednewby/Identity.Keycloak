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
        if (context.Principal?.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        foreach (var role in RealmRolesOf(identity).Where(role => !identity.HasClaim(ClaimTypes.Role, role)))
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, role));
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

    internal static IReadOnlyList<string> RealmRolesOf(ClaimsIdentity identity)
    {
        var realmAccessClaim = identity.FindFirst("realm_access");
        if (realmAccessClaim is null)
        {
            return [];
        }

        try
        {
            using var realmAccess = JsonDocument.Parse(realmAccessClaim.Value);
            return realmAccess.RootElement.ValueKind == JsonValueKind.Object
                && realmAccess.RootElement.TryGetProperty("roles", out var roles)
                && roles.ValueKind == JsonValueKind.Array
                ? roles.EnumerateArray()
                    .Where(role => role.ValueKind == JsonValueKind.String)
                    .Select(role => role.GetString()!)
                    .Where(role => !string.IsNullOrWhiteSpace(role))
                    .ToList()
                : [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
