using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Identity.Keycloak.Authentication;

/// <summary>
/// Shared helpers for mapping Keycloak JWT claims into the ASP.NET Core principal
/// and for deriving the Keycloak server URL from a full realm authority URL.
/// </summary>
/// <remarks>
/// Keycloak emits realm roles inside a JSON <c>realm_access.roles</c> claim rather
/// than as flat <see cref="ClaimTypes.Role"/> claims. <see cref="MapKeycloakRoleClaims"/>
/// flattens them so <c>[Authorize(Roles = ...)]</c> and
/// <see cref="ClaimsPrincipal.IsInRole(string)"/> work. Wire it from the JwtBearer
/// <see cref="JwtBearerEvents.OnTokenValidated"/> event.
/// </remarks>
public static class KeycloakClaimsHelper
{
    /// <summary>
    /// Flattens Keycloak's <c>realm_access.roles</c> JSON array into individual
    /// <see cref="ClaimTypes.Role"/> claims on the validated principal. No-op when
    /// the claim is absent or the principal is not a <see cref="ClaimsIdentity"/>.
    /// </summary>
    public static void MapKeycloakRoleClaims(TokenValidatedContext context)
    {
        if (context.Principal?.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        var realmAccessClaim = context.Principal.FindFirst("realm_access");
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

    /// <summary>
    /// Extracts the Keycloak base server URL from a full realm authority URL
    /// (e.g. <c>https://id/realms/foo</c> → <c>https://id</c>). Returns the trimmed
    /// authority unchanged when it carries no <c>/realms/</c> segment, or
    /// <see langword="null"/> when the input is null/whitespace.
    /// </summary>
    public static string? DeriveServerUrl(string? authority)
    {
        if (string.IsNullOrWhiteSpace(authority))
        {
            return null;
        }
        var idx = authority.IndexOf("/realms/", StringComparison.OrdinalIgnoreCase);
        return idx > 0 ? authority.Substring(0, idx) : authority.TrimEnd('/');
    }
}
