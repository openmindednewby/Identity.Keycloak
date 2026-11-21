using System.Security.Claims;
using Security.Claims.Claims;

namespace Identity.Keycloak.Authentication;

internal static class PrivilegedRoleFilter
{
    internal static void AddRealmRoleClaims(ClaimsIdentity identity, KeycloakRoleMappingOptions options)
    {
        var realm = RealmExtensions.ExtractRealmFromIssuer(identity.FindFirst("iss")?.Value);
        var fromPlatformRealm = realm is not null && string.Equals(realm, options.PlatformRealm, StringComparison.OrdinalIgnoreCase);
        if (!fromPlatformRealm)
        {
            foreach (var claim in identity.FindAll(identity.RoleClaimType).Where(claim => IsPrivileged(claim.Value, options)).ToList())
            {
                identity.RemoveClaim(claim);
            }
        }

        var roles = KeycloakClaimsHelper.RealmRolesOf(identity).Where(role => fromPlatformRealm || !IsPrivileged(role, options));
        foreach (var role in roles.Where(role => !identity.HasClaim(ClaimTypes.Role, role)))
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, role));
        }
    }

    private static bool IsPrivileged(string role, KeycloakRoleMappingOptions options) =>
        options.PrivilegedRoles.Contains(role, StringComparer.OrdinalIgnoreCase);
}
