using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Identity.Keycloak.Authentication;

internal sealed class KeycloakRealmRoleClaimsTransformation : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        KeycloakClaimsHelper.AddRealmRoleClaims(principal);
        return Task.FromResult(principal);
    }
}
