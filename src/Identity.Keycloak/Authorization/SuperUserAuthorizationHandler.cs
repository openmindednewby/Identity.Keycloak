using System.Security.Claims;
using Identity.Keycloak.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.Options;
using Security.Claims.Claims;

namespace Identity.Keycloak.Authorization;

/// <summary>
/// Grants a <c>superUser</c> access to any endpoint protected by a role
/// requirement (<c>[Authorize(Roles = ...)]</c> / FastEndpoints <c>Roles(...)</c>).
/// Non-superusers are left to the default role checks.
/// </summary>
/// <remarks>
/// Independent of the cross-realm wall — it satisfies
/// <see cref="RolesAuthorizationRequirement"/>, not <see cref="RealmRequirement"/>.
/// Opt in via <c>AddRealmAuthorization(enableSuperUser: true)</c>. Uses the shared
/// <c>superUser</c> role from Security.Claims.
/// </remarks>
public sealed class SuperUserAuthorizationHandler : AuthorizationHandler<RolesAuthorizationRequirement>
{
    private readonly string _platformRealm;

    public SuperUserAuthorizationHandler(IOptions<KeycloakRoleMappingOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _platformRealm = options.Value.PlatformRealm ?? string.Empty;
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        RolesAuthorizationRequirement requirement)
    {
        if (context.User.IsSuperUser(_platformRealm))
        {
            context.Succeed(requirement);
        }

        // Otherwise leave it to the default role checks.
        return Task.CompletedTask;
    }
}
