using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
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
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        RolesAuthorizationRequirement requirement)
    {
        if (context.User.IsSuperUser())
        {
            context.Succeed(requirement);
        }

        // Otherwise leave it to the default role checks.
        return Task.CompletedTask;
    }
}
