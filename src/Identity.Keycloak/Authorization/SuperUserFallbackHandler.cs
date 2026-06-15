using Microsoft.AspNetCore.Authorization;
using Security.Claims.Claims;

namespace Identity.Keycloak.Authorization;

/// <summary>
/// Grants a <c>superUser</c> access to endpoints protected by a plain
/// <c>[Authorize]</c> with no roles specified (covers any
/// <see cref="IAuthorizationRequirement"/> not otherwise satisfied).
/// </summary>
/// <remarks>
/// Companion to <see cref="SuperUserAuthorizationHandler"/>; opt in via
/// <c>AddRealmAuthorization(enableSuperUser: true)</c>. Note: because this
/// satisfies <em>any</em> requirement for a superuser, the cross-realm
/// <see cref="RealmRequirement"/> is also satisfied for superusers — which is
/// intended (a superuser is platform-wide, above the per-product realm wall).
/// </remarks>
public sealed class SuperUserFallbackHandler : AuthorizationHandler<IAuthorizationRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        IAuthorizationRequirement requirement)
    {
        if (context.User.IsSuperUser())
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
