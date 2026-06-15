using Microsoft.AspNetCore.Authorization;

namespace Identity.Keycloak.Authorization;

/// <summary>
/// Authorization requirement that gates an authenticated request on the Keycloak
/// realm that issued its token. Paired with <see cref="RealmAuthorizationHandler"/>
/// and the configured allowed-realm list.
/// </summary>
/// <remarks>
/// The cross-realm wall is the isolation between products that share a Keycloak
/// install but use distinct realms: a request is accepted only when its token's
/// <c>iss</c> realm is on the per-deployment allow-list. This is enforced on top
/// of (not instead of) the JwtBearer signature/audience/lifetime validation.
/// </remarks>
public sealed class RealmRequirement : IAuthorizationRequirement
{
}
