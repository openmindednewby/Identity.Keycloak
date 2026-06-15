using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Security.Claims.Claims;

namespace Identity.Keycloak.Authorization;

/// <summary>
/// Authorization handler that enforces the cross-realm wall: an authenticated
/// request is accepted only when its token's <c>iss</c> realm is one of the
/// realms in <see cref="RealmAuthorizationOptions.AllowedRealms"/>.
/// </summary>
/// <remarks>
/// <para>
/// Runs after the JwtBearer middleware has validated the token's signature,
/// audience, and lifetime — it adds a final product-level realm check on top.
/// </para>
/// <para>
/// On rejection it calls <see cref="AuthorizationHandlerContext.Fail()"/>, which
/// surfaces as HTTP 401 (challenge) for the policy — never 403 — keeping
/// cross-realm tokens indistinguishable from "no token" at the wire.
/// </para>
/// <para>
/// Never logs the JWT or any token-bearing claim — only the rejected realm name
/// and request path.
/// </para>
/// </remarks>
public sealed class RealmAuthorizationHandler : AuthorizationHandler<RealmRequirement>
{
    private const string RejectionEvent = "cross_realm_rejected";
    private const string FailureReason = "Token realm is not in the configured allowed-realms list.";

    private readonly IOptionsMonitor<RealmAuthorizationOptions> _options;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<RealmAuthorizationHandler> _logger;

    public RealmAuthorizationHandler(
        IOptionsMonitor<RealmAuthorizationOptions> options,
        IHttpContextAccessor httpContextAccessor,
        ILogger<RealmAuthorizationHandler> logger)
    {
        _options = options;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        RealmRequirement requirement)
    {
        var allowedRealms = _options.CurrentValue.AllowedRealms ?? Array.Empty<string>();

        // Fail-closed: an empty allow-list rejects everything.
        if (allowedRealms.Length == 0)
        {
            LogRejection(actualRealm: null, allowedRealms);
            context.Fail(new AuthorizationFailureReason(this, FailureReason));
            return Task.CompletedTask;
        }

        var actualRealm = context.User.GetRealm();

        if (string.IsNullOrEmpty(actualRealm))
        {
            LogRejection(actualRealm: null, allowedRealms);
            context.Fail(new AuthorizationFailureReason(this, FailureReason));
            return Task.CompletedTask;
        }

        var matched = false;
        for (var i = 0; i < allowedRealms.Length; i++)
        {
            var allowed = allowedRealms[i];
            if (string.IsNullOrWhiteSpace(allowed))
            {
                continue;
            }

            if (string.Equals(allowed, actualRealm, StringComparison.OrdinalIgnoreCase))
            {
                matched = true;
                break;
            }
        }

        if (!matched)
        {
            LogRejection(actualRealm, allowedRealms);
            context.Fail(new AuthorizationFailureReason(this, FailureReason));
            return Task.CompletedTask;
        }

        context.Succeed(requirement);
        return Task.CompletedTask;
    }

    private void LogRejection(string? actualRealm, string[] allowedRealms)
    {
        var path = _httpContextAccessor.HttpContext?.Request.Path.Value ?? "(unknown)";

#pragma warning disable CA1848 // High-perf logging not required for a rejection warning
        _logger.LogWarning(
            "{Event} expectedRealms={ExpectedRealms} actualRealm={ActualRealm} path={Path}",
            RejectionEvent,
            string.Join(",", allowedRealms),
            actualRealm ?? "(none)",
            path);
#pragma warning restore CA1848
    }
}
