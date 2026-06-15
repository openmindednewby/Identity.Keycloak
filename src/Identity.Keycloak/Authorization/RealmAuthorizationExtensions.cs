using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Identity.Keycloak.Authorization;

/// <summary>
/// DI wire-up for the shared cross-realm authorization wall (and the optional
/// superuser override).
/// </summary>
/// <remarks>
/// Call <see cref="AddRealmAuthorization"/> AFTER
/// <c>AddAuthentication().AddJwtBearer(...)</c> but BEFORE any
/// <c>AddAuthorization()</c>. It installs a fallback policy so every
/// authenticated endpoint inherits the realm requirement; <c>[AllowAnonymous]</c>
/// endpoints still bypass it.
/// </remarks>
public static class RealmAuthorizationExtensions
{
    /// <summary>Default config key holding the accepted-realm string array.</summary>
    public const string DefaultRealmsConfigKey = "Authentication:AllowedRealms";

    /// <summary>
    /// Registers the cross-realm wall: reads the accepted realms from
    /// <paramref name="realmsConfigKey"/>, binds <see cref="RealmAuthorizationOptions"/>,
    /// registers <see cref="RealmAuthorizationHandler"/>, and sets the fallback
    /// policy to require an authenticated user satisfying <see cref="RealmRequirement"/>.
    /// </summary>
    /// <param name="builder">The web application builder.</param>
    /// <param name="realmsConfigKey">
    /// The configuration key whose string-array value lists the accepted realms.
    /// Defaults to <c>Authentication:AllowedRealms</c>; pass a different key
    /// (e.g. <c>Authentication:ProductRealms</c>) to consume an existing config
    /// shape without renaming it.
    /// </param>
    /// <param name="enableSuperUser">
    /// When <see langword="true"/>, also registers
    /// <see cref="SuperUserAuthorizationHandler"/> + <see cref="SuperUserFallbackHandler"/>
    /// so a <c>superUser</c> satisfies role and plain-<c>[Authorize]</c> requirements
    /// (and, by extension, the realm wall) platform-wide.
    /// </param>
    public static WebApplicationBuilder AddRealmAuthorization(
        this WebApplicationBuilder builder,
        string realmsConfigKey = DefaultRealmsConfigKey,
        bool enableSuperUser = false)
    {
        var allowedRealms = builder.Configuration.GetSection(realmsConfigKey).Get<string[]>()
            ?? Array.Empty<string>();
        builder.Services.Configure<RealmAuthorizationOptions>(o => o.AllowedRealms = allowedRealms);

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddSingleton<IAuthorizationHandler, RealmAuthorizationHandler>();

        if (enableSuperUser)
        {
            builder.Services.AddSingleton<IAuthorizationHandler, SuperUserAuthorizationHandler>();
            builder.Services.AddSingleton<IAuthorizationHandler, SuperUserFallbackHandler>();
        }

        builder.Services.AddAuthorization(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new RealmRequirement())
            .Build();
        });

        return builder;
    }
}
