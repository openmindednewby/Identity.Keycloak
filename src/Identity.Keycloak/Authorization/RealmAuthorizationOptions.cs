namespace Identity.Keycloak.Authorization;

/// <summary>
/// Strongly-typed configuration for the cross-realm wall: the set of Keycloak
/// realms a service accepts tokens from.
/// </summary>
/// <remarks>
/// <para>
/// Populated by <see cref="RealmAuthorizationExtensions.AddRealmAuthorization"/>
/// from a caller-specified config key (default <c>Authentication:AllowedRealms</c>;
/// services that name the key differently — e.g. <c>Authentication:ProductRealms</c>
/// — pass their own key so no config rename is required).
/// </para>
/// <para>
/// Realm names are matched case-insensitively. An empty or missing list is
/// treated as <em>fail-closed</em>: every authenticated request is rejected.
/// This prevents a misconfigured deployment from silently accepting cross-realm
/// tokens.
/// </para>
/// </remarks>
public sealed class RealmAuthorizationOptions
{
    /// <summary>
    /// The set of Keycloak realms this service accepts tokens from. Comparison is
    /// case-insensitive. Defaults to an empty array (fail-closed).
    /// </summary>
    public string[] AllowedRealms { get; set; } = Array.Empty<string>();
}
