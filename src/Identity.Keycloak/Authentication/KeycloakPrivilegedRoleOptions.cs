using Microsoft.Extensions.Configuration;

namespace Identity.Keycloak.Authentication;

public sealed class KeycloakPrivilegedRoleOptions
{
    public const string SectionName = "Authentication";

    public string? PlatformRealm { get; set; }

    public string[]? PrivilegedRoles { get; set; }

    /// <summary>Binds the <c>Authentication</c> section; an absent section gives no platform realm and no roles.</summary>
    public static KeycloakPrivilegedRoleOptions From(IConfiguration configuration) =>
        configuration.GetSection(SectionName).Get<KeycloakPrivilegedRoleOptions>() ?? new KeycloakPrivilegedRoleOptions();
}
