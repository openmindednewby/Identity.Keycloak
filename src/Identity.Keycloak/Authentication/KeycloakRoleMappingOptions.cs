using Security.Claims.Claims;

namespace Identity.Keycloak.Authentication;

/// <summary>Which realms get realm-role claims, and which roles only the platform realm may grant.</summary>
public sealed class KeycloakRoleMappingOptions
{
    /// <summary>Realms whose tokens get realm-role claims.</summary>
    public string[] AllowedRealms { get; set; } = [];

    /// <summary>The only realm that may grant the privileged roles; none when null.</summary>
    public string? PlatformRealm { get; set; }

    /// <summary>Role names granted only to tokens issued by the platform realm.</summary>
    public string[] PrivilegedRoles { get; set; } = [OnlineMenuRoles.SuperUser];
}
