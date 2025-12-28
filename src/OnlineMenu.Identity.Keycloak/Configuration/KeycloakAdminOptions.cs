namespace OnlineMenu.Identity.Keycloak.Configuration;

/// <summary>
/// Configuration options for Keycloak Admin API
/// </summary>
public class KeycloakAdminOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json
    /// </summary>
    public const string SectionName = "KeycloakAdmin";

    /// <summary>
    /// Admin client ID with user management permissions
    /// </summary>
    public string AdminClientId { get; set; } = string.Empty;

    /// <summary>
    /// Admin client secret
    /// </summary>
    public string AdminClientSecret { get; set; } = string.Empty;
}
