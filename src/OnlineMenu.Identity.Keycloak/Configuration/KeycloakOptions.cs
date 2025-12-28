namespace OnlineMenu.Identity.Keycloak.Configuration;

/// <summary>
/// Configuration options for Keycloak identity provider
/// </summary>
public class KeycloakOptions
{
  /// <summary>
  /// Configuration section name in appsettings.json
  /// </summary>
  public const string SectionName = "Keycloak";

  /// <summary>
  /// Keycloak realm URL (e.g., https://keycloak.example.com/realms/myrealm)
  /// </summary>
  public string Authority { get; set; } = string.Empty;

  /// <summary>
  /// OAuth2 client ID
  /// </summary>
  public string ClientId { get; set; } = string.Empty;

  /// <summary>
  /// OAuth2 client secret (optional for public clients)
  /// </summary>
  public string? ClientSecret { get; set; }

  /// <summary>
  /// Whether to require HTTPS for metadata endpoint
  /// </summary>
  public bool RequireHttpsMetadata { get; set; } = true;

  /// <summary>
  /// Token endpoint URL
  /// </summary>
  public string TokenEndpoint => $"{Authority}/protocol/openid-connect/token";

  /// <summary>
  /// User info endpoint URL
  /// </summary>
  public string UserInfoEndpoint => $"{Authority}/protocol/openid-connect/userinfo";

  /// <summary>
  /// Logout endpoint URL
  /// </summary>
  public string EndSessionEndpoint => $"{Authority}/protocol/openid-connect/logout";

  /// <summary>
  /// Token introspection endpoint URL
  /// </summary>
  public string IntrospectionEndpoint => $"{Authority}/protocol/openid-connect/token/introspect";

  /// <summary>
  /// Token revocation endpoint URL
  /// </summary>
  public string RevocationEndpoint => $"{Authority}/protocol/openid-connect/revoke";
}
