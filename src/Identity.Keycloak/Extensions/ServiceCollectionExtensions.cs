using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Identity.Abstractions.Abstractions;
using Identity.Abstractions.Configuration;
using Identity.Keycloak.Configuration;
using Identity.Keycloak.Services;

namespace Identity.Keycloak.Extensions;

/// <summary>
/// Extension methods for registering Keycloak identity provider services
/// </summary>
public static class ServiceCollectionExtensions
{
  /// <summary>
  /// Add Keycloak identity provider to the service collection
  /// </summary>
  public static IServiceCollection AddKeycloakIdentityProvider(
    this IServiceCollection services,
    IConfiguration configuration)
  {
    // Register configuration
    services.Configure<KeycloakOptions>(
      configuration.GetSection(KeycloakOptions.SectionName));

    services.Configure<KeycloakAdminOptions>(
      configuration.GetSection(KeycloakAdminOptions.SectionName));

    services.Configure<IdentityProviderOptions>(
      configuration.GetSection(IdentityProviderOptions.SectionName));

    // Validate configuration on startup
    services.AddOptions<KeycloakOptions>()
      .ValidateOnStart();

    services.AddOptions<KeycloakAdminOptions>()
      .ValidateOnStart();

    services.AddOptions<IdentityProviderOptions>()
      .ValidateOnStart();

    // Register HttpClient for Keycloak services
    services.AddHttpClient<KeycloakTokenService>();
    services.AddHttpClient<KeycloakUserManagementService>();

    // Register services
    // Note: IOtpService and INotificationService should be registered by the consuming application
    // as they might use database or external services

    services.AddScoped<KeycloakTokenService>();
    services.AddScoped<IIdentityProvider, KeycloakIdentityProvider>();
    services.AddScoped<IUserManagementService, KeycloakUserManagementService>();

    return services;
  }
}
