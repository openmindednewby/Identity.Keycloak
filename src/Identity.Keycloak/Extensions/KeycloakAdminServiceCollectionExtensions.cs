using Identity.Keycloak.Admin;
using Identity.Keycloak.Authentication;
using Identity.Keycloak.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Identity.Keycloak.Extensions;

public static class KeycloakAdminServiceCollectionExtensions
{
    /// <summary>Registers IKeycloakAdminClient bound to KeycloakAdmin, falling back to Keycloak:Authority for the server URL.</summary>
    public static IHttpClientBuilder AddKeycloakAdminClient(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<KeycloakAdminClientOptions>()
            .Bind(configuration.GetSection(KeycloakAdminClientOptions.SectionName))
            .PostConfigure(options =>
            {
                if (string.IsNullOrWhiteSpace(options.Authority))
                    options.Authority = configuration[$"{KeycloakOptions.SectionName}:Authority"];
            });
        return services.AddKeycloakHttpClient<IKeycloakAdminClient, KeycloakAdminClient>(configuration);
    }
}
