using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Identity.Keycloak.Authentication;

internal static class JwtBearerKeySourceRules
{
    internal static IEnumerable<string> Violations(JwtBearerOptions options)
    {
        var parameters = options.TokenValidationParameters;
        var sources = new (bool Holds, string Source)[]
        {
            (options.Configuration is null, "Configuration"),
            (KeycloakOwnedValidators.IsUnsetOrOwned(options.ConfigurationManager), "ConfigurationManager"),
            (parameters.ConfigurationManager is null, "TokenValidationParameters.ConfigurationManager"),
            (parameters.IssuerSigningKey is null, "IssuerSigningKey"),
            (parameters.IssuerSigningKeys is null || !parameters.IssuerSigningKeys.Any(), "IssuerSigningKeys"),
            (parameters.CryptoProviderFactory is null, "CryptoProviderFactory"),
        }
            .Where(check => !check.Holds)
            .Select(check => $"{check.Source} must not be set outside Identity.Keycloak");
        return HasPackageResolverWhenPackageConfigured(options)
            ? sources
            : sources.Append("IssuerSigningKeyResolver must be the package resolver");
    }

    private static bool HasPackageResolverWhenPackageConfigured(JwtBearerOptions options)
    {
        var resolver = options.TokenValidationParameters.IssuerSigningKeyResolver;
        return !KeycloakOwnedValidators.IsOwned(options) || (resolver is not null && KeycloakOwnedValidators.IsOwned(resolver));
    }
}
