using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Identity.Keycloak.Authentication;

internal static class JwtBearerKeySourceRules
{
    internal static IEnumerable<string> Violations(JwtBearerOptions options)
    {
        var parameters = options.TokenValidationParameters;
        return new (bool Holds, string Source)[]
        {
            (options.Configuration is null, "Configuration"),
            (IsUnsetOrFrameworkCreated(options), "ConfigurationManager"),
            (parameters.ConfigurationManager is null, "TokenValidationParameters.ConfigurationManager"),
            (parameters.IssuerSigningKey is null, "IssuerSigningKey"),
            (parameters.IssuerSigningKeys is null || !parameters.IssuerSigningKeys.Any(), "IssuerSigningKeys"),
            (parameters.CryptoProviderFactory is null, "CryptoProviderFactory"),
        }
            .Where(check => !check.Holds)
            .Select(check => $"{check.Source} must not be set outside Identity.Keycloak");
    }

    private static bool IsUnsetOrFrameworkCreated(JwtBearerOptions options) =>
        options.ConfigurationManager is null
        || (options.ConfigurationManager.GetType() == typeof(ConfigurationManager<OpenIdConnectConfiguration>)
            && !string.IsNullOrEmpty(options.MetadataAddress)
            && string.Equals(
                ((ConfigurationManager<OpenIdConnectConfiguration>)options.ConfigurationManager).MetadataAddress,
                options.MetadataAddress,
                StringComparison.Ordinal));
}
