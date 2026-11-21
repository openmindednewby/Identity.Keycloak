using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Identity.Keycloak.Authentication;

internal sealed class JwtBearerFloorValidator : IValidateOptions<JwtBearerOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtBearerOptions options)
    {
        var parameters = options.TokenValidationParameters;
        var algorithms = parameters.ValidAlgorithms?.ToArray() ?? [];
        var failures = new (bool Holds, string Rule)[]
        {
            (parameters.ValidateIssuer, "ValidateIssuer must be true"),
            (parameters.ValidateAudience, "ValidateAudience must be true"),
            (parameters.ValidateLifetime, "ValidateLifetime must be true"),
            (parameters.ValidateIssuerSigningKey, "ValidateIssuerSigningKey must be true"),
            (parameters.RequireSignedTokens, "RequireSignedTokens must be true"),
            (parameters.ClockSkew <= KeycloakJwtDefaults.MaxClockSkew, $"ClockSkew must be at most {KeycloakJwtDefaults.MaxClockSkew}"),
            (algorithms.Length > 0 && algorithms.All(KeycloakJwtDefaults.AllowedAlgorithms.Contains), "ValidAlgorithms must be RS256 or ES256 only"),
        }
            .Where(check => !check.Holds)
            .Select(check => check.Rule)
            .Concat(JwtBearerExtensionPoints.Violations(options))
            .Select(rule => $"{name}: {rule}")
            .ToArray();

        return failures.Length == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
