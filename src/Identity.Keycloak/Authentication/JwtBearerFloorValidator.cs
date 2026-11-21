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
            (NotReplaced(parameters.SignatureValidator, parameters.SignatureValidatorUsingConfiguration), "SignatureValidator must not be replaced"),
            (NotReplaced(parameters.IssuerSigningKeyValidator, parameters.IssuerSigningKeyValidatorUsingConfiguration), "IssuerSigningKeyValidator must not be replaced"),
            (NotReplaced(parameters.LifetimeValidator), "LifetimeValidator must not be replaced"),
            (NotReplaced(parameters.IssuerValidator, parameters.IssuerValidatorUsingConfiguration), "IssuerValidator must not be replaced"),
        }
            .Where(check => !check.Holds)
            .Select(check => $"{name}: {check.Rule}")
            .ToArray();

        return failures.Length == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static bool NotReplaced(params Delegate?[] validators) => validators.All(KeycloakOwnedValidators.IsUnsetOrOwned);
}
