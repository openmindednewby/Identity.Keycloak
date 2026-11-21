using System.Reflection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Keycloak.Authentication;

internal static class JwtBearerExtensionPoints
{
    private static readonly PropertyInfo[] DelegateProperties = typeof(TokenValidationParameters)
        .GetProperties(BindingFlags.Public | BindingFlags.Instance)
        .Where(property => property.CanRead && typeof(Delegate).IsAssignableFrom(property.PropertyType))
        .ToArray();

    internal static IEnumerable<string> Violations(JwtBearerOptions options) =>
        DelegateProperties
            .Where(property => !KeycloakOwnedValidators.IsUnsetOrOwned((Delegate?)property.GetValue(options.TokenValidationParameters)))
            .Select(property => $"{property.Name} must not be set outside Identity.Keycloak")
            .Concat(TokenHandlerViolations(options))
            .Concat(JwtBearerEventRules.Violations(options))
            .Concat(JwtBearerKeySourceRules.Violations(options));

    private static IEnumerable<string> TokenHandlerViolations(JwtBearerOptions options)
    {
        var isDefault = !options.UseSecurityTokenValidators
            && options.TokenHandlers.Count == 1
            && options.TokenHandlers[0].GetType() == typeof(JsonWebTokenHandler);
        if (!isDefault)
        {
            yield return "TokenHandlers must be the package default JsonWebTokenHandler";
        }
    }
}
