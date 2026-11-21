using System.Reflection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Keycloak.Authentication;

internal static class JwtBearerExtensionPoints
{
    private const string AuthenticationFailedRule = "OnAuthenticationFailed must not be set outside Identity.Keycloak";

    private static readonly PropertyInfo[] DelegateProperties = typeof(TokenValidationParameters)
        .GetProperties(BindingFlags.Public | BindingFlags.Instance)
        .Where(property => property.CanRead && typeof(Delegate).IsAssignableFrom(property.PropertyType))
        .ToArray();

    private static readonly MethodInfo DefaultAuthenticationFailed = new JwtBearerEvents().OnAuthenticationFailed.Method;

    internal static IEnumerable<string> Violations(JwtBearerOptions options) =>
        DelegateProperties
            .Where(property => !KeycloakOwnedValidators.IsUnsetOrOwned((Delegate?)property.GetValue(options.TokenValidationParameters)))
            .Select(property => $"{property.Name} must not be set outside Identity.Keycloak")
            .Concat(TokenHandlerViolations(options))
            .Concat(EventViolations(options));

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

    private static IEnumerable<string> EventViolations(JwtBearerOptions options)
    {
        var events = options.Events;
        if (events is not null
            && (events.OnAuthenticationFailed.Method != DefaultAuthenticationFailed || OverridesAuthenticationFailed(events.GetType())))
        {
            yield return AuthenticationFailedRule;
        }

        if (options.EventsType is not null && OverridesAuthenticationFailed(options.EventsType))
        {
            yield return AuthenticationFailedRule;
        }
    }

    private static bool OverridesAuthenticationFailed(Type eventsType) =>
        eventsType.GetMethod(nameof(JwtBearerEvents.AuthenticationFailed))?.DeclaringType != typeof(JwtBearerEvents);
}
