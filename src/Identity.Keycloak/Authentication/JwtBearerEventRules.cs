using System.Reflection;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Identity.Keycloak.Authentication;

internal static class JwtBearerEventRules
{
    private static readonly PropertyInfo[] EventDelegates = typeof(JwtBearerEvents)
        .GetProperties(BindingFlags.Public | BindingFlags.Instance)
        .Where(property => property.CanRead && typeof(Delegate).IsAssignableFrom(property.PropertyType))
        .ToArray();

    internal static IEnumerable<string> Violations(JwtBearerOptions options)
    {
        if (options.EventsType is not null)
        {
            yield return "EventsType must not be set outside Identity.Keycloak";
        }

        var events = options.Events;
        if (events is null)
        {
            yield break;
        }

        var eventsType = events.GetType();
        if (eventsType != typeof(JwtBearerEvents) && eventsType != typeof(KeycloakJwtBearerEvents))
        {
            yield return "Events must be the package default JwtBearerEvents";
            yield break;
        }

        var defaults = (JwtBearerEvents)Activator.CreateInstance(eventsType)!;
        foreach (var property in EventDelegates.Where(property => !IsSameHandler(property, events, defaults)))
        {
            yield return $"{property.Name} must be the package default";
        }
    }

    private static bool IsSameHandler(PropertyInfo property, JwtBearerEvents events, JwtBearerEvents defaults) =>
        ((Delegate?)property.GetValue(events))?.Method == ((Delegate?)property.GetValue(defaults))?.Method;
}
