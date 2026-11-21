using System.Runtime.CompilerServices;

namespace Identity.Keycloak.Authentication;

internal static class KeycloakOwnedValidators
{
    private static readonly ConditionalWeakTable<object, object> Owned = new();

    private static readonly object Marker = new();

    internal static T Mark<T>(T value)
        where T : class
    {
        Owned.AddOrUpdate(value, Marker);
        return value;
    }

    internal static bool IsOwned(object value) => Owned.TryGetValue(value, out _);

    internal static bool IsUnsetOrOwned(object? value) => value is null || IsOwned(value);
}
