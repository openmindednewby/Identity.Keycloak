using System.Runtime.CompilerServices;

namespace Identity.Keycloak.Authentication;

internal static class KeycloakOwnedValidators
{
    private static readonly ConditionalWeakTable<Delegate, object> Owned = new();

    private static readonly object Marker = new();

    internal static T Mark<T>(T validator)
        where T : Delegate
    {
        Owned.AddOrUpdate(validator, Marker);
        return validator;
    }

    internal static bool IsUnsetOrOwned(Delegate? validator) => validator is null || Owned.TryGetValue(validator, out _);
}
