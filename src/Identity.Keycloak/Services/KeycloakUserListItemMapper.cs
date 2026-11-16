using Identity.Abstractions.Models;

namespace Identity.Keycloak.Services;

internal static class KeycloakUserListItemMapper
{
    public static UserListItem Map(KeycloakUser user, List<string> roles) => new()
    {
        Id = user.Id,
        Username = user.Username,
        Email = user.Email,
        FirstName = user.FirstName,
        LastName = user.LastName,
        Enabled = user.Enabled,
        CreatedTimestamp = user.CreatedTimestamp.HasValue
            ? DateTimeOffset.FromUnixTimeMilliseconds(user.CreatedTimestamp.Value).DateTime
            : null,
        PhoneNumber = FirstAttribute(user, "phoneNumber"),
        Roles = roles,
        TenantId = FirstAttribute(user, "tenantId")
    };

    private static string? FirstAttribute(KeycloakUser user, string name) =>
        user.Attributes?.TryGetValue(name, out var values) == true && values?.Length > 0 ? values[0] : null;
}
