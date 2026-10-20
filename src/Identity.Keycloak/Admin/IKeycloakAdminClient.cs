namespace Identity.Keycloak.Admin;

/// <summary>Typed client for the Keycloak Admin REST API of any realm, with a fresh admin token per call.</summary>
public interface IKeycloakAdminClient
{
    Task<string> GetAdminTokenAsync(CancellationToken cancellationToken = default);

    /// <summary>Sends an admin-token request to /admin/realms/{realm}/{relativePath}; the caller disposes it.</summary>
    Task<HttpResponseMessage> SendAsync(HttpMethod method, string realm, string relativePath, HttpContent? content = null, CancellationToken cancellationToken = default);

    Task<KeycloakAdminResult<IReadOnlyList<KeycloakUserRepresentation>>> ListUsersAsync(string realm, KeycloakUserQuery query, CancellationToken cancellationToken = default);

    Task<KeycloakAdminResult<KeycloakUserRepresentation>> GetUserAsync(string realm, string userId, CancellationToken cancellationToken = default);

    /// <summary>Creates the user, filling a missing first or last name from the email; the value is the new user id.</summary>
    Task<KeycloakAdminResult<string>> CreateUserAsync(string realm, KeycloakUserRepresentation user, CancellationToken cancellationToken = default);

    Task<KeycloakAdminResult> UpdateUserAsync(string realm, string userId, KeycloakUserRepresentation user, CancellationToken cancellationToken = default);

    Task<KeycloakAdminResult> DeleteUserAsync(string realm, string userId, CancellationToken cancellationToken = default);

    Task<KeycloakAdminResult> ResetPasswordAsync(string realm, string userId, KeycloakCredentialRepresentation credential, CancellationToken cancellationToken = default);

    Task<KeycloakAdminResult> LogoutUserAsync(string realm, string userId, CancellationToken cancellationToken = default);

    Task<KeycloakAdminResult<IReadOnlyList<KeycloakRoleRepresentation>>> ListRealmRolesAsync(string realm, CancellationToken cancellationToken = default);

    Task<KeycloakAdminResult<IReadOnlyList<KeycloakRoleRepresentation>>> GetUserRealmRolesAsync(string realm, string userId, CancellationToken cancellationToken = default);

    /// <summary>Maps the named realm roles that exist in the realm onto the user; unknown names are skipped.</summary>
    Task<KeycloakAdminResult> AddUserRealmRolesAsync(string realm, string userId, IEnumerable<string> roleNames, CancellationToken cancellationToken = default);

    /// <summary>Removes the named realm roles the user holds; names the user does not hold are skipped.</summary>
    Task<KeycloakAdminResult> RemoveUserRealmRolesAsync(string realm, string userId, IEnumerable<string> roleNames, CancellationToken cancellationToken = default);
}
