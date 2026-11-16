namespace Identity.Keycloak.Services;

/// <summary>Thrown when Keycloak does not return a user's realm role mappings.</summary>
public sealed class KeycloakRoleLookupException : HttpRequestException
{
    /// <summary>Creates the exception for the user whose role mappings could not be read.</summary>
    public KeycloakRoleLookupException(string userId, System.Net.HttpStatusCode? statusCode, Exception? inner = null)
        : base($"Failed to read realm role mappings for user {userId}. Status: {statusCode}", inner, statusCode)
    {
    }
}
