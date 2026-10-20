namespace Identity.Keycloak.Admin;

public enum KeycloakAdminOutcome
{
    Success,
    NotFound,
    Conflict,
    BadRequest,
    AccessDenied,
    UpstreamError,
}
