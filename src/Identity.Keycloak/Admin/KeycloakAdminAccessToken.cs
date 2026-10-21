namespace Identity.Keycloak.Admin;

internal sealed record KeycloakAdminAccessToken(string Value, TimeSpan Lifetime);
