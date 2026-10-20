namespace Identity.Keycloak.Admin;

/// <summary>The realm and form body of the admin token request the configured credentials call for.</summary>
public sealed record KeycloakAdminTokenRequest(string Realm, IReadOnlyDictionary<string, string> Form)
{
    public static KeycloakAdminTokenRequest From(KeycloakAdminClientOptions options)
    {
        var hasClientSecret = !string.IsNullOrWhiteSpace(options.AdminClientSecret);
        var hasMasterPassword = !string.IsNullOrWhiteSpace(options.MasterAdminUser)
            && !string.IsNullOrWhiteSpace(options.MasterAdminPassword);
        var useMasterPassword = hasMasterPassword && (options.PreferMasterAdminPassword || !hasClientSecret);
        if (useMasterPassword)
            return MasterPassword(options);
        if (hasClientSecret)
            return ClientCredentials(options);
        throw new InvalidOperationException(
            "No Keycloak admin credentials configured: set KeycloakAdmin:AdminClientSecret or KeycloakAdmin:MasterAdminUser and MasterAdminPassword.");
    }

    private static KeycloakAdminTokenRequest MasterPassword(KeycloakAdminClientOptions options) =>
        new(KeycloakAdminClientOptions.MasterRealm, new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = options.MasterAdminClientId,
            ["username"] = options.MasterAdminUser!,
            ["password"] = options.MasterAdminPassword!,
        });

    private static KeycloakAdminTokenRequest ClientCredentials(KeycloakAdminClientOptions options) =>
        new(options.ClientCredentialsRealm, new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = options.AdminClientId,
            ["client_secret"] = options.AdminClientSecret,
        });
}
