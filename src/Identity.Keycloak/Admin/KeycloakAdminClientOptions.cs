namespace Identity.Keycloak.Admin;

/// <summary>Where the Keycloak Admin REST API lives and which credentials obtain its token.</summary>
public sealed class KeycloakAdminClientOptions
{
    public const string SectionName = "KeycloakAdmin";

    public const string MasterRealm = "master";

    public const string DefaultMasterAdminClientId = "admin-cli";

    public string ServerUrl { get; set; } = string.Empty;

    public string? Authority { get; set; }

    public string ClientCredentialsRealm { get; set; } = MasterRealm;

    public string AdminClientId { get; set; } = string.Empty;

    public string AdminClientSecret { get; set; } = string.Empty;

    public string? MasterAdminUser { get; set; }

    public string? MasterAdminPassword { get; set; }

    public string MasterAdminClientId { get; set; } = DefaultMasterAdminClientId;

    public bool PreferMasterAdminPassword { get; set; }
}
