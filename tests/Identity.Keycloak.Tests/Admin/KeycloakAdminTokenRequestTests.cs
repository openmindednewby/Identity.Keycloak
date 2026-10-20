using Identity.Keycloak.Admin;

namespace Identity.Keycloak.Tests.Admin;

public class KeycloakAdminTokenRequestTests
{
    [Fact]
    public void From_WithClientSecretOnly_UsesClientCredentialsInConfiguredRealm()
    {
        var options = new KeycloakAdminClientOptions { ClientCredentialsRealm = "kefi", AdminClientId = "kefi-admin-cli", AdminClientSecret = "secret" };

        var request = KeycloakAdminTokenRequest.From(options);

        Assert.Equal("kefi", request.Realm);
        Assert.Equal("client_credentials", request.Form["grant_type"]);
        Assert.Equal("kefi-admin-cli", request.Form["client_id"]);
    }

    [Fact]
    public void From_WithBothCredentialsAndMasterPreferred_UsesPasswordGrantInMasterRealm()
    {
        var options = new KeycloakAdminClientOptions
        {
            AdminClientSecret = "secret",
            MasterAdminUser = "root",
            MasterAdminPassword = "pw",
            MasterAdminClientId = "tenant-admin",
            PreferMasterAdminPassword = true,
        };

        var request = KeycloakAdminTokenRequest.From(options);

        Assert.Equal("master", request.Realm);
        Assert.Equal("password", request.Form["grant_type"]);
        Assert.Equal("tenant-admin", request.Form["client_id"]);
        Assert.Equal("root", request.Form["username"]);
    }

    [Fact]
    public void From_WithBothCredentialsAndNoPreference_UsesClientSecret()
    {
        var options = new KeycloakAdminClientOptions { AdminClientSecret = "secret", MasterAdminUser = "root", MasterAdminPassword = "pw" };

        var request = KeycloakAdminTokenRequest.From(options);

        Assert.Equal("client_credentials", request.Form["grant_type"]);
    }

    [Fact]
    public void From_WithMasterPasswordOnly_UsesAdminCliClient()
    {
        var options = new KeycloakAdminClientOptions { MasterAdminUser = "root", MasterAdminPassword = "pw" };

        var request = KeycloakAdminTokenRequest.From(options);

        Assert.Equal("admin-cli", request.Form["client_id"]);
    }

    [Fact]
    public void From_WithoutCredentials_ThrowsInvalidOperation()
    {
        var options = new KeycloakAdminClientOptions { AdminClientId = "kefi-admin-cli" };

        var act = () => KeycloakAdminTokenRequest.From(options);

        Assert.Throws<InvalidOperationException>(act);
    }
}
