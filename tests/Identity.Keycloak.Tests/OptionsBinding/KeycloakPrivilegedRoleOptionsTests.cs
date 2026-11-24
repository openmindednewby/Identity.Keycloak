using Identity.Keycloak.Authentication;
using Microsoft.Extensions.Configuration;
using Shouldly;

namespace Identity.Keycloak.Tests.OptionsBinding;

public class KeycloakPrivilegedRoleOptionsTests
{
    [Fact]
    public void From_WithAuthenticationSection_BindsPlatformRealmAndRoles()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authentication:PlatformRealm"] = "platform",
            ["Authentication:PrivilegedRoles:0"] = "superUser",
            ["Authentication:PrivilegedRoles:1"] = "auditor",
        }).Build();

        var options = KeycloakPrivilegedRoleOptions.From(configuration);

        options.PlatformRealm.ShouldBe("platform");
        options.PrivilegedRoles.ShouldBe(["superUser", "auditor"]);
    }

    [Fact]
    public void From_WithoutAuthenticationSection_ReturnsNoRealmAndNoRoles()
    {
        var configuration = new ConfigurationBuilder().Build();

        var options = KeycloakPrivilegedRoleOptions.From(configuration);

        options.PlatformRealm.ShouldBeNull();
        options.PrivilegedRoles.ShouldBeNull();
    }
}
