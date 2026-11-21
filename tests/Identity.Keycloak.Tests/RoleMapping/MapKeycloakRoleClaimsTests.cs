using System.Security.Claims;
using Identity.Keycloak.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;

namespace Identity.Keycloak.Tests.RoleMapping;

public class MapKeycloakRoleClaimsTests
{
    [Fact]
    public void MapKeycloakRoleClaims_WithSuperUserFromTenantRealm_AddsNoPrivilegedRole()
    {
        var context = ContextFor("tenant", """{"roles":["superUser","viewer"]}""", platformRealm: "platform");

        KeycloakClaimsHelper.MapKeycloakRoleClaims(context);

        RolesOf(context).ShouldBe(["viewer"]);
    }

    [Fact]
    public void MapKeycloakRoleClaims_WithSuperUserFromPlatformRealm_AddsEveryRole()
    {
        var context = ContextFor("platform", """{"roles":["superUser","viewer"]}""", platformRealm: "platform");

        KeycloakClaimsHelper.MapKeycloakRoleClaims(context);

        RolesOf(context).ShouldBe(["superUser", "viewer"]);
    }

    [Fact]
    public void MapKeycloakRoleClaims_WithoutPlatformRealm_AddsNoPrivilegedRole()
    {
        var context = ContextFor("platform", """{"roles":["superUser","viewer"]}""", platformRealm: null);

        KeycloakClaimsHelper.MapKeycloakRoleClaims(context);

        RolesOf(context).ShouldBe(["viewer"]);
    }

    [Fact]
    public void MapKeycloakRoleClaims_WithSuperUserRoleClaimFromTenantRealm_RemovesIt()
    {
        var context = ContextFor("tenant", """{"roles":["viewer"]}""", platformRealm: "platform");
        ((ClaimsIdentity)context.Principal!.Identity!).AddClaim(new Claim(ClaimTypes.Role, "superUser"));

        KeycloakClaimsHelper.MapKeycloakRoleClaims(context);

        RolesOf(context).ShouldBe(["viewer"]);
    }

    private static TokenValidatedContext ContextFor(string realm, string realmAccess, string? platformRealm)
    {
        var services = new ServiceCollection();
        services.AddOptions<KeycloakRoleMappingOptions>().Configure(options => options.PlatformRealm = platformRealm);
        var httpContext = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        var identity = new ClaimsIdentity(
            [new Claim("iss", $"https://id.example/realms/{realm}"), new Claim("realm_access", realmAccess)],
            "Bearer",
            "name",
            ClaimTypes.Role);
        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        return new TokenValidatedContext(httpContext, scheme, new JwtBearerOptions()) { Principal = new ClaimsPrincipal(identity) };
    }

    private static string[] RolesOf(TokenValidatedContext context) =>
        context.Principal!.FindAll(ClaimTypes.Role).Select(claim => claim.Value).ToArray();
}
