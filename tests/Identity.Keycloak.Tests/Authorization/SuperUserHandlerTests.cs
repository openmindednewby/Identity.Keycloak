using System.Security.Claims;
using Identity.Keycloak.Authentication;
using Identity.Keycloak.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.Options;
using Shouldly;

namespace Identity.Keycloak.Tests.Authorization;

public class SuperUserHandlerTests
{
    [Fact]
    public async Task HandleAsync_WithSuperUserFromTenantRealm_DoesNotSucceed()
    {
        var context = ContextFor("tenant");
        var handler = new SuperUserFallbackHandler(Options.Create(new KeycloakRoleMappingOptions { PlatformRealm = "platform" }));

        await handler.HandleAsync(context);

        context.HasSucceeded.ShouldBeFalse();
    }

    [Fact]
    public async Task HandleAsync_WithSuperUserFromPlatformRealm_Succeeds()
    {
        var context = ContextFor("platform");
        var handler = new SuperUserAuthorizationHandler(Options.Create(new KeycloakRoleMappingOptions { PlatformRealm = "platform" }));

        await handler.HandleAsync(context);

        context.HasSucceeded.ShouldBeTrue();
    }

    [Fact]
    public async Task HandleAsync_WithoutPlatformRealm_DoesNotSucceed()
    {
        var context = ContextFor("platform");
        var handler = new SuperUserAuthorizationHandler(Options.Create(new KeycloakRoleMappingOptions()));

        await handler.HandleAsync(context);

        context.HasSucceeded.ShouldBeFalse();
    }

    private static AuthorizationHandlerContext ContextFor(string realm)
    {
        var identity = new ClaimsIdentity(
            [new Claim("iss", $"https://id.example/realms/{realm}"), new Claim(ClaimTypes.Role, "superUser")],
            "Bearer",
            "name",
            ClaimTypes.Role);
        return new AuthorizationHandlerContext([new RolesAuthorizationRequirement(["catalog-admin"])], new ClaimsPrincipal(identity), null);
    }
}
