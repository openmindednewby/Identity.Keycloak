using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using Identity.Keycloak.Authentication;
using Identity.Keycloak.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;

namespace Identity.Keycloak.Tests.JwtDefaults;

public class JwtRealmRoleSecurityTests
{
    [Fact]
    public async Task Get_WithSuperUserFromTenantRealm_Returns403()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await StartSuperUserHostAsync(keycloak, "platform");
        var token = keycloak.CreateTokenWithRealmRoles("selida-api", ["superUser"]);

        var status = await GetPlatformStatusAsync(host, token);

        status.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Get_WithSuperUserFromPlatformRealm_Returns200()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await StartSuperUserHostAsync(keycloak, FakeKeycloak.Realm);
        var token = keycloak.CreateTokenWithRealmRoles("selida-api", ["superUser"]);

        var status = await GetPlatformStatusAsync(host, token);

        status.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Get_WithMalformedRealmAccess_Returns200WithoutRoles()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(JwtValidationTests.JwtSettings(keycloak, "selida-api"));
        var token = keycloak.CreateTokenWithRealmAccess("selida-api", "{not-json");

        var response = await SendAsync(host, JwtDefaultsHost.RolesPath, token);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync()).ShouldBe("[]");
    }

    [Fact]
    public async Task TransformAsync_WithNonKeycloakIdentity_AddsNoRoleClaims()
    {
        var options = new KeycloakRoleMappingOptions { AllowedRealms = ["test"], PlatformRealm = "test" };
        var identity = new ClaimsIdentity(
            [new Claim("iss", "https://id.example/realms/test"), new Claim("realm_access", """{"roles":["superUser","viewer"]}""")],
            "Cookies");
        var transformation = new KeycloakRealmRoleClaimsTransformation(Options.Create(options));

        var principal = await transformation.TransformAsync(new ClaimsPrincipal(identity));

        principal.FindAll(ClaimTypes.Role).ShouldBeEmpty();
    }

    private static Task<JwtDefaultsHost> StartSuperUserHostAsync(FakeKeycloak keycloak, string platformRealm)
    {
        var settings = JwtValidationTests.JwtSettings(keycloak, "selida-api");
        settings["Authentication:PlatformRealm"] = platformRealm;
        return JwtDefaultsHost.StartAsync(settings, services: services =>
            services.AddSingleton<IAuthorizationHandler, SuperUserAuthorizationHandler>());
    }

    private static async Task<HttpStatusCode> GetPlatformStatusAsync(JwtDefaultsHost host, string token)
    {
        using var response = await SendAsync(host, JwtDefaultsHost.PlatformPath, token);
        return response.StatusCode;
    }

    private static async Task<HttpResponseMessage> SendAsync(JwtDefaultsHost host, string path, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await host.Client.SendAsync(request);
    }
}
