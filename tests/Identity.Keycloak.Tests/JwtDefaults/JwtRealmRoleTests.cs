using System.Net.Http.Headers;
using System.Net.Http.Json;
using Shouldly;

namespace Identity.Keycloak.Tests.JwtDefaults;

public class JwtRealmRoleTests
{
    [Fact]
    public async Task Get_WithRealmRolesInToken_ReturnsEachRoleAsRoleClaim()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(JwtValidationTests.JwtSettings(keycloak, "selida-api"));
        var token = keycloak.CreateTokenWithRealmRoles("selida-api", ["catalog-admin", "viewer"]);

        var roles = await GetRolesAsync(host, token);

        roles.ShouldBe(["catalog-admin", "viewer"]);
    }

    [Fact]
    public async Task Get_WithoutRealmAccessClaim_ReturnsNoRoleClaims()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(JwtValidationTests.JwtSettings(keycloak, "selida-api"));
        var token = keycloak.CreateToken("selida-api", DateTime.UtcNow.AddMinutes(5));

        var roles = await GetRolesAsync(host, token);

        roles.ShouldBeEmpty();
    }

    private static async Task<string[]> GetRolesAsync(JwtDefaultsHost host, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, JwtDefaultsHost.RolesPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await host.Client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<string[]>())!;
    }
}
