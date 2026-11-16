using System.Net;
using Identity.Keycloak.Configuration;
using Identity.Keycloak.Services;
using Identity.Keycloak.Tests.Admin;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Keycloak.Tests.UserManagement;

public sealed class KeycloakUserManagementServiceRolesTests
{
    private const string Authority = "https://kc.test/realms/finreg";
    private const string AdminBase = "https://kc.test/admin/realms/finreg";
    private const string TokenJson = """{"access_token":"tok","expires_in":300,"refresh_expires_in":0,"token_type":"Bearer","scope":"profile email"}""";

    [Fact]
    public async Task GetUsersAsync_WithRealmRoleMappings_ReturnsEachUsersRoles()
    {
        var responses = new Dictionary<string, (HttpStatusCode, string)>
        {
            [$"{AdminBase}/users"] = (HttpStatusCode.OK, """[{"id":"u-1","username":"alice","enabled":true,"createdTimestamp":1700000000000,"email":"alice@example.test","emailVerified":true,"attributes":{"tenantId":["7c9e6679-7425-40de-944b-e07fc1f90ae7"]}},{"id":"u-2","username":"bob","enabled":true,"createdTimestamp":1700000000001,"emailVerified":false}]"""),
            [$"{AdminBase}/users/u-1/role-mappings/realm"] = (HttpStatusCode.OK, """[{"id":"r-1","name":"finreg-admin","description":"FinReg admin","composite":false,"clientRole":false,"containerId":"finreg"},{"id":"r-2","name":"default-roles-finreg","composite":true,"clientRole":false,"containerId":"finreg"}]"""),
            [$"{AdminBase}/users/u-2/role-mappings/realm"] = (HttpStatusCode.OK, """[{"id":"r-3","name":"finreg-user","composite":false,"clientRole":false,"containerId":"finreg"}]"""),
        };
        var service = CreateService(responses);

        var users = await service.GetUsersAsync();

        Assert.Equal(["finreg-admin", "default-roles-finreg"], users.Single(u => u.Id == "u-1").Roles);
        Assert.Equal(["finreg-user"], users.Single(u => u.Id == "u-2").Roles);
    }

    [Fact]
    public async Task GetUserByIdAsync_WithRealmRoleMappings_ReturnsUserRoles()
    {
        var responses = new Dictionary<string, (HttpStatusCode, string)>
        {
            [$"{AdminBase}/users/u-1"] = (HttpStatusCode.OK, """{"id":"u-1","username":"alice","enabled":true,"createdTimestamp":1700000000000,"email":"alice@example.test"}"""),
            [$"{AdminBase}/users/u-1/role-mappings/realm"] = (HttpStatusCode.OK, """[{"id":"r-1","name":"finreg-admin","composite":false,"clientRole":false,"containerId":"finreg"}]"""),
        };
        var service = CreateService(responses);

        var user = await service.GetUserByIdAsync("u-1");

        Assert.Equal(["finreg-admin"], user!.Roles);
    }

    [Fact]
    public async Task GetUsersAsync_WhenRoleMappingsGetFails_ThrowsKeycloakRoleLookupException()
    {
        var responses = new Dictionary<string, (HttpStatusCode, string)>
        {
            [$"{AdminBase}/users"] = (HttpStatusCode.OK, """[{"id":"u-1","username":"alice","enabled":true}]"""),
            [$"{AdminBase}/users/u-1/role-mappings/realm"] = (HttpStatusCode.Forbidden, """{"error":"unknown_error"}"""),
        };
        var service = CreateService(responses);

        var act = () => service.GetUsersAsync();

        var ex = await Assert.ThrowsAsync<KeycloakRoleLookupException>(act);
        Assert.Contains("u-1", ex.Message);
    }

    [Fact]
    public async Task GetUserByIdAsync_WhenRoleMappingsGetFails_ThrowsKeycloakRoleLookupException()
    {
        var responses = new Dictionary<string, (HttpStatusCode, string)>
        {
            [$"{AdminBase}/users/u-1"] = (HttpStatusCode.OK, """{"id":"u-1","username":"alice","enabled":true}"""),
            [$"{AdminBase}/users/u-1/role-mappings/realm"] = (HttpStatusCode.InternalServerError, "{}"),
        };
        var service = CreateService(responses);

        var act = () => service.GetUserByIdAsync("u-1");

        await Assert.ThrowsAsync<KeycloakRoleLookupException>(act);
    }

    [Fact]
    public async Task GetUsersAsync_WhenRoleMappingsRequestThrows_ThrowsKeycloakRoleLookupException()
    {
        var responses = new Dictionary<string, (HttpStatusCode, string)>
        {
            [$"{AdminBase}/users"] = (HttpStatusCode.OK, """[{"id":"u-1","username":"alice","enabled":true}]"""),
        };
        var service = CreateService(responses, new HttpRequestException("Connection refused"));

        var act = () => service.GetUsersAsync();

        var ex = await Assert.ThrowsAsync<KeycloakRoleLookupException>(act);
        Assert.IsType<HttpRequestException>(ex.InnerException);
    }

    [Fact]
    public async Task GetUserByIdAsync_WhenRoleMappingsRequestTimesOut_ThrowsKeycloakRoleLookupException()
    {
        var responses = new Dictionary<string, (HttpStatusCode, string)>
        {
            [$"{AdminBase}/users/u-1"] = (HttpStatusCode.OK, """{"id":"u-1","username":"alice","enabled":true}"""),
        };
        var service = CreateService(responses, new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout"));

        var act = () => service.GetUserByIdAsync("u-1");

        var ex = await Assert.ThrowsAsync<KeycloakRoleLookupException>(act);
        Assert.IsType<TaskCanceledException>(ex.InnerException);
    }

    [Fact]
    public async Task GetUsersAsync_WhenUsersGetFails_ReturnsEmptyList()
    {
        var responses = new Dictionary<string, (HttpStatusCode, string)>
        {
            [$"{AdminBase}/users"] = (HttpStatusCode.ServiceUnavailable, "{}"),
        };
        var service = CreateService(responses);

        var users = await service.GetUsersAsync();

        Assert.Empty(users);
    }

    [Fact]
    public async Task AssignRolesAsync_WhenRealmRolesGetFails_ReturnsFalse()
    {
        var responses = new Dictionary<string, (HttpStatusCode, string)>
        {
            [$"{AdminBase}/roles"] = (HttpStatusCode.Forbidden, """{"error":"unknown_error"}"""),
        };
        var service = CreateService(responses);

        var assigned = await service.AssignRolesAsync("u-1", ["finreg-admin"]);

        Assert.False(assigned);
    }

    private static KeycloakUserManagementService CreateService(Dictionary<string, (HttpStatusCode Status, string Json)> responses) =>
        CreateService(responses, roleMappingsFailure: null);

    private static KeycloakUserManagementService CreateService(
        Dictionary<string, (HttpStatusCode Status, string Json)> responses,
        Exception? roleMappingsFailure)
    {
        var handler = new FakeHttpMessageHandler(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            if (url.EndsWith("/protocol/openid-connect/token", StringComparison.Ordinal))
                return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenJson);
            if (roleMappingsFailure is not null && url.EndsWith("/role-mappings/realm", StringComparison.Ordinal))
                throw roleMappingsFailure;
            return responses.TryGetValue(url, out var response)
                ? FakeHttpMessageHandler.Json(response.Status, response.Json)
                : FakeHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"error":"not found"}""");
        });
        return new KeycloakUserManagementService(
            new HttpClient(handler),
            Options.Create(new KeycloakOptions { Authority = Authority }),
            Options.Create(new KeycloakAdminOptions { AdminClientId = "finreg-admin-cli", AdminClientSecret = "secret" }),
            NullLogger<KeycloakUserManagementService>.Instance);
    }
}
