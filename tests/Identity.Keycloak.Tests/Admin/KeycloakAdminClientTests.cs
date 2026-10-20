using System.Net;
using System.Text.Json;
using Identity.Keycloak.Admin;

namespace Identity.Keycloak.Tests.Admin;

public class KeycloakAdminClientTests
{
    [Fact]
    public async Task GetAdminTokenAsync_WithClientSecret_PostsClientCredentialsToConfiguredRealm()
    {
        var (client, handler) = AdminClientFactory.Create("https://kc.test", "admin-token", _ => new HttpResponseMessage(HttpStatusCode.OK));

        var token = await client.GetAdminTokenAsync();

        Assert.Equal("admin-token", token);
        var tokenCall = Assert.Single(handler.Requests);
        Assert.Equal("https://kc.test/realms/kefi/protocol/openid-connect/token", tokenCall.Url);
        Assert.Equal("grant_type=client_credentials&client_id=kefi-admin-cli&client_secret=secret", tokenCall.Body);
    }

    [Fact]
    public async Task GetUserAsync_WithExistingUser_SendsBearerTokenToRealmUserUrl()
    {
        var (client, handler) = AdminClientFactory.Create(
            "https://kc.test",
            "admin-token",
            _ => FakeHttpMessageHandler.Json(HttpStatusCode.OK, "{\"id\":\"u-1\",\"attributes\":{\"tenantId\":[\"t-9\"]}}"));

        var result = await client.GetUserAsync("kefi", "u-1");

        Assert.True(result.IsSuccess);
        Assert.Equal("t-9", result.Value!.FirstAttribute("tenantId"));
        Assert.Equal("https://kc.test/admin/realms/kefi/users/u-1", handler.Requests[1].Url);
        Assert.Equal("Bearer admin-token", handler.Requests[1].Authorization);
    }

    [Fact]
    public async Task GetUserAsync_WhenUserMissing_ReturnsNotFoundWithKeycloakError()
    {
        var (client, _) = AdminClientFactory.Create(
            "https://kc.test",
            "admin-token",
            _ => FakeHttpMessageHandler.Json(HttpStatusCode.NotFound, "{\"error\":\"User not found\"}"));

        var result = await client.GetUserAsync("kefi", "missing");

        Assert.Equal(KeycloakAdminOutcome.NotFound, result.Outcome);
        Assert.Equal("User not found", result.ErrorMessage);
    }

    [Fact]
    public async Task CreateUserAsync_WithoutProfileNames_DerivesNamesFromEmail()
    {
        var created = new HttpResponseMessage(HttpStatusCode.Created);
        created.Headers.Location = new Uri("https://kc.test/admin/realms/kefi/users/new-id");
        var (client, handler) = AdminClientFactory.Create("https://kc.test", "admin-token", _ => created);
        var user = new KeycloakUserRepresentation { Username = "ana.lopez@example.com", Email = "ana.lopez@example.com", Enabled = true };

        var result = await client.CreateUserAsync("kefi", user);

        Assert.Equal("new-id", result.Value);
        using var body = JsonDocument.Parse(handler.Requests[1].Body!);
        Assert.Equal("Ana", body.RootElement.GetProperty("firstName").GetString());
        Assert.Equal("Lopez", body.RootElement.GetProperty("lastName").GetString());
        Assert.False(body.RootElement.TryGetProperty("id", out _));
    }

    [Fact]
    public async Task CreateUserAsync_WhenUsernameTaken_ReturnsConflictWithKeycloakMessage()
    {
        var (client, _) = AdminClientFactory.Create(
            "https://kc.test",
            "admin-token",
            _ => FakeHttpMessageHandler.Json(HttpStatusCode.Conflict, "{\"errorMessage\":\"User exists with same username\"}"));
        var user = new KeycloakUserRepresentation { Username = "ana", Email = "ana@example.com", FirstName = "Ana", LastName = "Lopez" };

        var result = await client.CreateUserAsync("kefi", user);

        Assert.Equal(KeycloakAdminOutcome.Conflict, result.Outcome);
        Assert.Equal("User exists with same username", result.ErrorMessage);
    }

    [Fact]
    public async Task ListUsersAsync_WithAttributeQuery_SendsEscapedQueryString()
    {
        var (client, handler) = AdminClientFactory.Create("https://kc.test", "admin-token", _ => FakeHttpMessageHandler.Json(HttpStatusCode.OK, "[{\"id\":\"u-1\"}]"));
        var query = new KeycloakUserQuery { AttributeQuery = "tenantId:abc", Max = 1000 };

        var result = await client.ListUsersAsync("kefi", query);

        Assert.Equal("u-1", Assert.Single(result.Value!).Id);
        Assert.Equal("https://kc.test/admin/realms/kefi/users?q=tenantId%3Aabc&max=1000", handler.Requests[1].Url);
    }

    [Fact]
    public async Task AddUserRealmRolesAsync_WithUnknownRoleName_PostsOnlyExistingRoles()
    {
        var (client, handler) = AdminClientFactory.Create(
            "https://kc.test",
            "admin-token",
            request => request.Method == HttpMethod.Get
                ? FakeHttpMessageHandler.Json(HttpStatusCode.OK, "[{\"id\":\"r1\",\"name\":\"organizer\"},{\"id\":\"r2\",\"name\":\"admin\"}]")
                : new HttpResponseMessage(HttpStatusCode.NoContent));

        var result = await client.AddUserRealmRolesAsync("kefi", "u-1", ["organizer", "ghost"]);

        Assert.True(result.IsSuccess);
        var post = Assert.Single(handler.Requests, r => r.Method == HttpMethod.Post && r.Url.Contains("/admin/", StringComparison.Ordinal));
        Assert.Equal("https://kc.test/admin/realms/kefi/users/u-1/role-mappings/realm", post.Url);
        using var body = JsonDocument.Parse(post.Body!);
        Assert.Equal("organizer", Assert.Single(body.RootElement.EnumerateArray()).GetProperty("name").GetString());
    }

    [Fact]
    public async Task RemoveUserRealmRolesAsync_WhenUserHoldsNoneOfTheRoles_SendsNoDelete()
    {
        var (client, handler) = AdminClientFactory.Create("https://kc.test", "admin-token", _ => FakeHttpMessageHandler.Json(HttpStatusCode.OK, "[]"));

        var result = await client.RemoveUserRealmRolesAsync("kefi", "u-1", ["organizer"]);

        Assert.True(result.IsSuccess);
        Assert.DoesNotContain(handler.Requests, r => r.Method == HttpMethod.Delete);
    }

    [Fact]
    public async Task DeleteUserAsync_WhenTokenEndpointRejects_ReturnsUpstreamErrorWithoutAdminCall()
    {
        var (client, handler) = AdminClientFactory.Create(
            "https://kc.test",
            "admin-token",
            _ => new HttpResponseMessage(HttpStatusCode.NoContent),
            HttpStatusCode.Unauthorized);

        var result = await client.DeleteUserAsync("kefi", "u-1");

        Assert.Equal(KeycloakAdminOutcome.UpstreamError, result.Outcome);
        Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        Assert.Single(handler.Requests);
    }
}
