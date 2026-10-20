using System.Net;
using Identity.Keycloak.Admin;
using Identity.Keycloak.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Identity.Keycloak.Tests.Admin;

public class KeycloakAdminClientGuardTests
{
    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("a/../b")]
    [InlineData("a\\b")]
    [InlineData("")]
    [InlineData(" ")]
    public async Task DeleteUserAsync_WithUnsafeUserId_ReturnsBadRequestWithoutAnyRequest(string userId)
    {
        var (client, handler) = AdminClientFactory.Create("https://kc.test", "admin-token", _ => new HttpResponseMessage(HttpStatusCode.NoContent));

        var result = await client.DeleteUserAsync("kefi", userId);

        Assert.Equal(KeycloakAdminOutcome.BadRequest, result.Outcome);
        Assert.Null(result.StatusCode);
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("a/../b")]
    public async Task GetUserAsync_WithUnsafeUserId_ReturnsBadRequestWithoutAnyRequest(string userId)
    {
        var (client, handler) = AdminClientFactory.Create("https://kc.test", "admin-token", _ => FakeHttpMessageHandler.Json(HttpStatusCode.OK, "{\"id\":\"u-1\"}"));

        var result = await client.GetUserAsync("kefi", userId);

        Assert.Equal(KeycloakAdminOutcome.BadRequest, result.Outcome);
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData("..")]
    [InlineData("a/../b")]
    public async Task RemoveUserRealmRolesAsync_WithUnsafeUserId_ReturnsBadRequestWithoutAnyRequest(string userId)
    {
        var (client, handler) = AdminClientFactory.Create("https://kc.test", "admin-token", _ => FakeHttpMessageHandler.Json(HttpStatusCode.OK, "[]"));

        var result = await client.RemoveUserRealmRolesAsync("kefi", userId, ["organizer"]);

        Assert.Equal(KeycloakAdminOutcome.BadRequest, result.Outcome);
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("kefi/../master")]
    public async Task ListRealmRolesAsync_WithUnsafeRealm_ReturnsBadRequestWithoutAnyRequest(string realm)
    {
        var (client, handler) = AdminClientFactory.Create("https://kc.test", "admin-token", _ => FakeHttpMessageHandler.Json(HttpStatusCode.OK, "[]"));

        var result = await client.ListRealmRolesAsync(realm);

        Assert.Equal(KeycloakAdminOutcome.BadRequest, result.Outcome);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task DeleteUserAsync_WithoutAdminCredentials_ReturnsUpstreamErrorWithoutAnyRequest()
    {
        var options = new KeycloakAdminClientOptions { ServerUrl = "https://kc.test", AdminClientId = "kefi-admin-cli" };
        var (client, handler) = AdminClientFactory.Create(options, "admin-token", _ => new HttpResponseMessage(HttpStatusCode.NoContent));

        var result = await client.DeleteUserAsync("kefi", "u-1");

        Assert.Equal(KeycloakAdminOutcome.UpstreamError, result.Outcome);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task GetUserAsync_WithoutAdminCredentials_ReturnsUpstreamErrorWithoutAnyRequest()
    {
        var options = new KeycloakAdminClientOptions { ServerUrl = "https://kc.test", AdminClientId = "kefi-admin-cli" };
        var (client, handler) = AdminClientFactory.Create(options, "admin-token", _ => FakeHttpMessageHandler.Json(HttpStatusCode.OK, "{\"id\":\"u-1\"}"));

        var result = await client.GetUserAsync("kefi", "u-1");

        Assert.Equal(KeycloakAdminOutcome.UpstreamError, result.Outcome);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task CreateUserAsync_WithoutProfileNames_LeavesCallerUserUnchanged()
    {
        var created = new HttpResponseMessage(HttpStatusCode.Created);
        created.Headers.Location = new Uri("https://kc.test/admin/realms/kefi/users/new-id");
        var (client, _) = AdminClientFactory.Create("https://kc.test", "admin-token", _ => created);
        var user = new KeycloakUserRepresentation { Username = "ana.lopez@example.com", Email = "ana.lopez@example.com", FirstName = null, LastName = null };

        await client.CreateUserAsync("kefi", user);

        Assert.Null(user.FirstName);
        Assert.Null(user.LastName);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData("not a url", null)]
    [InlineData(null, "kc.test/realms/kefi")]
    public void AddKeycloakAdminClient_WithoutAbsoluteServerUrlOrAuthority_FailsOnOptionsResolve(string? serverUrl, string? authority)
    {
        var settings = new Dictionary<string, string?>
        {
            ["KeycloakAdmin:ServerUrl"] = serverUrl,
            ["KeycloakAdmin:Authority"] = authority,
        };
        var services = new ServiceCollection();
        services.AddKeycloakAdminClient(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
        using var provider = services.BuildServiceProvider();

        var act = () => provider.GetRequiredService<IOptions<KeycloakAdminClientOptions>>().Value;

        Assert.Throws<OptionsValidationException>(act);
    }

    [Theory]
    [InlineData("https://kc.test", null, "https://kc.test")]
    [InlineData(null, "https://kc.test/realms/kefi", "https://kc.test/realms/kefi")]
    public void AddKeycloakAdminClient_WithAbsoluteServerUrlOrAuthority_ResolvesOptions(string? serverUrl, string? authority, string expectedConfigured)
    {
        var settings = new Dictionary<string, string?>
        {
            ["KeycloakAdmin:ServerUrl"] = serverUrl,
            ["KeycloakAdmin:Authority"] = authority,
        };
        var services = new ServiceCollection();
        services.AddKeycloakAdminClient(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<KeycloakAdminClientOptions>>().Value;

        Assert.Equal(expectedConfigured, serverUrl is null ? options.Authority : options.ServerUrl);
    }
}
