using System.Net;
using Identity.Keycloak.Admin;
using Microsoft.Extensions.Options;

namespace Identity.Keycloak.Tests.Admin;

public class KeycloakAdminTokenCacheTests
{
    private const string TokenPathSuffix = "/protocol/openid-connect/token";

    [Fact]
    public async Task GetUserRealmRolesAsync_WhenCalledAfterListUsers_ReusesAdminToken()
    {
        const int expectedBearerCalls = 4;
        var (client, handler) = AdminClientFactory.Create(
            "https://kc.test",
            "admin-token",
            request => request.RequestUri!.AbsolutePath.EndsWith("/users", StringComparison.Ordinal)
                ? FakeHttpMessageHandler.Json(HttpStatusCode.OK, "[{\"id\":\"u-1\"},{\"id\":\"u-2\"},{\"id\":\"u-3\"}]")
                : FakeHttpMessageHandler.Json(HttpStatusCode.OK, "[{\"name\":\"tenant-admin\"}]"));
        var users = await client.ListUsersAsync("kefi", new KeycloakUserQuery());

        foreach (var user in users.Value!)
            await client.GetUserRealmRolesAsync("kefi", user.Id!);

        Assert.Single(handler.Requests, request => request.Url.EndsWith(TokenPathSuffix, StringComparison.Ordinal));
        Assert.Equal(expectedBearerCalls, handler.Requests.Count(request => request.Authorization == "Bearer admin-token"));
    }

    [Fact]
    public async Task GetAdminTokenAsync_WhenTokenReachesRefreshMargin_RequestsNewToken()
    {
        const int expectedTokenRequests = 2;
        var clock = new MutableTimeProvider();
        var (client, handler) = AdminClientFactory.Create(
            AdminOptions("kefi"), "admin-token", _ => new HttpResponseMessage(HttpStatusCode.OK), tokenCache: new KeycloakAdminTokenCache(clock));
        await client.GetAdminTokenAsync();
        clock.UtcNow += TimeSpan.FromSeconds(AdminClientFactory.TokenLifetimeSeconds) - KeycloakAdminTokenCache.RefreshMargin;

        await client.GetAdminTokenAsync();

        Assert.Equal(expectedTokenRequests, handler.Requests.Count);
    }

    [Fact]
    public async Task GetAdminTokenAsync_WhenTokenIsBeforeRefreshMargin_ReusesCachedToken()
    {
        var clock = new MutableTimeProvider();
        var (client, handler) = AdminClientFactory.Create(
            AdminOptions("kefi"), "admin-token", _ => new HttpResponseMessage(HttpStatusCode.OK), tokenCache: new KeycloakAdminTokenCache(clock));
        await client.GetAdminTokenAsync();
        clock.UtcNow += TimeSpan.FromSeconds(AdminClientFactory.TokenLifetimeSeconds) - KeycloakAdminTokenCache.RefreshMargin - TimeSpan.FromSeconds(1);

        var token = await client.GetAdminTokenAsync();

        Assert.Equal("admin-token", token);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetAdminTokenAsync_WithSharedCacheAndDifferentRealms_RequestsOneTokenPerRealm()
    {
        var cache = new KeycloakAdminTokenCache(new MutableTimeProvider());
        var (kefiClient, kefiHandler) = AdminClientFactory.Create(AdminOptions("kefi"), "kefi-token", _ => new HttpResponseMessage(HttpStatusCode.OK), tokenCache: cache);
        var (agoraClient, agoraHandler) = AdminClientFactory.Create(AdminOptions("agora"), "agora-token", _ => new HttpResponseMessage(HttpStatusCode.OK), tokenCache: cache);
        await kefiClient.GetAdminTokenAsync();
        await agoraClient.GetAdminTokenAsync();

        var kefiAgain = await kefiClient.GetAdminTokenAsync();

        Assert.Equal("kefi-token", kefiAgain);
        Assert.Single(kefiHandler.Requests);
        Assert.Single(agoraHandler.Requests);
    }

    [Fact]
    public async Task GetAdminTokenAsync_WithConcurrentCallers_RequestsOneToken()
    {
        const int callerCount = 10;
        const int expectedTokenCalls = 1;
        var tokenCalls = 0;
        var handler = new FakeHttpMessageHandler(_ =>
        {
            Interlocked.Increment(ref tokenCalls);
            Thread.Sleep(TimeSpan.FromMilliseconds(50));
            return FakeHttpMessageHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"admin-token\",\"expires_in\":300}");
        });
        var client = new KeycloakAdminClient(new HttpClient(handler), Options.Create(AdminOptions("kefi")), new KeycloakAdminTokenCache(new MutableTimeProvider()));

        var tokens = await Task.WhenAll(Enumerable.Range(0, callerCount).Select(_ => Task.Run(() => client.GetAdminTokenAsync())));

        Assert.All(tokens, token => Assert.Equal("admin-token", token));
        Assert.Equal(expectedTokenCalls, tokenCalls);
    }

    [Fact]
    public async Task GetAdminTokenAsync_WithoutExpiresIn_RequestsNewTokenEachCall()
    {
        const int expectedTokenRequests = 2;
        var handler = new FakeHttpMessageHandler(_ => FakeHttpMessageHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"admin-token\"}"));
        var client = new KeycloakAdminClient(new HttpClient(handler), Options.Create(AdminOptions("kefi")), new KeycloakAdminTokenCache(new MutableTimeProvider()));
        await client.GetAdminTokenAsync();

        await client.GetAdminTokenAsync();

        Assert.Equal(expectedTokenRequests, handler.Requests.Count);
    }

    private static KeycloakAdminClientOptions AdminOptions(string realm) => new()
    {
        ServerUrl = "https://kc.test",
        ClientCredentialsRealm = realm,
        AdminClientId = $"{realm}-admin-cli",
        AdminClientSecret = "secret",
    };
}
