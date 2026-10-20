using System.Net;
using Identity.Keycloak.Admin;
using Microsoft.Extensions.Options;

namespace Identity.Keycloak.Tests.Admin;

internal static class AdminClientFactory
{
    private const string TokenPath = "/protocol/openid-connect/token";

    public static (KeycloakAdminClient Client, FakeHttpMessageHandler Handler) Create(
        string serverUrl,
        string token,
        Func<HttpRequestMessage, HttpResponseMessage> adminResponder,
        HttpStatusCode tokenStatus = HttpStatusCode.OK) =>
        Create(
            new KeycloakAdminClientOptions
            {
                ServerUrl = serverUrl,
                ClientCredentialsRealm = "kefi",
                AdminClientId = "kefi-admin-cli",
                AdminClientSecret = "secret",
            },
            token,
            adminResponder,
            tokenStatus);

    public static (KeycloakAdminClient Client, FakeHttpMessageHandler Handler) Create(
        KeycloakAdminClientOptions options,
        string token,
        Func<HttpRequestMessage, HttpResponseMessage> adminResponder,
        HttpStatusCode tokenStatus = HttpStatusCode.OK)
    {
        var handler = new FakeHttpMessageHandler(request => request.RequestUri!.AbsolutePath.EndsWith(TokenPath, StringComparison.Ordinal)
            ? FakeHttpMessageHandler.Json(tokenStatus, tokenStatus == HttpStatusCode.OK ? $"{{\"access_token\":\"{token}\"}}" : "{\"error\":\"invalid_client\"}")
            : adminResponder(request));
        return (new KeycloakAdminClient(new HttpClient(handler), Options.Create(options)), handler);
    }
}
