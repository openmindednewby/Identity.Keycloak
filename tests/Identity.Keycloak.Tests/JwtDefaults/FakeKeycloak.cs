using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Keycloak.Tests.JwtDefaults;

internal sealed class FakeKeycloak : IAsyncDisposable
{
    public const string Realm = "test";

    private const string KeyId = "fake-key";

    private readonly WebApplication _app;

    private readonly RsaSecurityKey _key;

    private FakeKeycloak(WebApplication app, RsaSecurityKey key, string serverUrl)
    {
        _app = app;
        _key = key;
        ServerUrl = serverUrl;
    }

    public string ServerUrl { get; }

    public static async Task<FakeKeycloak> StartAsync()
    {
        var key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = KeyId };
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        app.MapGet($"/realms/{Realm}/.well-known/openid-configuration", (HttpContext context) => Results.Json(new Dictionary<string, object>
        {
            ["issuer"] = IssuerOf(context),
            ["jwks_uri"] = $"{IssuerOf(context)}/protocol/openid-connect/certs",
            ["id_token_signing_alg_values_supported"] = new[] { SecurityAlgorithms.RsaSha256 },
        }));
        app.MapGet($"/realms/{Realm}/protocol/openid-connect/certs", () => Results.Json(new { keys = new[] { PublicJwk(key) } }));
        await app.StartAsync();

        var address = app.Services.GetRequiredService<IServer>().Features
            .GetRequiredFeature<IServerAddressesFeature>().Addresses.First();
        return new FakeKeycloak(app, key, address);
    }

    public string CreateToken(string audience, DateTime expiresUtc) =>
        new JsonWebTokenHandler().CreateToken(Descriptor(audience, expiresUtc, new SigningCredentials(_key, SecurityAlgorithms.RsaSha256)));

    public string CreateUnsignedToken(string audience) =>
        new JsonWebTokenHandler().CreateToken(Descriptor(audience, DateTime.UtcNow.AddMinutes(5), null));

    public string CreateTokenSignedByUnknownKey(string audience)
    {
        var unknownKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = KeyId };
        return new JsonWebTokenHandler().CreateToken(
            Descriptor(audience, DateTime.UtcNow.AddMinutes(5), new SigningCredentials(unknownKey, SecurityAlgorithms.RsaSha256)));
    }

    public string CreateTokenWithKeyId(string audience, string keyId) =>
        new JsonWebTokenHandler().CreateToken(Descriptor(
            audience,
            DateTime.UtcNow.AddMinutes(5),
            new SigningCredentials(new RsaSecurityKey(_key.Rsa) { KeyId = keyId }, SecurityAlgorithms.RsaSha256)));

    public string CreateTokenWithoutExpiry(string audience)
    {
        var descriptor = Descriptor(audience, DateTime.UtcNow.AddMinutes(5), new SigningCredentials(_key, SecurityAlgorithms.RsaSha256));
        descriptor.Expires = null;
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
    }

    public string CreateTokenWithRealmRoles(string audience, string[] roles)
    {
        var descriptor = Descriptor(audience, DateTime.UtcNow.AddMinutes(5), new SigningCredentials(_key, SecurityAlgorithms.RsaSha256));
        descriptor.Claims = new Dictionary<string, object> { ["realm_access"] = new Dictionary<string, object> { ["roles"] = roles } };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();

    private SecurityTokenDescriptor Descriptor(string audience, DateTime expiresUtc, SigningCredentials? credentials) => new()
    {
        Issuer = $"{ServerUrl}/realms/{Realm}",
        Audience = audience,
        IssuedAt = expiresUtc.AddMinutes(-10),
        NotBefore = expiresUtc.AddMinutes(-10),
        Expires = expiresUtc,
        Subject = new ClaimsIdentity([new Claim("sub", "user-1")]),
        SigningCredentials = credentials,
    };

    private static string IssuerOf(HttpContext context) => $"{context.Request.Scheme}://{context.Request.Host}/realms/{Realm}";

    private static Dictionary<string, string> PublicJwk(RsaSecurityKey key)
    {
        var parameters = key.Rsa.ExportParameters(false);
        return new Dictionary<string, string>
        {
            ["kty"] = "RSA",
            ["use"] = "sig",
            ["alg"] = SecurityAlgorithms.RsaSha256,
            ["kid"] = KeyId,
            ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
            ["e"] = Base64UrlEncoder.Encode(parameters.Exponent),
        };
    }
}
