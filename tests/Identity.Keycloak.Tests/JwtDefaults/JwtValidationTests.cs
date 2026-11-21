using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;

namespace Identity.Keycloak.Tests.JwtDefaults;

public class JwtValidationTests
{
    [Fact]
    public async Task Get_WithValidToken_Returns200()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await StartHostAsync(keycloak, "selida-api");
        var token = keycloak.CreateToken("selida-api", DateTime.UtcNow.AddMinutes(5));

        var response = await GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Get_WithTokenExpiredBeyondSkew_Returns401()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await StartHostAsync(keycloak, "selida-api");
        var token = keycloak.CreateToken("selida-api", DateTime.UtcNow.AddMinutes(-2));

        var response = await GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Get_WithWrongAudience_Returns401()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await StartHostAsync(keycloak, "selida-api");
        var token = keycloak.CreateToken("other-api", DateTime.UtcNow.AddMinutes(5));

        var response = await GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task StartAsync_WithoutAllowedRealms_ThrowsInvalidOperation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        var settings = JwtSettings(keycloak, "selida-api");
        settings.Remove("Authentication:AllowedRealms:0");

        var start = () => JwtDefaultsHost.StartAsync(settings);

        (await start.ShouldThrowAsync<InvalidOperationException>()).Message.ShouldBe("Authentication:AllowedRealms is required when Jwt:Authority is set.");
    }

    [Fact]
    public async Task Get_WithUnsignedAlgNoneToken_Returns401()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await StartHostAsync(keycloak, "selida-api");
        var token = keycloak.CreateUnsignedToken("selida-api");

        var response = await GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Get_WithTokenSignedByUnknownKey_Returns401()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await StartHostAsync(keycloak, "selida-api");
        var token = keycloak.CreateTokenSignedByUnknownKey("selida-api");

        var response = await GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task StartAsync_WithServicePostConfigureDisablingIssuerCheck_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtSettings(keycloak, "selida-api"),
            services: services => services.PostConfigure<JwtBearerOptions>(
                JwtBearerDefaults.AuthenticationScheme,
                options => options.TokenValidationParameters.ValidateIssuer = false));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("ValidateIssuer");
    }

    [Fact]
    public async Task StartAsync_WithServicePostConfigureTighteningClockSkew_Returns200()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(
            JwtSettings(keycloak, "selida-api"),
            services: services => services.PostConfigure<JwtBearerOptions>(
                JwtBearerDefaults.AuthenticationScheme,
                options => options.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(10)));
        var token = keycloak.CreateToken("selida-api", DateTime.UtcNow.AddMinutes(5));

        var response = await GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Theory]
    [InlineData("Development", true)]
    [InlineData("Staging", false)]
    [InlineData("Production", false)]
    public async Task Get_WithSkipCertValidationFlag_SkipsBackchannelCertsOnlyInDevelopment(string environmentName, bool skipped)
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        var settings = JwtSettings(keycloak, "selida-api");
        settings["Keycloak:SkipCertValidation"] = "true";
        await using var host = await JwtDefaultsHost.StartAsync(settings, environmentName);
        var token = keycloak.CreateToken("selida-api", DateTime.UtcNow.AddMinutes(5));

        await GetSecureAsync(host, token);

        host.Logs.Messages.Any(message => message.Contains("keycloak_cert_validation_disabled", StringComparison.Ordinal)).ShouldBe(skipped);
    }

    internal static Dictionary<string, string?> JwtSettings(FakeKeycloak keycloak, string audience) => new()
    {
        ["Jwt:Authority"] = $"{keycloak.ServerUrl}/realms/{FakeKeycloak.Realm}",
        ["Jwt:Audience"] = audience,
        ["Jwt:RequireHttpsMetadata"] = "false",
        ["Authentication:AllowedRealms:0"] = FakeKeycloak.Realm,
    };

    internal static async Task<HttpResponseMessage> GetSecureAsync(JwtDefaultsHost host, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, JwtDefaultsHost.SecurePath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await host.Client.SendAsync(request);
    }

    private static Task<JwtDefaultsHost> StartHostAsync(FakeKeycloak keycloak, string audience) => JwtDefaultsHost.StartAsync(JwtSettings(keycloak, audience));
}
