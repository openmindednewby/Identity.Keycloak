using System.Net;
using System.Security.Cryptography;
using Identity.Keycloak.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shouldly;

namespace Identity.Keycloak.Tests.JwtDefaults;

public class JwtExtensionPointTests
{
    private const string Audience = "selida-api";

    [Fact]
    public async Task StartAsync_WithServiceAudienceValidator_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options =>
                options.TokenValidationParameters.AudienceValidator = (_, _, _) => true));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("AudienceValidator");
    }

    [Fact]
    public async Task StartAsync_WithServiceOnAuthenticationFailed_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options =>
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        context.NoResult();
                        return Task.CompletedTask;
                    },
                }));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("OnAuthenticationFailed");
    }

    [Fact]
    public async Task StartAsync_WithServiceOnTokenValidated_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options =>
                options.Events = new JwtBearerEvents { OnTokenValidated = _ => Task.CompletedTask }));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("OnTokenValidated");
    }

    [Fact]
    public async Task StartAsync_WithServiceEventsType_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options => options.EventsType = typeof(ServiceEvents)));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("EventsType");
    }

    [Fact]
    public async Task Get_WithQueryStringTokenUnderAllowedPrefix_Returns200()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => services.AddAuthentication().AllowQueryStringToken(JwtDefaultsHost.SecurePath));
        var token = keycloak.CreateToken(Audience, DateTime.UtcNow.AddMinutes(5));

        var response = await host.Client.GetAsync($"{JwtDefaultsHost.SecurePath}?access_token={token}");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Get_WithQueryStringTokenWithoutAllowedPrefix_Returns401()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => services.AddAuthentication().AllowQueryStringToken("/hubs/notifications"));
        var token = keycloak.CreateToken(Audience, DateTime.UtcNow.AddMinutes(5));

        var response = await host.Client.GetAsync($"{JwtDefaultsHost.SecurePath}?access_token={token}");

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task StartAsync_WithServiceIssuerSigningKey_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options =>
                options.TokenValidationParameters.IssuerSigningKey = new RsaSecurityKey(RSA.Create(2048))));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("IssuerSigningKey");
    }

    [Fact]
    public async Task Get_WithUnknownKeyId_Returns401()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(JwtValidationTests.JwtSettings(keycloak, Audience));
        var token = keycloak.CreateTokenWithKeyId(Audience, "unknown-kid");

        var response = await JwtValidationTests.GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task StartAsync_WithServiceRequireExpirationTimeFalse_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options =>
                options.TokenValidationParameters.RequireExpirationTime = false));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("RequireExpirationTime must be true");
    }

    [Fact]
    public async Task Get_WithTokenWithoutExpiry_Returns401()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(JwtValidationTests.JwtSettings(keycloak, Audience));
        var token = keycloak.CreateTokenWithoutExpiry(Audience);

        var response = await JwtValidationTests.GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task StartAsync_WithAuthenticationDisabledAndWeakServiceScheme_ThrowsOptionsValidation()
    {
        var start = () => JwtDefaultsHost.StartAsync(
            new Dictionary<string, string?>(),
            services: services => JwtFloorTests.AddSecondScheme(services, validateIssuer: false),
            authenticationEnabled: false);

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("ValidateIssuer must be true");
    }

    private static void PostConfigureBearer(IServiceCollection services, Action<JwtBearerOptions> configure) =>
        services.PostConfigure(JwtBearerDefaults.AuthenticationScheme, configure);

    private sealed class ServiceEvents : JwtBearerEvents
    {
        public override Task TokenValidated(TokenValidatedContext context) => Task.CompletedTask;
    }
}
