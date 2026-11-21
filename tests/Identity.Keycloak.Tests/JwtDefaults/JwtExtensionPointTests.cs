using System.Net;
using System.Security.Cryptography;
using Identity.Keycloak.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
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
    public async Task StartAsync_WithForgedHandlerPrependedToOnMessageReceived_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options =>
                options.Events.OnMessageReceived = (Func<MessageReceivedContext, Task>)Delegate.Combine(
                    new Func<MessageReceivedContext, Task>(ForgeTokenAsync),
                    options.Events.OnMessageReceived)));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("OnMessageReceived must be the package default");
    }

    [Fact]
    public async Task StartAsync_WithForgedHandlerPrependedToOnTokenValidated_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options =>
                options.Events.OnTokenValidated = (Func<TokenValidatedContext, Task>)Delegate.Combine(
                    new Func<TokenValidatedContext, Task>(_ => Task.CompletedTask),
                    options.Events.OnTokenValidated)));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("OnTokenValidated must be the package default");
    }

    [Theory]
    [InlineData("/")]
    [InlineData("")]
    public void AllowQueryStringToken_WithoutPathSegment_ThrowsArgument(string prefix)
    {
        var authentication = new ServiceCollection().AddAuthentication();

        var allow = () => authentication.AllowQueryStringToken(prefix);

        allow.ShouldThrow<ArgumentException>();
    }

    [Fact]
    public async Task StartAsync_WithServiceConfigurationManagerAtSameMetadataAddress_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        var metadataAddress = $"{keycloak.ServerUrl}/realms/{FakeKeycloak.Realm}/.well-known/openid-configuration";

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options =>
            {
                options.TokenValidationParameters.IssuerSigningKeyResolver = null;
                options.MetadataAddress = metadataAddress;
                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    metadataAddress,
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever { RequireHttps = false });
            }));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("ConfigurationManager must not be set outside Identity.Keycloak");
    }

    [Fact]
    public async Task StartAsync_WithPackageResolverRemoved_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, Audience),
            services: services => PostConfigureBearer(services, options =>
                options.TokenValidationParameters.IssuerSigningKeyResolver = null));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("IssuerSigningKeyResolver must be the package resolver");
    }

    [Fact]
    public async Task StartAsync_WithAuthenticationDisabledAndWeakServiceScheme_ThrowsOptionsValidation()
    {
        var start = () => JwtDefaultsHost.StartAsync(
            new Dictionary<string, string?>(StringComparer.Ordinal),
            services: services => JwtFloorTests.AddSecondScheme(services, validateIssuer: false),
            authenticationEnabled: false);

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("ValidateIssuer must be true");
    }

    private static void PostConfigureBearer(IServiceCollection services, Action<JwtBearerOptions> configure) =>
        services.PostConfigure(JwtBearerDefaults.AuthenticationScheme, configure);

    private static Task ForgeTokenAsync(MessageReceivedContext context)
    {
        context.Token = "forged";
        return Task.CompletedTask;
    }

    private sealed class ServiceEvents : JwtBearerEvents
    {
        public override Task TokenValidated(TokenValidatedContext context) => Task.CompletedTask;
    }
}
