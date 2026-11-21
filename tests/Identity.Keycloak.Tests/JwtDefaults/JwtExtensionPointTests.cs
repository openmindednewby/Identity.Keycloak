using System.Net;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;

namespace Identity.Keycloak.Tests.JwtDefaults;

public class JwtExtensionPointTests
{
    [Fact]
    public async Task StartAsync_WithServiceAudienceValidator_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, "selida-api"),
            services: services => PostConfigureBearer(services, options =>
                options.TokenValidationParameters.AudienceValidator = (_, _, _) => true));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("AudienceValidator");
    }

    [Fact]
    public async Task StartAsync_WithServiceOnAuthenticationFailed_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, "selida-api"),
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
    public async Task Get_WithServiceOnTokenValidated_Returns200()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, "selida-api"),
            services: services => PostConfigureBearer(services, options =>
                options.Events = new JwtBearerEvents { OnTokenValidated = _ => Task.CompletedTask }));
        var token = keycloak.CreateToken("selida-api", DateTime.UtcNow.AddMinutes(5));

        var response = await JwtValidationTests.GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
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
}
