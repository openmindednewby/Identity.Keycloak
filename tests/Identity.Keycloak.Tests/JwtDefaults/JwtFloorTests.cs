using System.Net;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Shouldly;

namespace Identity.Keycloak.Tests.JwtDefaults;

public class JwtFloorTests
{
    private const string SecondScheme = "Canary";

    [Fact]
    public async Task StartAsync_WithSecondSchemeDisablingIssuerCheck_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, "selida-api"),
            services: services => AddSecondScheme(services, validateIssuer: false));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("ValidateIssuer must be true");
    }

    [Fact]
    public async Task StartAsync_WithFloorCompliantSecondScheme_Returns200()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();
        await using var host = await JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, "selida-api"),
            services: services => AddSecondScheme(services, validateIssuer: true));
        var token = keycloak.CreateToken("selida-api", DateTime.UtcNow.AddMinutes(5));

        var response = await JwtValidationTests.GetSecureAsync(host, token);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task StartAsync_WithServiceSetSignatureValidator_ThrowsOptionsValidation()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        var start = () => JwtDefaultsHost.StartAsync(
            JwtValidationTests.JwtSettings(keycloak, "selida-api"),
            services: services => services.PostConfigure<JwtBearerOptions>(
                JwtBearerDefaults.AuthenticationScheme,
                options => options.TokenValidationParameters.SignatureValidator = (token, _) => new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(token)));

        (await start.ShouldThrowAsync<OptionsValidationException>()).Message.ShouldContain("SignatureValidator");
    }

    [Fact]
    public async Task StartAsync_WithPackageMultiRealmIssuerValidator_KeepsIssuerValidator()
    {
        await using var keycloak = await FakeKeycloak.StartAsync();

        await using var host = await JwtDefaultsHost.StartAsync(JwtValidationTests.JwtSettings(keycloak, "selida-api"));

        host.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters.IssuerValidator.ShouldNotBeNull();
    }

    [Fact]
    public async Task StartAsync_WithoutAuthorityAndAuthenticationEnabled_ThrowsInvalidOperation()
    {
        var start = () => JwtDefaultsHost.StartAsync(new Dictionary<string, string?>());

        (await start.ShouldThrowAsync<InvalidOperationException>()).Message.ShouldContain("Jwt:Authority");
    }

    [Fact]
    public async Task Get_WithoutAuthorityAndAuthenticationDisabled_Returns401()
    {
        await using var host = await JwtDefaultsHost.StartAsync(new Dictionary<string, string?>(), authenticationEnabled: false);

        var response = await host.Client.GetAsync(JwtDefaultsHost.SecurePath);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    private static void AddSecondScheme(IServiceCollection services, bool validateIssuer) =>
        services.AddAuthentication().AddJwtBearer(SecondScheme, options =>
        {
            var parameters = options.TokenValidationParameters;
            parameters.ValidateIssuer = validateIssuer;
            parameters.ValidateIssuerSigningKey = true;
            parameters.ClockSkew = TimeSpan.FromSeconds(10);
            parameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256];
        });
}
