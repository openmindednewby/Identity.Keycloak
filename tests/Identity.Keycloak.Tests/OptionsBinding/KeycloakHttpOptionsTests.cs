using Identity.Keycloak.Authentication;
using Microsoft.Extensions.Configuration;
using Shouldly;

namespace Identity.Keycloak.Tests.OptionsBinding;

public class KeycloakHttpOptionsTests
{
    [Fact]
    public void From_WithKeycloakSection_BindsEveryValue()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Keycloak:SkipCertValidation"] = "true",
            ["Keycloak:AllowSkipCertValidationInProduction"] = "true",
            ["Keycloak:ServerUrl"] = "https://keycloak.local",
        }).Build();

        var options = KeycloakHttpOptions.From(configuration);

        options.SkipCertValidation.ShouldBeTrue();
        options.AllowSkipCertValidationInProduction.ShouldBeTrue();
        options.ServerUrl.ShouldBe("https://keycloak.local");
    }

    [Fact]
    public void From_WithoutKeycloakSection_KeepsCertValidationOn()
    {
        var configuration = new ConfigurationBuilder().Build();

        var options = KeycloakHttpOptions.From(configuration);

        options.SkipCertValidation.ShouldBeFalse();
        options.AllowSkipCertValidationInProduction.ShouldBeFalse();
        options.ServerUrl.ShouldBeNull();
    }
}
