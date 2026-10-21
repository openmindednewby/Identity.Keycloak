using Identity.Keycloak.Admin;

namespace Identity.Keycloak.Tests.Admin;

public class KeycloakAdminHelpersTests
{
    [Fact]
    public void Resolve_WithConfiguredUrl_TrimsTrailingSlash()
    {
        var configured = "https://kc.test/";

        var serverUrl = KeycloakServerUrl.Resolve(configured, "https://other/realms/kefi");

        Assert.Equal("https://kc.test", serverUrl);
    }

    [Fact]
    public void Resolve_WithAuthorityOnly_KeepsPathBeforeRealms()
    {
        var authority = "https://kc.test/auth/realms/kefi";

        var serverUrl = KeycloakServerUrl.Resolve(null, authority);

        Assert.Equal("https://kc.test/auth", serverUrl);
    }

    [Fact]
    public void RealmFromAuthority_WithRealmAuthority_ReturnsRealm()
    {
        var authority = "https://kc.test/realms/questioner/";

        var realm = KeycloakServerUrl.RealmFromAuthority(authority);

        Assert.Equal("questioner", realm);
    }

    [Fact]
    public void Parse_WithErrorDescriptionOnly_ReturnsDescription()
    {
        var body = "{\"error_description\":\"Invalid client credentials\"}";

        var message = KeycloakAdminErrorParser.Parse(body);

        Assert.Equal("Invalid client credentials", message);
    }

    [Fact]
    public void Parse_WithNonJsonBody_ReturnsNull()
    {
        var body = "<html>bad gateway</html>";

        var message = KeycloakAdminErrorParser.Parse(body);

        Assert.Null(message);
    }

    [Fact]
    public void FromEmail_WithDottedLocalPart_SplitsFirstAndRest()
    {
        var email = "ana.maria.LOPEZ@example.com";

        var (firstName, lastName) = KeycloakProfileNames.FromEmail(email);

        Assert.Equal("Ana", firstName);
        Assert.Equal("Maria Lopez", lastName);
    }

    [Fact]
    public void FromEmail_WithOnlySeparators_ReturnsPlaceholders()
    {
        var email = "._@example.com";

        var (firstName, lastName) = KeycloakProfileNames.FromEmail(email);

        Assert.Equal("Member", firstName);
        Assert.Equal("Account", lastName);
    }

    [Theory]
    [InlineData("smoke@dloizides.com", "Smoke")]
    [InlineData("info@example.com", "Info")]
    [InlineData("HELLO@example.com", "Hello")]
    public void FromEmail_WithoutSeparator_RepeatsLocalPartInBothFields(string email, string expected)
    {
        var (firstName, lastName) = KeycloakProfileNames.FromEmail(email);

        Assert.Equal(expected, firstName);
        Assert.Equal(expected, lastName);
    }

    [Theory]
    [InlineData("jane_smith@example.com", "Jane", "Smith")]
    [InlineData("alex-rivera@example.com", "Alex", "Rivera")]
    [InlineData("dev+test@example.com", "Dev", "Test")]
    public void FromEmail_WithNonDotSeparator_SplitsFirstAndLast(string email, string expectedFirst, string expectedLast)
    {
        var (firstName, lastName) = KeycloakProfileNames.FromEmail(email);

        Assert.Equal(expectedFirst, firstName);
        Assert.Equal(expectedLast, lastName);
    }

    [Theory]
    [InlineData("a@b.com")]
    [InlineData("a.b@c.com")]
    [InlineData("...@example.com")]
    [InlineData("single@example.com")]
    [InlineData("_@example.com")]
    [InlineData("no-at-sign")]
    public void FromEmail_WithAnyInput_ReturnsNonEmptyFields(string email)
    {
        var (firstName, lastName) = KeycloakProfileNames.FromEmail(email);

        Assert.False(string.IsNullOrEmpty(firstName));
        Assert.False(string.IsNullOrEmpty(lastName));
    }

    [Fact]
    public void ToQueryString_WithoutFilters_ReturnsEmpty()
    {
        var query = new KeycloakUserQuery();

        var queryString = query.ToQueryString();

        Assert.Equal(string.Empty, queryString);
    }
}
