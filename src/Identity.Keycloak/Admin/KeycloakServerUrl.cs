namespace Identity.Keycloak.Admin;

public static class KeycloakServerUrl
{
    private const string RealmsSegment = "/realms/";

    /// <summary>The explicit server URL without a trailing slash, else the part of the authority before /realms/.</summary>
    public static string Resolve(string? configuredServerUrl, string? authority)
    {
        if (!string.IsNullOrWhiteSpace(configuredServerUrl))
            return configuredServerUrl.TrimEnd('/');
        if (string.IsNullOrWhiteSpace(authority))
            return string.Empty;
        var index = authority.IndexOf(RealmsSegment, StringComparison.OrdinalIgnoreCase);
        return index > 0 ? authority[..index] : authority.TrimEnd('/');
    }

    /// <summary>The realm named by an authority such as https://host/realms/kefi, or null.</summary>
    public static string? RealmFromAuthority(string? authority)
    {
        if (string.IsNullOrWhiteSpace(authority))
            return null;
        var index = authority.IndexOf(RealmsSegment, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
            return null;
        var realm = authority[(index + RealmsSegment.Length)..].Trim('/').Split('/')[0];
        return realm.Length == 0 ? null : realm;
    }
}
