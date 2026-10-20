using System.Globalization;

namespace Identity.Keycloak.Admin;

/// <summary>Filters for GET /admin/realms/{realm}/users; unset members are not sent.</summary>
public sealed class KeycloakUserQuery
{
    public string? Search { get; init; }

    public string? Username { get; init; }

    public string? Email { get; init; }

    public bool? Exact { get; init; }

    public string? AttributeQuery { get; init; }

    public int? First { get; init; }

    public int? Max { get; init; }

    public bool? BriefRepresentation { get; init; }

    public string ToQueryString()
    {
        var pairs = new List<KeyValuePair<string, string>>();
        Add(pairs, "search", Search);
        Add(pairs, "username", Username);
        Add(pairs, "email", Email);
        Add(pairs, "exact", Lower(Exact));
        Add(pairs, "q", AttributeQuery);
        Add(pairs, "first", First?.ToString(CultureInfo.InvariantCulture));
        Add(pairs, "max", Max?.ToString(CultureInfo.InvariantCulture));
        Add(pairs, "briefRepresentation", Lower(BriefRepresentation));
        return pairs.Count == 0
            ? string.Empty
            : "?" + string.Join("&", pairs.Select(pair => $"{pair.Key}={Uri.EscapeDataString(pair.Value)}"));
    }

    private static string? Lower(bool? value) => value.HasValue ? (value.Value ? "true" : "false") : null;

    private static void Add(List<KeyValuePair<string, string>> pairs, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            pairs.Add(new KeyValuePair<string, string>(key, value));
    }
}
