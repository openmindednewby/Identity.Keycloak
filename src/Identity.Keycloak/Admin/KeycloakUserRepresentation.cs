namespace Identity.Keycloak.Admin;

/// <summary>The Keycloak Admin REST user representation; null members are omitted on writes.</summary>
public sealed class KeycloakUserRepresentation
{
    public string? Id { get; set; }

    public string? Username { get; set; }

    public string? Email { get; set; }

    public string? FirstName { get; set; }

    public string? LastName { get; set; }

    public bool? Enabled { get; set; }

    public bool? EmailVerified { get; set; }

    public long? CreatedTimestamp { get; set; }

    public Dictionary<string, List<string>>? Attributes { get; set; }

    public List<KeycloakCredentialRepresentation>? Credentials { get; set; }

    public List<string>? RequiredActions { get; set; }

    public string? FirstAttribute(string key)
    {
        if (Attributes is null || !Attributes.TryGetValue(key, out var values) || values is null || values.Count == 0)
            return null;
        return string.IsNullOrEmpty(values[0]) ? null : values[0];
    }
}
