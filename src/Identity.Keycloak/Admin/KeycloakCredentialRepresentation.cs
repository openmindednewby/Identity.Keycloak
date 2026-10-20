namespace Identity.Keycloak.Admin;

public sealed class KeycloakCredentialRepresentation
{
    public const string PasswordType = "password";

    public string Type { get; set; } = PasswordType;

    public string Value { get; set; } = string.Empty;

    public bool Temporary { get; set; }

    public static KeycloakCredentialRepresentation Password(string value, bool temporary) =>
        new() { Type = PasswordType, Value = value, Temporary = temporary };
}
