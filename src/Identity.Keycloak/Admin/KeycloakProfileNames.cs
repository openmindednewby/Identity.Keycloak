namespace Identity.Keycloak.Admin;

public static class KeycloakProfileNames
{
    public const string PlaceholderFirstName = "Member";

    public const string PlaceholderLastName = "Account";

    private static readonly char[] Separators = ['.', '_', '-', '+'];

    /// <summary>First and last name from an email local part; Keycloak refuses login to a user without them.</summary>
    public static (string FirstName, string LastName) FromEmail(string email)
    {
        var atIndex = email.IndexOf('@');
        var localPart = atIndex > 0 ? email[..atIndex] : email;
        var pieces = localPart
            .Split(Separators, StringSplitOptions.RemoveEmptyEntries)
            .Select(TitleCase)
            .ToArray();
        if (pieces.Length == 0)
            return (PlaceholderFirstName, PlaceholderLastName);
        if (pieces.Length == 1)
            return (pieces[0], pieces[0]);
        return (pieces[0], string.Join(" ", pieces.Skip(1)));
    }

    private static string TitleCase(string value) =>
        char.ToUpperInvariant(value[0]) + value[1..].ToLowerInvariant();
}
