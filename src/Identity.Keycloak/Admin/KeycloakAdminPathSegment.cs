namespace Identity.Keycloak.Admin;

internal static class KeycloakAdminPathSegment
{
    private const string CurrentDirectory = ".";
    private const string ParentDirectory = "..";
    private static readonly char[] Separators = ['/', '\\'];

    public static bool AreSafe(IEnumerable<string?> segments) => segments.All(IsSafe);

    private static bool IsSafe(string? segment) =>
        !string.IsNullOrWhiteSpace(segment)
        && segment != CurrentDirectory
        && segment != ParentDirectory
        && segment.IndexOfAny(Separators) < 0;
}
