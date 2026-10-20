using System.Text.Json;

namespace Identity.Keycloak.Admin;

public static class KeycloakAdminErrorParser
{
    private static readonly string[] MessageFields = ["errorMessage", "error_description", "error"];

    /// <summary>The first of errorMessage, error_description or error in a Keycloak error body, or null.</summary>
    public static string? Parse(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return null;
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;
            return MessageFields
                .Select(field => root.TryGetProperty(field, out var value) && value.ValueKind == JsonValueKind.String
                    ? value.GetString()
                    : null)
                .FirstOrDefault(message => !string.IsNullOrEmpty(message));
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
