using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text.Json;

namespace Identity.Keycloak.Services;

internal static class KeycloakUserRealmRoleReader
{
    private const int MaxConcurrentRequests = 8;

    public static async Task<IReadOnlyDictionary<string, List<string>>> ReadAsync(
        HttpClient httpClient,
        Func<string, string> adminApiUrl,
        IReadOnlyCollection<string> userIds,
        CancellationToken cancellationToken)
    {
        var rolesByUser = new ConcurrentDictionary<string, List<string>>();
        var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = MaxConcurrentRequests, CancellationToken = cancellationToken };
        await Parallel.ForEachAsync(userIds.Distinct(), parallelOptions, async (userId, ct) =>
            rolesByUser[userId] = await ReadUserRolesAsync(httpClient, adminApiUrl, userId, ct));
        return rolesByUser;
    }

    private static async Task<List<string>> ReadUserRolesAsync(
        HttpClient httpClient,
        Func<string, string> adminApiUrl,
        string userId,
        CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(adminApiUrl($"users/{userId}/role-mappings/realm"), cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new KeycloakRoleLookupException(userId, response.StatusCode);
        try
        {
            var roles = await response.Content.ReadFromJsonAsync<List<RoleMapping>>(cancellationToken);
            return roles?.Select(r => r.Name).ToList() ?? throw new KeycloakRoleLookupException(userId, response.StatusCode);
        }
        catch (JsonException ex)
        {
            throw new KeycloakRoleLookupException(userId, response.StatusCode, ex);
        }
    }

    private sealed record RoleMapping(string Name);
}
