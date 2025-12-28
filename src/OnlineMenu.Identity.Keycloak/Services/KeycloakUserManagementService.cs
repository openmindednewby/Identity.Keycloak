using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnlineMenu.Identity.Abstractions.Abstractions;
using OnlineMenu.Identity.Abstractions.Models;
using OnlineMenu.Identity.Keycloak.Configuration;

namespace OnlineMenu.Identity.Keycloak.Services;

/// <summary>
/// Keycloak implementation of user management service using Admin REST API
/// </summary>
public class KeycloakUserManagementService : IUserManagementService
{
    private readonly HttpClient _httpClient;
    private readonly KeycloakOptions _options;
    private readonly KeycloakAdminOptions _adminOptions;
    private readonly ILogger<KeycloakUserManagementService> _logger;

    public KeycloakUserManagementService(
        HttpClient httpClient,
        IOptions<KeycloakOptions> options,
        IOptions<KeycloakAdminOptions> adminOptions,
        ILogger<KeycloakUserManagementService> logger)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _adminOptions = adminOptions.Value;
        _logger = logger;
    }

    private async Task<string> GetAdminTokenAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Getting admin token from Keycloak. Endpoint: {Endpoint}, ClientId: {ClientId}",
            _options.TokenEndpoint, _adminOptions.AdminClientId);

        // Get admin token using client credentials
        var tokenRequest = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _adminOptions.AdminClientId,
            ["client_secret"] = _adminOptions.AdminClientSecret
        };

        var response = await _httpClient.PostAsync(
            _options.TokenEndpoint,
            new FormUrlEncodedContent(tokenRequest),
            cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogError("Failed to get admin token. Status: {Status}, Response: {Response}",
                response.StatusCode, errorContent);

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                _logger.LogError("Admin client credentials are invalid. Please configure KeycloakAdmin:AdminClientId and KeycloakAdmin:AdminClientSecret in appsettings.json");
            }
        }

        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<Dictionary<string, JsonElement>>(cancellationToken);
        _logger.LogInformation("Successfully obtained admin token");
        return result?["access_token"].GetString() ?? throw new Exception("Failed to get admin token");
    }

    private string GetAdminApiUrl(string path) =>
        $"{_options.Authority.Replace("/realms/", "/admin/realms/")}/{path}";

    public async Task<List<UserListItem>> GetUsersAsync(Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var url = GetAdminApiUrl("users");
            if (tenantId.HasValue)
            {
                url += $"?q=tenantId:{tenantId}";
            }

            var response = await _httpClient.GetAsync(url, cancellationToken);
            response.EnsureSuccessStatusCode();

            var users = await response.Content.ReadFromJsonAsync<List<KeycloakUser>>(cancellationToken);
            return users?.Select(MapToUserListItem).ToList() ?? new List<UserListItem>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get users");
            return new List<UserListItem>();
        }
    }

    public async Task<UserListItem?> GetUserByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var url = GetAdminApiUrl($"users/{userId}");
            var response = await _httpClient.GetAsync(url, cancellationToken);

            if (!response.IsSuccessStatusCode) return null;

            var user = await response.Content.ReadFromJsonAsync<KeycloakUser>(cancellationToken);
            return user != null ? MapToUserListItem(user) : null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user {UserId}", userId);
            return null;
        }
    }

    public async Task<string> CreateUserAsync(CreateUserRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var keycloakUser = new
            {
                username = request.Username,
                email = request.Email,
                firstName = request.FirstName,
                lastName = request.LastName,
                enabled = request.Enabled,
                attributes = new Dictionary<string, string[]>
                {
                    ["phoneNumber"] = new[] { request.PhoneNumber ?? string.Empty },
                    ["tenantId"] = request.TenantId.HasValue ? new[] { request.TenantId.Value.ToString() } : Array.Empty<string>()
                },
                credentials = !string.IsNullOrEmpty(request.Password) ? new[]
                {
                    new
                    {
                        type = "password",
                        value = request.Password,
                        temporary = false
                    }
                } : null
            };

            var url = GetAdminApiUrl("users");
            var response = await _httpClient.PostAsJsonAsync(url, keycloakUser, cancellationToken);
            response.EnsureSuccessStatusCode();

            // Get created user ID from Location header
            var location = response.Headers.Location?.ToString();
            var userId = location?.Split('/').Last() ?? throw new Exception("Failed to get user ID");

            // Assign roles if specified
            if (request.Roles.Any())
            {
                await AssignRolesAsync(userId, request.Roles, cancellationToken);
            }

            return userId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create user");
            throw;
        }
    }

    public async Task<bool> SetUserEnabledAsync(string userId, bool enabled, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var url = GetAdminApiUrl($"users/{userId}");
            var update = new { enabled };

            var response = await _httpClient.PutAsJsonAsync(url, update, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to set user enabled status");
            return false;
        }
    }

    public async Task<bool> DeleteUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var url = GetAdminApiUrl($"users/{userId}");
            var response = await _httpClient.DeleteAsync(url, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete user");
            return false;
        }
    }

    public async Task<bool> UpdatePasswordAsync(string userId, string newPassword, bool temporary = false, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var url = GetAdminApiUrl($"users/{userId}/reset-password");
            var credential = new
            {
                type = "password",
                value = newPassword,
                temporary
            };

            var response = await _httpClient.PutAsJsonAsync(url, credential, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update password");
            return false;
        }
    }

    public async Task<bool> AssignRolesAsync(string userId, List<string> roles, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // Get available realm roles
            var rolesUrl = GetAdminApiUrl("roles");
            var rolesResponse = await _httpClient.GetAsync(rolesUrl, cancellationToken);
            var availableRoles = await rolesResponse.Content.ReadFromJsonAsync<List<KeycloakRole>>(cancellationToken);

            // Filter to requested roles
            var rolesToAssign = availableRoles?.Where(r => roles.Contains(r.Name)).ToList() ?? new List<KeycloakRole>();

            if (!rolesToAssign.Any()) return true;

            var url = GetAdminApiUrl($"users/{userId}/role-mappings/realm");
            var response = await _httpClient.PostAsJsonAsync(url, rolesToAssign, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to assign roles");
            return false;
        }
    }

    public async Task<bool> RemoveRolesAsync(string userId, List<string> roles, CancellationToken cancellationToken = default)
    {
        try
        {
            var token = await GetAdminTokenAsync(cancellationToken);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            // Get user's current roles
            var url = GetAdminApiUrl($"users/{userId}/role-mappings/realm");
            var rolesResponse = await _httpClient.GetAsync(url, cancellationToken);
            var currentRoles = await rolesResponse.Content.ReadFromJsonAsync<List<KeycloakRole>>(cancellationToken);

            // Filter to roles we want to remove
            var rolesToRemove = currentRoles?.Where(r => roles.Contains(r.Name)).ToList() ?? new List<KeycloakRole>();

            if (!rolesToRemove.Any()) return true;

            var request = new HttpRequestMessage(HttpMethod.Delete, url)
            {
                Content = JsonContent.Create(rolesToRemove)
            };

            var response = await _httpClient.SendAsync(request, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove roles");
            return false;
        }
    }

    private static UserListItem MapToUserListItem(KeycloakUser user)
    {
        // Extract tenantId from Keycloak attributes
        string? tenantId = null;
        if (user.Attributes?.TryGetValue("tenantId", out var tenantIdValues) == true && tenantIdValues?.Length > 0)
        {
            tenantId = tenantIdValues[0];
        }

        return new UserListItem
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Enabled = user.Enabled,
            CreatedTimestamp = user.CreatedTimestamp.HasValue
                ? DateTimeOffset.FromUnixTimeMilliseconds(user.CreatedTimestamp.Value).DateTime
                : null,
            Roles = new List<string>(), // Roles would need separate call to fetch
            TenantId = tenantId
        };
    }

    // Internal Keycloak models
    private class KeycloakUser
    {
        public string Id { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string? Email { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public bool Enabled { get; set; }
        public long? CreatedTimestamp { get; set; }
        public Dictionary<string, string[]>? Attributes { get; set; }
    }

    private class KeycloakRole
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
    }
}
