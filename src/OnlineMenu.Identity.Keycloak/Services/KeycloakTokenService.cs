using IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OnlineMenu.Identity.Abstractions.Exceptions;
using OnlineMenu.Identity.Abstractions.Models;
using Identity.Keycloak.Configuration;
using System.Net.Http.Json;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;

namespace Identity.Keycloak.Services;

/// <summary>
/// Service for Keycloak token operations
/// </summary>
public class KeycloakTokenService
{
    private readonly HttpClient _httpClient;
    private readonly KeycloakOptions _options;
    private readonly ILogger<KeycloakTokenService> _logger;

    public KeycloakTokenService(
        HttpClient httpClient,
        IOptions<KeycloakOptions> options,
        ILogger<KeycloakTokenService> logger)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Authenticate using Resource Owner Password Credentials (ROPC) flow
    /// </summary>
    public async Task<TokenResponse> AuthenticateWithPasswordAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        var request = new PasswordTokenRequest
        {
            Address = _options.TokenEndpoint,
            ClientId = _options.ClientId,
            ClientSecret = _options.ClientSecret,
            UserName = username,
            Password = password,
            Scope = "openid profile email"
        };

        var response = await _httpClient.RequestPasswordTokenAsync(request, cancellationToken);

        if (response.IsError)
        {
            throw new InvalidCredentialsException(
                response.Error ?? "Authentication failed");
        }

        return response;
    }

    /// <summary>
    /// Refresh an access token using a refresh token
    /// </summary>
    public async Task<TokenResponse> RefreshTokenAsync(
        string refreshToken,
        CancellationToken cancellationToken = default)
    {
        var request = new RefreshTokenRequest
        {
            Address = _options.TokenEndpoint,
            ClientId = _options.ClientId,
            ClientSecret = _options.ClientSecret,
            RefreshToken = refreshToken
        };

        var response = await _httpClient.RequestRefreshTokenAsync(request, cancellationToken);

        if (response.IsError)
        {
            throw new InvalidTokenException(
                response.Error ?? "Token refresh failed");
        }

        return response;
    }

    /// <summary>
    /// Revoke a token (access or refresh)
    /// </summary>
    public async Task<bool> RevokeTokenAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        var request = new TokenRevocationRequest
        {
            Address = _options.RevocationEndpoint,
            ClientId = _options.ClientId,
            ClientSecret = _options.ClientSecret,
            Token = token
        };

        var response = await _httpClient.RevokeTokenAsync(request, cancellationToken);

        return !response.IsError;
    }

    /// <summary>
    /// Get user information from an access token
    /// </summary>
    public async Task<UserInfo?> GetUserInfoAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Fetching user info from endpoint: {Endpoint}", _options.UserInfoEndpoint);

        var request = new UserInfoRequest
        {
            Address = _options.UserInfoEndpoint,
            Token = accessToken
        };

        var response = await _httpClient.GetUserInfoAsync(request, cancellationToken);

        if (response.IsError)
        {
            _logger.LogError("GetUserInfoAsync failed. Error: {Error}, Raw: {Raw}",
                response.Error, response.Raw);
            return null;
        }

        _logger.LogInformation("Successfully received user info response with {ClaimCount} claims",
            response.Claims?.Count() ?? 0);

        var userInfo = MapToUserInfo(response);

        _logger.LogInformation("Mapped user info: Sub={Sub}, Email={Email}, Username={Username}, InitialRoleCount={RoleCount}",
            userInfo.Sub, userInfo.Email, userInfo.Username, userInfo.Roles.Count);

        // If no roles found from UserInfo endpoint, try extracting from JWT token
        if (userInfo.Roles.Count == 0)
        {
            _logger.LogInformation("No roles found in UserInfo response, attempting to extract from JWT token");
            var rolesFromToken = ExtractRolesFromToken(accessToken);
            if (rolesFromToken.Any())
            {
                _logger.LogInformation("Extracted {RoleCount} roles from JWT token: {Roles}",
                    rolesFromToken.Count, string.Join(", ", rolesFromToken));
                userInfo.Roles = rolesFromToken;
            }
            else
            {
                _logger.LogWarning("No roles found in JWT token either");
            }
        }
        else
        {
            _logger.LogInformation("Found {RoleCount} roles in UserInfo response: {Roles}",
                userInfo.Roles.Count, string.Join(", ", userInfo.Roles));
        }

        return userInfo;
    }

    /// <summary>
    /// Exchange OTP verification for a token using client credentials
    /// This creates a token for a user identified by phone/email
    /// </summary>
    public async Task<TokenResponse> ExchangeForTokenAsync(
        string subject,
        CancellationToken cancellationToken = default)
    {
        // Use client credentials flow to get a token
        // In production, you might want to use token exchange (RFC 8693)
        // or create the user in Keycloak first, then use password flow

        var request = new ClientCredentialsTokenRequest
        {
            Address = _options.TokenEndpoint,
            ClientId = _options.ClientId,
            ClientSecret = _options.ClientSecret,
            Scope = "openid profile email"
        };

        var response = await _httpClient.RequestClientCredentialsTokenAsync(request, cancellationToken);

        if (response.IsError)
        {
            throw new AuthenticationException(
                response.Error ?? "Token exchange failed");
        }

        return response;
    }

    private UserInfo MapToUserInfo(IdentityModel.Client.UserInfoResponse response)
    {
        var userInfo = new UserInfo
        {
            Sub = response.Claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? string.Empty,
            Username = response.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value,
            Email = response.Claims.FirstOrDefault(c => c.Type == "email")?.Value,
            EmailVerified = bool.TryParse(
                response.Claims.FirstOrDefault(c => c.Type == "email_verified")?.Value,
                out var emailVerified) && emailVerified,
            PhoneNumber = response.Claims.FirstOrDefault(c => c.Type == "phone_number")?.Value,
            PhoneNumberVerified = bool.TryParse(
                response.Claims.FirstOrDefault(c => c.Type == "phone_number_verified")?.Value,
                out var phoneVerified) && phoneVerified,
            GivenName = response.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value,
            FamilyName = response.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value,
            Name = response.Claims.FirstOrDefault(c => c.Type == "name")?.Value,
            PreferredUsername = response.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
        };

        // Extract roles from Keycloak claims
        // Try multiple approaches as Keycloak can return roles in different formats

        // 1. Try realm_access as a JSON string (some Keycloak versions)
        var realmAccessClaim = response.Claims.FirstOrDefault(c => c.Type == "realm_access")?.Value;
        if (!string.IsNullOrEmpty(realmAccessClaim))
        {
            try
            {
                var realmAccess = JsonSerializer.Deserialize<JsonElement>(realmAccessClaim);
                if (realmAccess.TryGetProperty("roles", out var rolesElement))
                {
                    userInfo.Roles = rolesElement.EnumerateArray()
                        .Select(r => r.GetString())
                        .Where(r => !string.IsNullOrEmpty(r))
                        .Cast<string>()
                        .ToList();
                }
            }
            catch
            {
                // Ignore JSON parsing errors
            }
        }

        // 2. If no roles found, try resource_access (client-specific roles)
        if (userInfo.Roles.Count == 0)
        {
            var resourceAccessClaim = response.Claims.FirstOrDefault(c => c.Type == "resource_access")?.Value;
            if (!string.IsNullOrEmpty(resourceAccessClaim))
            {
                try
                {
                    var resourceAccess = JsonSerializer.Deserialize<JsonElement>(resourceAccessClaim);
                    // Look for roles in the client (using ClientId)
                    if (resourceAccess.TryGetProperty(_options.ClientId, out var clientAccess))
                    {
                        if (clientAccess.TryGetProperty("roles", out var rolesElement))
                        {
                            userInfo.Roles = rolesElement.EnumerateArray()
                                .Select(r => r.GetString())
                                .Where(r => !string.IsNullOrEmpty(r))
                                .Cast<string>()
                                .ToList();
                        }
                    }
                }
                catch
                {
                    // Ignore JSON parsing errors
                }
            }
        }

        // 3. If still no roles, try looking for individual role claims
        if (userInfo.Roles.Count == 0)
        {
            var roleClaims = response.Claims
                .Where(c => c.Type == "role" || c.Type == "roles")
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrEmpty(v))
                .ToList();

            if (roleClaims.Any())
            {
                userInfo.Roles = roleClaims;
            }
        }

        // Extract tenantId from claims
        var tenantIdClaim = response.Claims.FirstOrDefault(c => c.Type == "tenantId")?.Value;
        if (!string.IsNullOrEmpty(tenantIdClaim) && Guid.TryParse(tenantIdClaim, out var tenantId))
        {
            userInfo.TenantId = tenantId;
        }

        return userInfo;
    }

    /// <summary>
    /// Extract roles from JWT access token
    /// </summary>
    private List<string> ExtractRolesFromToken(string accessToken)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(accessToken);

            var roles = new List<string>();

            // Try to find realm_access.roles
            var realmAccessClaim = token.Claims.FirstOrDefault(c => c.Type == "realm_access");
            if (realmAccessClaim != null)
            {
                try
                {
                    var realmAccess = JsonSerializer.Deserialize<JsonElement>(realmAccessClaim.Value);
                    if (realmAccess.TryGetProperty("roles", out var rolesElement))
                    {
                        roles.AddRange(rolesElement.EnumerateArray()
                            .Select(r => r.GetString())
                            .Where(r => !string.IsNullOrEmpty(r))
                            .Cast<string>());
                    }
                }
                catch
                {
                    // Ignore JSON parsing errors
                }
            }

            // Try to find resource_access (client-specific roles)
            if (roles.Count == 0)
            {
                var resourceAccessClaim = token.Claims.FirstOrDefault(c => c.Type == "resource_access");
                if (resourceAccessClaim != null)
                {
                    try
                    {
                        var resourceAccess = JsonSerializer.Deserialize<JsonElement>(resourceAccessClaim.Value);
                        if (resourceAccess.TryGetProperty(_options.ClientId, out var clientAccess))
                        {
                            if (clientAccess.TryGetProperty("roles", out var rolesElement))
                            {
                                roles.AddRange(rolesElement.EnumerateArray()
                                    .Select(r => r.GetString())
                                    .Where(r => !string.IsNullOrEmpty(r))
                                    .Cast<string>());
                            }
                        }
                    }
                    catch
                    {
                        // Ignore JSON parsing errors
                    }
                }
            }

            // Try to find individual role claims
            if (roles.Count == 0)
            {
                roles.AddRange(token.Claims
                    .Where(c => c.Type == "role" || c.Type == "roles")
                    .Select(c => c.Value)
                    .Where(v => !string.IsNullOrEmpty(v)));
            }

            return roles;
        }
        catch
        {
            return new List<string>();
        }
    }
}
