using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace Identity.Keycloak.Admin;

public sealed class KeycloakAdminClient : IKeycloakAdminClient
{
    private const string AccessTokenField = "access_token";
    private const string RealmRolesPath = "roles";
    private const string UnsafePathSegmentMessage = "Realm and user id must be non-empty and must not be '.', '..' or contain a path separator.";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _httpClient;
    private readonly KeycloakAdminClientOptions _options;
    private readonly string _serverUrl;

    public KeycloakAdminClient(HttpClient httpClient, IOptions<KeycloakAdminClientOptions> options)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _serverUrl = KeycloakServerUrl.Resolve(_options.ServerUrl, _options.Authority);
    }

    public async Task<string> GetAdminTokenAsync(CancellationToken cancellationToken = default)
    {
        var tokenRequest = KeycloakAdminTokenRequest.From(_options);
        var endpoint = $"{_serverUrl}/realms/{Uri.EscapeDataString(tokenRequest.Realm)}/protocol/openid-connect/token";
        using var content = new FormUrlEncodedContent(tokenRequest.Form);
        using var response = await _httpClient.PostAsync(endpoint, content, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException(
                $"Keycloak admin token request failed with {(int)response.StatusCode}: {await ReadErrorAsync(response, cancellationToken)}",
                null,
                response.StatusCode);

        var payload = await response.Content.ReadFromJsonAsync<Dictionary<string, JsonElement>>(JsonOptions, cancellationToken);
        var hasToken = payload is not null
            && payload.TryGetValue(AccessTokenField, out var token)
            && token.ValueKind == JsonValueKind.String
            && !string.IsNullOrEmpty(token.GetString());
        return hasToken
            ? payload![AccessTokenField].GetString()!
            : throw new HttpRequestException("Keycloak admin token response had no access_token.");
    }

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string realm, string relativePath, HttpContent? content = null, CancellationToken cancellationToken = default)
    {
        var token = await GetAdminTokenAsync(cancellationToken);
        return await SendWithTokenAsync(token, method, realm, relativePath, content, cancellationToken);
    }

    public async Task<KeycloakAdminResult<IReadOnlyList<KeycloakUserRepresentation>>> ListUsersAsync(string realm, KeycloakUserQuery query, CancellationToken cancellationToken = default) =>
        AsReadOnly(await ExecuteValueAsync(token => ReadAsync<List<KeycloakUserRepresentation>>(token, realm, "users" + query.ToQueryString(), cancellationToken), cancellationToken, realm));

    public Task<KeycloakAdminResult<KeycloakUserRepresentation>> GetUserAsync(string realm, string userId, CancellationToken cancellationToken = default) =>
        ExecuteValueAsync(token => ReadAsync<KeycloakUserRepresentation>(token, realm, UserPath(userId), cancellationToken), cancellationToken, realm, userId);

    public Task<KeycloakAdminResult<string>> CreateUserAsync(string realm, KeycloakUserRepresentation user, CancellationToken cancellationToken = default) =>
        ExecuteValueAsync(token => PostUserAsync(token, realm, user, cancellationToken), cancellationToken, realm);

    public Task<KeycloakAdminResult> UpdateUserAsync(string realm, string userId, KeycloakUserRepresentation user, CancellationToken cancellationToken = default) =>
        WriteAsync(HttpMethod.Put, realm, UserPath(userId), user, cancellationToken, userId);

    public Task<KeycloakAdminResult> DeleteUserAsync(string realm, string userId, CancellationToken cancellationToken = default) =>
        WriteAsync(HttpMethod.Delete, realm, UserPath(userId), null, cancellationToken, userId);

    public Task<KeycloakAdminResult> ResetPasswordAsync(string realm, string userId, KeycloakCredentialRepresentation credential, CancellationToken cancellationToken = default) =>
        WriteAsync(HttpMethod.Put, realm, $"{UserPath(userId)}/reset-password", credential, cancellationToken, userId);

    public Task<KeycloakAdminResult> LogoutUserAsync(string realm, string userId, CancellationToken cancellationToken = default) =>
        WriteAsync(HttpMethod.Post, realm, $"{UserPath(userId)}/logout", null, cancellationToken, userId);

    public async Task<KeycloakAdminResult<IReadOnlyList<KeycloakRoleRepresentation>>> ListRealmRolesAsync(string realm, CancellationToken cancellationToken = default) =>
        AsReadOnly(await ExecuteValueAsync(token => ReadAsync<List<KeycloakRoleRepresentation>>(token, realm, RealmRolesPath, cancellationToken), cancellationToken, realm));

    public async Task<KeycloakAdminResult<IReadOnlyList<KeycloakRoleRepresentation>>> GetUserRealmRolesAsync(string realm, string userId, CancellationToken cancellationToken = default) =>
        AsReadOnly(await ExecuteValueAsync(token => ReadAsync<List<KeycloakRoleRepresentation>>(token, realm, RoleMappingsPath(userId), cancellationToken), cancellationToken, realm, userId));

    public Task<KeycloakAdminResult> AddUserRealmRolesAsync(string realm, string userId, IEnumerable<string> roleNames, CancellationToken cancellationToken = default) =>
        ExecuteAsync(token => ChangeRoleMappingsAsync(token, HttpMethod.Post, realm, userId, RealmRolesPath, roleNames, cancellationToken), cancellationToken, realm, userId);

    public Task<KeycloakAdminResult> RemoveUserRealmRolesAsync(string realm, string userId, IEnumerable<string> roleNames, CancellationToken cancellationToken = default) =>
        ExecuteAsync(token => ChangeRoleMappingsAsync(token, HttpMethod.Delete, realm, userId, RoleMappingsPath(userId), roleNames, cancellationToken), cancellationToken, realm, userId);

    private async Task<KeycloakAdminResult<string>> PostUserAsync(string token, string realm, KeycloakUserRepresentation user, CancellationToken cancellationToken)
    {
        using var response = await SendWithTokenAsync(token, HttpMethod.Post, realm, "users", JsonContent.Create(WithProfileNames(user), options: JsonOptions), cancellationToken);
        if (!response.IsSuccessStatusCode)
            return await FailureAsync<string>(response, cancellationToken);

        var userId = response.Headers.Location?.OriginalString
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .LastOrDefault();
        return string.IsNullOrEmpty(userId)
            ? KeycloakAdminResult<string>.Failure(KeycloakAdminOutcome.UpstreamError, response.StatusCode, "Keycloak created the user without a Location header.")
            : KeycloakAdminResult<string>.Success(userId);
    }

    private async Task<KeycloakAdminResult> ChangeRoleMappingsAsync(
        string token,
        HttpMethod method,
        string realm,
        string userId,
        string candidatesPath,
        IEnumerable<string> roleNames,
        CancellationToken cancellationToken)
    {
        var candidates = await ReadAsync<List<KeycloakRoleRepresentation>>(token, realm, candidatesPath, cancellationToken);
        if (!candidates.IsSuccess)
            return KeycloakAdminResult.Failure(candidates.Outcome, candidates.StatusCode, candidates.ErrorMessage);

        var wanted = new HashSet<string>(roleNames, StringComparer.Ordinal);
        var selected = candidates.Value!.Where(role => wanted.Contains(role.Name)).ToList();
        if (selected.Count == 0)
            return KeycloakAdminResult.Success();
        return await SendAndMapAsync(token, method, realm, RoleMappingsPath(userId), selected, cancellationToken);
    }

    private Task<KeycloakAdminResult> WriteAsync(HttpMethod method, string realm, string path, object? body, CancellationToken cancellationToken, string userId) =>
        ExecuteAsync(token => SendAndMapAsync(token, method, realm, path, body, cancellationToken), cancellationToken, realm, userId);

    private async Task<KeycloakAdminResult> SendAndMapAsync(string token, HttpMethod method, string realm, string path, object? body, CancellationToken cancellationToken)
    {
        var content = body is null ? null : JsonContent.Create(body, body.GetType(), options: JsonOptions);
        using var response = await SendWithTokenAsync(token, method, realm, path, content, cancellationToken);
        return response.IsSuccessStatusCode
            ? KeycloakAdminResult.Success()
            : KeycloakAdminResult.Failure(KeycloakAdminResult.OutcomeFor(response.StatusCode), response.StatusCode, await ReadErrorAsync(response, cancellationToken));
    }

    private async Task<KeycloakAdminResult<T>> ReadAsync<T>(string token, string realm, string path, CancellationToken cancellationToken)
    {
        using var response = await SendWithTokenAsync(token, HttpMethod.Get, realm, path, null, cancellationToken);
        if (!response.IsSuccessStatusCode)
            return await FailureAsync<T>(response, cancellationToken);

        var value = await response.Content.ReadFromJsonAsync<T>(JsonOptions, cancellationToken);
        return value is null
            ? KeycloakAdminResult<T>.Failure(KeycloakAdminOutcome.UpstreamError, response.StatusCode, "Keycloak returned an empty body.")
            : KeycloakAdminResult<T>.Success(value);
    }

    private async Task<HttpResponseMessage> SendWithTokenAsync(string token, HttpMethod method, string realm, string relativePath, HttpContent? content, CancellationToken cancellationToken)
    {
        var url = $"{_serverUrl}/admin/realms/{Uri.EscapeDataString(realm)}/{relativePath.TrimStart('/')}";
        using var request = new HttpRequestMessage(method, url) { Content = content };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _httpClient.SendAsync(request, cancellationToken);
    }

    private async Task<KeycloakAdminResult<T>> ExecuteValueAsync<T>(Func<string, Task<KeycloakAdminResult<T>>> call, CancellationToken cancellationToken, params string[] pathSegments)
    {
        if (!KeycloakAdminPathSegment.AreSafe(pathSegments))
            return KeycloakAdminResult<T>.Failure(KeycloakAdminOutcome.BadRequest, null, UnsafePathSegmentMessage);
        try
        {
            return await call(await GetAdminTokenAsync(cancellationToken));
        }
        catch (HttpRequestException ex)
        {
            return KeycloakAdminResult<T>.Failure(KeycloakAdminOutcome.UpstreamError, ex.StatusCode, ex.Message);
        }
        catch (JsonException ex)
        {
            return KeycloakAdminResult<T>.Failure(KeycloakAdminOutcome.UpstreamError, null, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return KeycloakAdminResult<T>.Failure(KeycloakAdminOutcome.UpstreamError, null, ex.Message);
        }
    }

    private async Task<KeycloakAdminResult> ExecuteAsync(Func<string, Task<KeycloakAdminResult>> call, CancellationToken cancellationToken, params string[] pathSegments)
    {
        if (!KeycloakAdminPathSegment.AreSafe(pathSegments))
            return KeycloakAdminResult.Failure(KeycloakAdminOutcome.BadRequest, null, UnsafePathSegmentMessage);
        try
        {
            return await call(await GetAdminTokenAsync(cancellationToken));
        }
        catch (HttpRequestException ex)
        {
            return KeycloakAdminResult.Failure(KeycloakAdminOutcome.UpstreamError, ex.StatusCode, ex.Message);
        }
        catch (JsonException ex)
        {
            return KeycloakAdminResult.Failure(KeycloakAdminOutcome.UpstreamError, null, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return KeycloakAdminResult.Failure(KeycloakAdminOutcome.UpstreamError, null, ex.Message);
        }
    }

    private static async Task<KeycloakAdminResult<T>> FailureAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken) =>
        KeycloakAdminResult<T>.Failure(KeycloakAdminResult.OutcomeFor(response.StatusCode), response.StatusCode, await ReadErrorAsync(response, cancellationToken));

    private static async Task<string?> ReadErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken) =>
        KeycloakAdminErrorParser.Parse(await response.Content.ReadAsStringAsync(cancellationToken));

    private static KeycloakAdminResult<IReadOnlyList<T>> AsReadOnly<T>(KeycloakAdminResult<List<T>> result) =>
        result.IsSuccess
            ? KeycloakAdminResult<IReadOnlyList<T>>.Success(result.Value!)
            : KeycloakAdminResult<IReadOnlyList<T>>.Failure(result.Outcome, result.StatusCode, result.ErrorMessage);

    private static KeycloakUserRepresentation WithProfileNames(KeycloakUserRepresentation user)
    {
        var missingName = string.IsNullOrWhiteSpace(user.FirstName) || string.IsNullOrWhiteSpace(user.LastName);
        if (!missingName || string.IsNullOrWhiteSpace(user.Email))
            return user;
        var (firstName, lastName) = KeycloakProfileNames.FromEmail(user.Email);
        return new KeycloakUserRepresentation
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            FirstName = string.IsNullOrWhiteSpace(user.FirstName) ? firstName : user.FirstName,
            LastName = string.IsNullOrWhiteSpace(user.LastName) ? lastName : user.LastName,
            Enabled = user.Enabled,
            EmailVerified = user.EmailVerified,
            CreatedTimestamp = user.CreatedTimestamp,
            Attributes = user.Attributes,
            Credentials = user.Credentials,
            RequiredActions = user.RequiredActions,
        };
    }

    private static string UserPath(string userId) => $"users/{Uri.EscapeDataString(userId)}";

    private static string RoleMappingsPath(string userId) => $"{UserPath(userId)}/role-mappings/realm";
}
