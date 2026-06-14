using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Keycloak.Authentication;

/// <summary>
/// Configures JwtBearer to accept tokens issued by any realm in a supplied
/// allow-list.
/// </summary>
/// <remarks>
/// <para>
/// JwtBearer's default <c>Authority</c>-based discovery can only target a single
/// realm — but services that serve every product's apps (e.g. Tenant,
/// Notification) must accept tokens from every allowed realm. This helper:
/// </para>
/// <list type="number">
///   <item><description>
///     Builds a per-realm OIDC <see cref="ConfigurationManager{T}"/> which lazily
///     fetches the realm's discovery document + JWKS, caches it, and refreshes on
///     a long interval (default 24h).
///   </description></item>
///   <item><description>
///     Sets <see cref="TokenValidationParameters.IssuerValidator"/> to resolve the
///     token's <c>iss</c> against the realm-issuer URLs. Mismatches throw
///     <see cref="SecurityTokenInvalidIssuerException"/> (surfaced as 401).
///   </description></item>
///   <item><description>
///     Sets <see cref="TokenValidationParameters.IssuerSigningKeyResolver"/> to ask
///     the matching realm's <see cref="ConfigurationManager{T}"/> for its current
///     signing keys, so JWKS keys for every realm are reachable.
///   </description></item>
/// </list>
/// <para>
/// A cross-realm authorization wall (owned per-service) is still required after
/// this — it re-checks the token's realm against the per-deployment allow-list.
/// This helper only widens the JWT validation surface; the wall remains the
/// security boundary.
/// </para>
/// </remarks>
public static class MultiRealmJwtBearerExtensions
{
    /// <summary>
    /// Default OIDC discovery refresh interval. 24h is a typical Keycloak
    /// signing-key rotation window — JWKS updates land within that.
    /// </summary>
    private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromHours(24);

    /// <summary>
    /// Configures the supplied <see cref="JwtBearerOptions"/> to accept tokens
    /// issued by any realm in <paramref name="allowedRealms"/>. Each realm's OIDC
    /// metadata is fetched from <c>{serverUrl}/realms/{realm}</c>.
    /// </summary>
    /// <param name="options">The JwtBearer options being configured.</param>
    /// <param name="serverUrl">The Keycloak base URL (no realm).</param>
    /// <param name="allowedRealms">The realm names to accept tokens from.</param>
    /// <param name="requireHttpsMetadata">Whether OIDC discovery is HTTPS-only.</param>
    /// <param name="backchannelHttpClient">
    /// Optional <see cref="HttpClient"/> for OIDC discovery + JWKS fetch. Supply a
    /// cert-skip-configured client when the realm is reachable only via a
    /// self-signed in-cluster cert (staging). When <see langword="null"/>, the
    /// default <c>HttpDocumentRetriever</c> HttpClient is used.
    /// </param>
    public static void ConfigureMultiRealm(
        this JwtBearerOptions options,
        string serverUrl,
        IReadOnlyList<string> allowedRealms,
        bool requireHttpsMetadata,
        HttpClient? backchannelHttpClient = null)
    {
        if (string.IsNullOrWhiteSpace(serverUrl))
        {
            throw new ArgumentException("serverUrl is required", nameof(serverUrl));
        }
        if (allowedRealms == null || allowedRealms.Count == 0)
        {
            throw new ArgumentException("At least one allowed realm is required", nameof(allowedRealms));
        }

        var trimmedServerUrl = serverUrl.TrimEnd('/');
        var realmConfigs = BuildRealmConfigs(
            trimmedServerUrl,
            allowedRealms,
            requireHttpsMetadata,
            backchannelHttpClient);

        // Disable default Authority-driven discovery — we manage our own
        // ConfigurationManagers per realm.
        options.Authority = null;
        options.RequireHttpsMetadata = requireHttpsMetadata;

        var validIssuers = CollectIssuers(realmConfigs);

        options.TokenValidationParameters ??= new TokenValidationParameters();
        options.TokenValidationParameters.ValidateIssuer = true;
        options.TokenValidationParameters.ValidIssuers = validIssuers;
        options.TokenValidationParameters.ValidateIssuerSigningKey = true;
        options.TokenValidationParameters.ValidateLifetime = true;
        options.TokenValidationParameters.IssuerValidator = MakeIssuerValidator(realmConfigs);
        options.TokenValidationParameters.IssuerSigningKeyResolver = MakeIssuerSigningKeyResolver(realmConfigs);
    }

    private static List<string> CollectIssuers(List<RealmConfig> realmConfigs)
    {
        var validIssuers = new List<string>(realmConfigs.Count);
        foreach (var rc in realmConfigs)
        {
            validIssuers.Add(rc.Issuer);
        }
        return validIssuers;
    }

    private static IssuerValidator MakeIssuerValidator(List<RealmConfig> realmConfigs)
    {
        return (issuer, _, _) =>
        {
            for (var i = 0; i < realmConfigs.Count; i++)
            {
                if (string.Equals(realmConfigs[i].Issuer, issuer, StringComparison.Ordinal))
                {
                    return realmConfigs[i].Issuer;
                }
            }
            throw new SecurityTokenInvalidIssuerException($"Issuer '{issuer}' is not on the allow-list.");
        };
    }

    private static IssuerSigningKeyResolver MakeIssuerSigningKeyResolver(List<RealmConfig> realmConfigs)
    {
        return (_, securityToken, _, _) =>
        {
            var issuer = securityToken?.Issuer;
            if (string.IsNullOrEmpty(issuer))
            {
                return Array.Empty<SecurityKey>();
            }

            for (var i = 0; i < realmConfigs.Count; i++)
            {
                if (!string.Equals(realmConfigs[i].Issuer, issuer, StringComparison.Ordinal))
                {
                    continue;
                }
                var config = realmConfigs[i].ConfigurationManager
                    .GetConfigurationAsync(CancellationToken.None)
                    .GetAwaiter().GetResult();
                return config.SigningKeys;
            }
            return Array.Empty<SecurityKey>();
        };
    }

    private static List<RealmConfig> BuildRealmConfigs(
        string serverUrl,
        IReadOnlyList<string> allowedRealms,
        bool requireHttpsMetadata,
        HttpClient? backchannelHttpClient)
    {
        var configs = new List<RealmConfig>(allowedRealms.Count);
        for (var i = 0; i < allowedRealms.Count; i++)
        {
            var realm = allowedRealms[i];
            if (string.IsNullOrWhiteSpace(realm))
            {
                continue;
            }

            var issuer = $"{serverUrl}/realms/{realm}";
            var metadataAddress = $"{issuer}/.well-known/openid-configuration";

            // When a custom backchannel HttpClient is supplied (typically cert-skip for
            // self-signed in-cluster traffic), feed it to HttpDocumentRetriever.
            var documentRetriever = backchannelHttpClient is null
                ? new HttpDocumentRetriever { RequireHttps = requireHttpsMetadata }
                : new HttpDocumentRetriever(backchannelHttpClient) { RequireHttps = requireHttpsMetadata };
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                documentRetriever)
            {
                AutomaticRefreshInterval = DefaultRefreshInterval,
            };

            configs.Add(new RealmConfig(realm, issuer, configManager));
        }
        return configs;
    }

    private sealed record RealmConfig(
        string Realm,
        string Issuer,
        ConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager);
}
