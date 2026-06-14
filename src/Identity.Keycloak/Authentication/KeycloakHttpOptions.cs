namespace Identity.Keycloak.Authentication;

/// <summary>
/// HTTP transport options for every Keycloak <see cref="System.Net.Http.HttpClient"/>
/// used by a consuming service — realm-aware ROPC/admin clients and the
/// multi-realm JwtBearer backchannel (OIDC discovery + JWKS).
/// </summary>
/// <remarks>
/// <para>
/// Lives outside <c>KeycloakOptions</c> because this is a deploy-target concern:
/// a staging cluster may terminate HTTPS with a self-signed cert (no public ACME
/// path inside the cluster) while the same hostname must be reachable from APIs
/// running in the same cluster. .NET's default TLS validator rejects the
/// self-signed cert and surfaces it as <c>"Identity provider unreachable"</c>
/// with an <c>SslStream</c> handshake failure underneath.
/// </para>
/// <para>
/// <strong>Security note:</strong> setting <see cref="SkipCertValidation"/> to
/// <see langword="true"/> disables certificate validation for every outbound
/// Keycloak call. Acceptable only when caller and Keycloak live in the same K8s
/// cluster (the network is the trust boundary, not the TLS cert). It must never
/// be enabled in prod. The DI wire-up logs a loud warning at startup when the
/// flag is set and refuses to honor it unless the deploy target also opts in via
/// <see cref="AllowSkipCertValidationInProduction"/>.
/// </para>
/// </remarks>
public sealed class KeycloakHttpOptions
{
    /// <summary>
    /// Configuration section name — bound via
    /// <c>configuration.GetSection("Keycloak")</c>. Shares the <c>Keycloak</c>
    /// section with <c>ServerUrl</c> / <c>Authority</c> / <c>RequireHttpsMetadata</c>
    /// so per-deploy ConfigMap entries cluster together.
    /// </summary>
    public const string SectionName = "Keycloak";

    /// <summary>
    /// When <see langword="true"/>, every Keycloak HttpClient configures its
    /// <see cref="System.Net.Http.HttpClientHandler.ServerCertificateCustomValidationCallback"/>
    /// to accept ANY certificate. Default <see langword="false"/> applies the
    /// platform's default chain-of-trust validation.
    /// </summary>
    public bool SkipCertValidation { get; set; }

    /// <summary>
    /// Break-glass escape hatch for the rare case where
    /// <see cref="SkipCertValidation"/> must be honored on a deploy target the
    /// startup guard would otherwise classify as production. Defaults to
    /// <see langword="false"/> — if the guard ever trips on prod by accident, the
    /// fix is to flip <see cref="SkipCertValidation"/> back to
    /// <see langword="false"/>, not to flip this flag.
    /// </summary>
    public bool AllowSkipCertValidationInProduction { get; set; }
}
