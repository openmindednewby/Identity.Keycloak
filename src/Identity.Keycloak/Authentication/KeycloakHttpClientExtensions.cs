using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Identity.Keycloak.Authentication;

/// <summary>
/// Helpers that configure a Keycloak-targeted <see cref="HttpClient"/> (or raw
/// <see cref="HttpClientHandler"/>) to optionally skip TLS certificate
/// validation, gated by <see cref="KeycloakHttpOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// Centralises the "should we skip cert validation" decision so all Keycloak
/// HTTP consumers (ROPC client, admin client, JwtBearer OIDC backchannel) honor
/// the same env-gate. New consumers should funnel through this helper rather than
/// reading the option directly.
/// </para>
/// <para>
/// The startup guard <see cref="LogAndCheckCertValidationFlag"/> emits a loud
/// warning every time the flag is honored and refuses to honor it when the host
/// is classified as production (unless the break-glass
/// <see cref="KeycloakHttpOptions.AllowSkipCertValidationInProduction"/> is set).
/// The classifier inspects <c>Keycloak:ServerUrl</c> for the well-known prod
/// hostname rather than <c>ASPNETCORE_ENVIRONMENT</c>, because every SaaS API runs
/// with <c>ASPNETCORE_ENVIRONMENT=Production</c> on both staging and prod clusters
/// — the environment-name signal is uninformative and the hostname is the actual
/// deploy-target indicator.
/// </para>
/// </remarks>
public static class KeycloakHttpClientExtensions
{
    /// <summary>
    /// Hostname of the public production Keycloak. Any <c>Keycloak:ServerUrl</c>
    /// pointing here is treated as prod regardless of <c>ASPNETCORE_ENVIRONMENT</c>.
    /// </summary>
    private const string ProdKeycloakHost = "identity.dloizides.com";

    /// <summary>
    /// Registers an <see cref="HttpClient"/> for the typed client
    /// <typeparamref name="TClient"/>, attaching an <see cref="HttpClientHandler"/>
    /// whose <see cref="HttpClientHandler.ServerCertificateCustomValidationCallback"/>
    /// returns <see langword="true"/> when (and only when)
    /// <see cref="KeycloakHttpOptions.SkipCertValidation"/> is set and the startup
    /// guard accepts the deploy target.
    /// </summary>
    public static IHttpClientBuilder AddKeycloakHttpClient<TClient>(
        this IServiceCollection services,
        IConfiguration configuration)
        where TClient : class
    {
        var options = ReadKeycloakHttpOptions(configuration);
        var skipCertValidation = ShouldSkipCertValidation(options, configuration);

        return services
            .AddHttpClient<TClient>()
            .ConfigurePrimaryHttpMessageHandler(() => CreateHandler(skipCertValidation));
    }

    /// <summary>
    /// Returns an <see cref="HttpClient"/> wired with the same cert-skip policy as
    /// the typed Keycloak clients, suitable for the JwtBearer backchannel's
    /// <c>HttpDocumentRetriever</c> (OIDC discovery + JWKS fetch).
    /// </summary>
    public static HttpClient CreateBackchannelHttpClient(IConfiguration configuration)
    {
        var options = ReadKeycloakHttpOptions(configuration);
        var skipCertValidation = ShouldSkipCertValidation(options, configuration);
        return new HttpClient(CreateHandler(skipCertValidation), disposeHandler: true);
    }

    /// <summary>
    /// Emits a loud startup warning when <c>SkipCertValidation=true</c> and throws
    /// when the deploy target is classified as production without the break-glass
    /// flag set. Returns the effective value of the flag.
    /// </summary>
    public static bool LogAndCheckCertValidationFlag(
        IConfiguration configuration,
        ILogger logger)
    {
        var options = ReadKeycloakHttpOptions(configuration);
        if (!options.SkipCertValidation)
        {
            return false;
        }

        var serverUrl = configuration["Keycloak:ServerUrl"];
        var looksLikeProduction = LooksLikeProductionHost(serverUrl);
        if (looksLikeProduction && !options.AllowSkipCertValidationInProduction)
        {
            throw new InvalidOperationException(
                $"Keycloak:SkipCertValidation=true rejected for production-shaped "
                + $"deploy target (Keycloak:ServerUrl='{serverUrl}'). "
                + "If this is truly an emergency, also set "
                + "Keycloak:AllowSkipCertValidationInProduction=true. "
                + "Otherwise set SkipCertValidation=false.");
        }

#pragma warning disable CA1848 // High-perf logging not required for startup warning
        logger.LogWarning(
            "keycloak_cert_validation_disabled "
            + "serverUrl={ServerUrl} looksLikeProduction={LooksLikeProduction} "
            + "allowInProduction={AllowInProduction} — "
            + "every outbound Keycloak HTTPS call accepts ANY certificate. "
            + "This is acceptable only for self-signed in-cluster traffic.",
            serverUrl,
            looksLikeProduction,
            options.AllowSkipCertValidationInProduction);
#pragma warning restore CA1848

        return true;
    }

    private static KeycloakHttpOptions ReadKeycloakHttpOptions(IConfiguration configuration)
    {
        var options = new KeycloakHttpOptions();
        configuration.GetSection(KeycloakHttpOptions.SectionName).Bind(options);
        return options;
    }

    private static bool ShouldSkipCertValidation(
        KeycloakHttpOptions options,
        IConfiguration configuration)
    {
        if (!options.SkipCertValidation)
        {
            return false;
        }

        var serverUrl = configuration["Keycloak:ServerUrl"];
        if (LooksLikeProductionHost(serverUrl)
            && !options.AllowSkipCertValidationInProduction)
        {
            // The startup guard (LogAndCheckCertValidationFlag) will throw on boot —
            // return false here so this helper never silently wires the lax handler if
            // a caller forgets to invoke the guard.
            return false;
        }

        return true;
    }

    private static bool LooksLikeProductionHost(string? serverUrl)
    {
        if (string.IsNullOrWhiteSpace(serverUrl))
        {
            return false;
        }
        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out var uri))
        {
            return false;
        }
        // A subdomain like `staging.identity.dloizides.com` MUST NOT match — require
        // an exact host match (case-insensitive) on the prod hostname.
        return string.Equals(uri.Host, ProdKeycloakHost, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Constructs the primary <see cref="HttpClientHandler"/> for a Keycloak
    /// HttpClient. When <paramref name="skipCertValidation"/> is
    /// <see langword="true"/>, the handler's server-cert callback returns
    /// <see langword="true"/> for any cert.
    /// </summary>
#pragma warning disable S4830 // Server-cert validation disabled by design — see KeycloakHttpOptions remarks
    private static HttpClientHandler CreateHandler(bool skipCertValidation)
    {
        var handler = new HttpClientHandler();
        if (skipCertValidation)
        {
            handler.ServerCertificateCustomValidationCallback =
                static (_, _, _, _) => true;
        }
        return handler;
    }
#pragma warning restore S4830
}
