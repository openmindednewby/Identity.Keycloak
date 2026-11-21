using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Keycloak.Authentication;

public static class KeycloakJwtDefaults
{
    internal const string AuthorityKey = "Jwt:Authority";

    internal const string AudienceKey = "Jwt:Audience";

    internal const string RequireHttpsMetadataKey = "Jwt:RequireHttpsMetadata";

    internal const string AllowedRealmsKey = "Authentication:AllowedRealms";

    internal const string PlatformRealmKey = "Authentication:PlatformRealm";

    internal const string PrivilegedRolesKey = "Authentication:PrivilegedRoles";

    internal const string IdentityAuthenticationType = "Keycloak.JwtBearer";

    internal static readonly TimeSpan MaxClockSkew = TimeSpan.FromSeconds(30);

    internal static readonly string[] AllowedAlgorithms = [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.EcdsaSha256];

    /// <summary>Binds Keycloak JWT settings and maps realm roles to role claims; startup fails when any JwtBearer scheme is below the floor.</summary>
    public static AuthenticationBuilder AddKeycloakJwtDefaults(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment,
        bool authenticationEnabled = true)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        var authority = configuration[AuthorityKey];
        if (string.IsNullOrWhiteSpace(authority))
        {
            return AddWithoutAuthentication(services, authenticationEnabled);
        }

        var audience = configuration[AudienceKey];
        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new InvalidOperationException($"{AudienceKey} is required when {AuthorityKey} is set.");
        }

        if (RealmsOf(configuration).Length == 0)
        {
            throw new InvalidOperationException($"{AllowedRealmsKey} is required when {AuthorityKey} is set.");
        }

        var authentication = services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<ILoggerFactory>((options, loggerFactory) =>
                ConfigureJwtBearer(options, configuration, BackchannelFor(configuration, environment, loggerFactory)))
            .ValidateOnStart();
        services.AddOptions<KeycloakRoleMappingOptions>().Configure(options => ConfigureRoleMapping(options, configuration));
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClaimsTransformation, KeycloakRealmRoleClaimsTransformation>());
        AddFloor(services);
        return authentication;
    }

    internal static void ConfigurePrivilegedRoles(KeycloakRoleMappingOptions options, IConfiguration configuration)
    {
        options.PlatformRealm = configuration[PlatformRealmKey];
        var privilegedRoles = configuration.GetSection(PrivilegedRolesKey).Get<string[]>();
        if (privilegedRoles is { Length: > 0 })
        {
            options.PrivilegedRoles = privilegedRoles;
        }
    }

    private static AuthenticationBuilder AddWithoutAuthentication(IServiceCollection services, bool authenticationEnabled)
    {
        if (authenticationEnabled)
        {
            throw new InvalidOperationException(
                $"{AuthorityKey} is required; a service without authentication must switch authentication off with a reason.");
        }

        AddFloor(services);
        return services.AddAuthentication(NoAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, NoAuthenticationHandler>(NoAuthenticationHandler.SchemeName, _ => { });
    }

    private static void AddFloor(IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<JwtBearerOptions>, JwtBearerFloorValidator>());
        services.AddHostedService<JwtBearerSchemesStartupCheck>();
    }

    private static void ConfigureJwtBearer(JwtBearerOptions options, IConfiguration configuration, HttpClient? backchannel)
    {
        var authority = configuration[AuthorityKey];
        var audience = configuration[AudienceKey];
        var requireHttpsMetadata = configuration.GetValue(RequireHttpsMetadataKey, true);
        KeycloakOwnedValidators.Mark(options);
        options.MapInboundClaims = false;
        options.ConfigureMultiRealm(KeycloakClaimsHelper.DeriveServerUrl(authority)!, RealmsOf(configuration), requireHttpsMetadata, backchannel);
        options.Audience = audience;
        options.Events = new KeycloakJwtBearerEvents();
        var parameters = options.TokenValidationParameters;
        parameters.ValidAudience = audience;
        parameters.ValidateAudience = true;
        parameters.RequireSignedTokens = true;
        parameters.RequireExpirationTime = true;
        parameters.ClockSkew = MaxClockSkew;
        parameters.ValidAlgorithms = AllowedAlgorithms;
        parameters.AuthenticationType = IdentityAuthenticationType;
    }

    private static void ConfigureRoleMapping(KeycloakRoleMappingOptions options, IConfiguration configuration)
    {
        options.AllowedRealms = RealmsOf(configuration);
        ConfigurePrivilegedRoles(options, configuration);
    }

    private static string[] RealmsOf(IConfiguration configuration) =>
        configuration.GetSection(AllowedRealmsKey).Get<string[]>() ?? [];

    private static HttpClient? BackchannelFor(IConfiguration configuration, IHostEnvironment environment, ILoggerFactory loggerFactory)
    {
        if (!environment.IsDevelopment())
        {
            return null;
        }

        var logger = loggerFactory.CreateLogger(nameof(KeycloakJwtDefaults));
        return KeycloakHttpClientExtensions.LogAndCheckCertValidationFlag(configuration, logger)
            ? KeycloakHttpClientExtensions.CreateBackchannelHttpClient(configuration)
            : null;
    }
}
