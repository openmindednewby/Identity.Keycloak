using System.Net;

namespace Identity.Keycloak.Admin;

/// <summary>Outcome of one Keycloak Admin REST call, with the upstream status and error text on failure.</summary>
public class KeycloakAdminResult
{
    protected KeycloakAdminResult(KeycloakAdminOutcome outcome, HttpStatusCode? statusCode, string? errorMessage)
    {
        Outcome = outcome;
        StatusCode = statusCode;
        ErrorMessage = errorMessage;
    }

    public KeycloakAdminOutcome Outcome { get; }

    public HttpStatusCode? StatusCode { get; }

    public string? ErrorMessage { get; }

    public bool IsSuccess => Outcome == KeycloakAdminOutcome.Success;

    public static KeycloakAdminResult Success() => new(KeycloakAdminOutcome.Success, null, null);

    public static KeycloakAdminResult Failure(KeycloakAdminOutcome outcome, HttpStatusCode? statusCode, string? errorMessage) =>
        new(outcome, statusCode, errorMessage);

    public static KeycloakAdminOutcome OutcomeFor(HttpStatusCode statusCode) => statusCode switch
    {
        HttpStatusCode.NotFound => KeycloakAdminOutcome.NotFound,
        HttpStatusCode.Conflict => KeycloakAdminOutcome.Conflict,
        HttpStatusCode.BadRequest => KeycloakAdminOutcome.BadRequest,
        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => KeycloakAdminOutcome.AccessDenied,
        _ => KeycloakAdminOutcome.UpstreamError,
    };
}
