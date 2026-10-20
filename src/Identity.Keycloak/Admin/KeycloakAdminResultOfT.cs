using System.Net;

namespace Identity.Keycloak.Admin;

/// <summary>Outcome of one Keycloak Admin REST call that returns a value on success.</summary>
public sealed class KeycloakAdminResult<T> : KeycloakAdminResult
{
    private KeycloakAdminResult(KeycloakAdminOutcome outcome, HttpStatusCode? statusCode, string? errorMessage, T? value)
        : base(outcome, statusCode, errorMessage)
    {
        Value = value;
    }

    public T? Value { get; }

    public static KeycloakAdminResult<T> Success(T value) => new(KeycloakAdminOutcome.Success, null, null, value);

    public static new KeycloakAdminResult<T> Failure(KeycloakAdminOutcome outcome, HttpStatusCode? statusCode, string? errorMessage) =>
        new(outcome, statusCode, errorMessage, default);
}
