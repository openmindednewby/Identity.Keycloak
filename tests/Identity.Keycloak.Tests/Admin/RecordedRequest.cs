namespace Identity.Keycloak.Tests.Admin;

internal sealed record RecordedRequest(HttpMethod Method, string Url, string? Authorization, string? Body);
