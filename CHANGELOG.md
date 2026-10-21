# Changelog — Identity.Keycloak

All notable changes to this package.

> **Honest header:** this file starts at **1.8.0**. Versions 1.0.0–1.7.0 predate it and
> were never changelogged; reconstruct them from `git log` if needed. Created during the
> NuGet drift backlog (Wave 2b), where a *missing* changelog on a sibling package was the
> thing that blocked an upgrade for a full session.

## [1.10.2] - 2026-10-21

### Fixed
- `KeycloakAdminClient` (EXTRACT-CS-KCADMIN-1 "Add a Keycloak admin REST client to Identity.Keycloak"): the admin token is reused
  until 30 s before its `expires_in`, instead of one token request per admin call (a user list plus N role reads was 1 + N token
  requests, now 1). New singleton `KeycloakAdminTokenCache`, keyed per server URL, token realm, grant and client/user, thread-safe
  (one fetch per key under concurrency); registered by `AddKeycloakAdminClient`, honours a registered `TimeProvider`. A token
  response without `expires_in` is not cached.

## [1.10.1] - 2026-10-21

### Fixed
- `KeycloakAdminClient` (EXTRACT-CS-KCADMIN-1 "Add a Keycloak admin REST client to Identity.Keycloak" review fixes): a realm or
  user id that is empty, `.`, `..` or contains `/` or `\` now returns `BadRequest` (no status code) without sending any request;
  before, `..` collapsed `DELETE users/..` onto the realm URL.
- Missing admin credentials now return `UpstreamError` from every typed call instead of throwing `InvalidOperationException`.
- `CreateUserAsync` no longer writes derived first/last names into the caller's `KeycloakUserRepresentation`.
- `AddKeycloakAdminClient` validates that `KeycloakAdmin:ServerUrl`, `KeycloakAdmin:Authority` or `Keycloak:Authority` resolves to an
  absolute http(s) URL (`ValidateOnStart`), so a missing server URL fails at startup, not on the first admin call.

## [1.10.0] - 2026-10-21

### Added
- `Identity.Keycloak.Admin`: `IKeycloakAdminClient` / `KeycloakAdminClient`, a typed Keycloak Admin REST client for any realm
  (EXTRACT-CS-KCADMIN-1 "Add a Keycloak admin REST client to Identity.Keycloak"). Admin token by client_credentials in a
  configurable realm or by the master-realm password grant (`PreferMasterAdminPassword`, `MasterAdminClientId`); users
  list/get/create/update/delete, reset password, logout, realm roles list/get/add/remove; every call returns
  `KeycloakAdminResult` (NotFound / Conflict / BadRequest / AccessDenied / UpstreamError). Create fills a missing first or
  last name from the email, because Keycloak refuses login without them.
- `AddKeycloakAdminClient(configuration)` binds section `KeycloakAdmin` and registers the client through
  `IHttpClientFactory` with the shared cert-skip policy (new `AddKeycloakHttpClient<TClient, TImplementation>`).
- Helpers: `KeycloakServerUrl`, `KeycloakAdminErrorParser`, `KeycloakProfileNames`, `KeycloakUserQuery`.
- First test project, `tests/Identity.Keycloak.Tests` (22 tests, fake `HttpMessageHandler`).

No dependency change: `Identity.Abstractions` stays 1.7.1.

## [1.8.0] — 2026-08-23

### Changed
- `Identity.Abstractions` **1.6.2 → 1.7.1**. Verified additive before bumping: the only
  source change across that range is `TenantManagedRoleSet` (a new class + its tests),
  with **zero removed lines under `src/`**. No API of this package changes.

### Removed
- The explicit `PackageReference Microsoft.Extensions.Http 8.0.1`.

  Not cosmetic. This project carries `<FrameworkReference Include="Microsoft.AspNetCore.App" />`,
  which already ships `Microsoft.Extensions.Http`, so the reference was redundant locally
  (**NU1510**) — but it was also written into the **published nuspec**, handing every
  consumer a NuGet dependency on the 8.0.1 package alongside a net10 shared framework that
  already provides it. Removal is safe for consumers because `FrameworkReference` flows
  transitively; the package still compiles with `HttpClient`/`AddHttpClient` in use, which
  is what proves the framework supplies it. Build went **2 warnings → 0**.

### Not verified by this release
- **This package has no test project.** `dotnet test` exits **0 with zero output** — it
  runs nothing. Read the "build succeeded" above as compilation only; it is not behavioural
  evidence. Untracked follow-up: add a test project.
