# Changelog — Identity.Keycloak

All notable changes to this package.

> **Honest header:** this file starts at **1.8.0**. Versions 1.0.0–1.7.0 predate it and
> were never changelogged; reconstruct them from `git log` if needed. Created during the
> NuGet drift backlog (Wave 2b), where a *missing* changelog on a sibling package was the
> thing that blocked an upgrade for a full session.

## [1.13.0] - 2026-11-21

### Added
- `AddKeycloakJwtDefaults` registers an `IClaimsTransformation` that adds one `ClaimTypes.Role` claim per
  `realm_access.roles` entry (SVCDEF-1 D-SVCDEF-42 item A), so services delete their own
  `KeycloakRealmRoleClaimsTransformation` copy. A token without `realm_access` gets no role claims.

## [1.12.3] - 2026-11-21

### Security
- An event handler counts as the package default only when it is that exact delegate with one invocation, so a forged
  handler combined in front of the package one (`Forge + events.OnMessageReceived`) fails startup.
- `AllowQueryStringToken` rejects "/" and empty prefixes; each prefix names at least one path segment.
- Any JwtBearerOptions.ConfigurationManager not created by this package fails startup, and the package-configured scheme
  must keep the package IssuerSigningKeyResolver.

## [1.12.2] - 2026-11-21

### Security
- D-SVCDEF-41 "The package owns JWT events and key sources": every JwtBearerEvents delegate must be the package default and any
  EventsType fails startup; claim changes go through IClaimsTransformation. The package events log challenges and failed
  authentications (path, error, exception type).
- Configuration, ConfigurationManager (other than the one the framework builds from Authority), TokenValidationParameters
  ConfigurationManager, IssuerSigningKey(s) and CryptoProviderFactory set by a service fail startup; ConfigureMultiRealm sets
  TryAllIssuerSigningKeys = false and its key resolver returns only the key whose kid matches, so an unknown kid gets 401.
- The floor requires RequireExpirationTime = true.

### Added
- `AuthenticationBuilder.AllowQueryStringToken(params string[] pathPrefixes)`: accepts `?access_token=` only under the named
  path prefixes (SignalR hubs).

## [1.12.1] - 2026-11-21

### Security
- The JWT floor is an allowlist: every delegate-typed property of TokenValidationParameters (found by reflection, the
  UsingConfiguration variants and IssuerSigningKeyResolver included) must be null or set by this package; TokenHandlers must
  be the default JsonWebTokenHandler; a service-set OnAuthenticationFailed (or events type overriding it) fails startup.
- With authentication switched off, the floor validator and startup check still run, so a service's own AddJwtBearer gets the floor.

## [1.12.0] - 2026-11-21

### Added
- `services.AddKeycloakJwtDefaults(configuration, environment, authenticationEnabled)` (SVCDEF-1 item 8 "the composition has no
  behaviour of its own"): binds `Jwt:Authority`, `Jwt:Audience`, `Jwt:RequireHttpsMetadata` and `Authentication:AllowedRealms`,
  moved from Dloizides.ServiceDefaults. Without `Jwt:Authority` it throws unless `authenticationEnabled` is false, which
  registers a scheme that authenticates no one.

### Security
- The JWT floor (ValidateIssuer/Audience/Lifetime/IssuerSigningKey, RequireSignedTokens, ClockSkew <= 30 s, RS256/ES256 only)
  now applies to EVERY JwtBearer scheme and is checked at startup, not only `Bearer`.
- Startup fails when SignatureValidator, IssuerSigningKeyValidator, LifetimeValidator or IssuerValidator (and their
  UsingConfiguration twins) is set by anything other than this package; `ConfigureMultiRealm`'s IssuerValidator stays allowed.

## [1.11.1] - 2026-11-16

### Fixed
- `KeycloakUserManagementService` (FINREG-FUNDS-1 "Tenant funds, deal gate, blocking roles" review fixes): a role-mappings
  request that throws `HttpRequestException` or times out (`TaskCanceledException` without caller cancellation) now throws
  `KeycloakRoleLookupException` instead of returning an empty user list / `null`.

## [1.11.0] - 2026-11-16

### Fixed
- `KeycloakUserManagementService` (FINREG-FUNDS-1 "Tenant funds, deal gate, blocking roles"): `GetUsersAsync` and
  `GetUserByIdAsync` now fill `UserListItem.Roles` from `users/{id}/role-mappings/realm` (at most 8 requests at once);
  before, `Roles` was always empty, so callers that confirm a role assignment or count admins saw none.
- A failed role-mappings read throws the new `KeycloakRoleLookupException` (an `HttpRequestException`) instead of
  returning users with no roles. A failed users read still returns an empty list / `null`.
- `AssignRolesAsync` returns `false` when the realm roles read fails, instead of `true` with nothing assigned.

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
