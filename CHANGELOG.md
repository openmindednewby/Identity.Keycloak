# Changelog — Identity.Keycloak

All notable changes to this package.

> **Honest header:** this file starts at **1.8.0**. Versions 1.0.0–1.7.0 predate it and
> were never changelogged; reconstruct them from `git log` if needed. Created during the
> NuGet drift backlog (Wave 2b), where a *missing* changelog on a sibling package was the
> thing that blocked an upgrade for a full session.

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
