# L2-NUGET-DEPC-001: NuGet Dependency Confusion

**Severity:** CRITICAL  
**Category:** dependency  
**Ecosystem:** nuget  

## Description

Detects internal-looking package IDs declared in .csproj or packages.config
without a private NuGet source configuration. Attackers can register
internal-looking package IDs on nuget.org, causing `dotnet restore` to resolve
the public malicious version instead of the intended private one.

## Detection Method

The rule checks each package ID for patterns that suggest internal/private usage
(e.g., `Company.*`, `Internal.*`, `Private.*`). If no private NuGet source is
configured (via `<packageSources>` in nuget.config), the package is flagged.

## Mitigation

- Configure a private NuGet source via `<packageSources>` in nuget.config.
- Use `<clear />` before custom package sources to prevent fallback to nuget.org.
- Use project references for local dependencies.

## References

- [Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4)
- [NuGet Configuration Documentation](https://docs.microsoft.com/en-us/nuget/consume-packages/configuring-nuget-behavior)