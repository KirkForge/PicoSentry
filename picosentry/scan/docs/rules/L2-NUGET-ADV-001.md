# L2-NUGET-ADV-001: NuGet Advisory Vulnerability Check

**Severity:** HIGH  
**Category:** vulnerability  
**Ecosystem:** nuget  

## Description

Checks .NET package dependencies against a local OSV-format advisory database.
Flags packages with known CVEs or security advisories from the NuGet ecosystem.

## Detection Method

The rule extracts all package IDs and versions from .csproj files,
packages.config, and packages.lock.json, then checks each against the advisory
database using "NuGet" as the OSV ecosystem.

## Mitigation

- Update vulnerable packages to the fixed version specified in the advisory.
- Review the advisory details for impact assessment.
- Run `picosentry update` to refresh the advisory database regularly.

## References

- [OSV Database](https://osv.dev/)
- [NuGet Security Advisories](https://learn.microsoft.com/en-us/nuget/reference/security-advisories)