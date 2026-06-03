# L2-NUGET-TYPO-001: NuGet Package Typosquatting

**Severity:** HIGH  
**Category:** typosquat  
**Ecosystem:** nuget  

## Description

Detects .NET package dependencies whose IDs are within edit distance ≤2 of
popular NuGet packages. Attackers register misspelled package IDs on nuget.org
to trick developers into importing malicious code.

## Detection Method

The rule extracts all package IDs from `.csproj` PackageReference elements and
`packages.config`, then compares each ID against the corpus of top NuGet
packages using Levenshtein edit distance.

## Mitigation

- Double-check package IDs before adding them to your project.
- Verify the package source and author before importing.
- Use a private NuGet source for internal packages.

## References

- [Typosquatting on npm (similar pattern)](https://blog.npmjs.org/post/186451959906/typosquatting-on-npm)
- [Snyk: Typosquatting Attacks](https://snyk.io/blog/typosquatting-attacks/)