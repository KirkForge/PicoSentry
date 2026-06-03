# L2-RUBYGEMS-ADV-001: RubyGems Advisory Vulnerability Check

**Severity:** HIGH  
**Category:** vulnerability  
**Ecosystem:** rubygems  

## Description

Checks Ruby gem dependencies against a local OSV-format advisory database.
Flags gems with known CVEs or security advisories from the RubyGems ecosystem.

## Detection Method

The rule extracts all gem names and versions from Gemfile and Gemfile.lock,
then checks each against the advisory database using "RubyGems" as the
OSV ecosystem.

## Mitigation

- Update vulnerable gems to the fixed version specified in the advisory.
- Review the advisory details for impact assessment.
- Run `picosentry update` to refresh the advisory database regularly.

## References

- [OSV Database](https://osv.dev/)
- [Ruby Security Mailing List](https://www.ruby-lang.org/en/community/mailing-lists/)