# L2-RUBYGEMS-DEPC-001: RubyGems Dependency Confusion

**Severity:** CRITICAL  
**Category:** dependency  
**Ecosystem:** rubygems  

## Description

Detects private/internal-looking gem names declared in Gemfile without
a private gem server configuration. Attackers can register internal-looking
gem names on rubygems.org, causing `bundle install` to resolve the public
malicious version instead of the intended private one.

## Detection Method

The rule checks each gem in Gemfile for patterns that suggest internal/private
usage (e.g., `internal-*`, `private-*`, `company-*`). If no private gem server
is configured (via custom `source` blocks in Gemfile, `.gemrc`, or `.bundle/config`),
the gem is flagged.

## Mitigation

- Configure a private gem server via a custom `source` block in Gemfile.
- Use git or path sources for internal gems.
- Add a top-level `source` block pointing to your private server.

## References

- [Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4)
- [Bundler Gemfile Documentation](https://bundler.io/man/gemfile.5.html)