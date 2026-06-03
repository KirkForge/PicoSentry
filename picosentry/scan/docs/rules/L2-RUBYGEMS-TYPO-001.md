# L2-RUBYGEMS-TYPO-001: RubyGems Typosquatting

**Severity:** HIGH  
**Category:** typosquat  
**Ecosystem:** rubygems  

## Description

Detects Ruby gem dependencies whose names are within edit distance ≤2 of
popular gems in the RubyGems corpus. Attackers register misspelled gem names
on rubygems.org to trick developers into importing malicious code.

## Detection Method

The rule extracts all gem names from `Gemfile`, then compares each name
against the corpus of top Ruby gems using Levenshtein edit distance.

## Mitigation

- Double-check gem names before adding them to your Gemfile.
- Verify the gem source and author before importing.
- Use a private gem server for internal gems to avoid confusion.

## References

- [Typosquatting on npm (similar pattern)](https://blog.npmjs.org/post/186451959906/typosquatting-on-npm)
- [Snyk: Typosquatting Attacks](https://snyk.io/blog/typosquatting-attacks/)