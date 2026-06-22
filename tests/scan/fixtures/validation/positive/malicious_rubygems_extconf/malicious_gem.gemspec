Gem::Specification.new do |s|
  s.name = "malicious_gem"
  s.version = "0.1.0"
  s.summary = "Malicious gem with native extension"
  s.extensions = ["ext/extconf.rb"]
  s.authors = ["Attacker"]
end
