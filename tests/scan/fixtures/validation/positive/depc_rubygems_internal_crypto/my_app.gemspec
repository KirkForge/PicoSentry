Gem::Specification.new do |s|
  s.name = "my_app"
  s.version = "1.0.0"
  s.summary = "App with internal dependency"
  s.authors = ["Example Author"]
  s.add_runtime_dependency 'internal_crypto', '~> 1.5.0'
end
