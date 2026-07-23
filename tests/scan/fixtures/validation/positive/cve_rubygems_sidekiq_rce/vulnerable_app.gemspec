Gem::Specification.new do |s|
  s.name = "vulnerable_app"
  s.version = "1.0.0"
  s.summary = "App with vulnerable sidekiq"
  s.authors = ["Example Author"]
  s.add_runtime_dependency 'sidekiq', '~> 6.4.0'
end
