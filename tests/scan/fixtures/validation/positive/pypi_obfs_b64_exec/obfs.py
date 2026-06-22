"""Multi-rule OBFS fixture. b64-decode followed by exec on the next line."""


import base64


# L2-PYPI-OBFS-002 fires on the b64decode call below.
# L2-PYPI-OBFS-007 fires because b64decode + exec are within 200 chars.
# L2-PYPI-OBFS-001 fires on the exec call on the next line.
_payload = base64.b64decode("aGVsbG8=")
exec(_payload)
