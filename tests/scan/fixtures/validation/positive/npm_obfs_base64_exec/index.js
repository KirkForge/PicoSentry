// Multi-rule OBFS-001 + OBFS-003 fixture. b64 decode followed by exec.
const buf = Buffer.from("Y29kZQ==", "base64");
const result = eval(buf.toString());
module.exports = { result };
