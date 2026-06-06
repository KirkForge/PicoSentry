// L2-OBFS-001: eval call
const x = eval("1 + 1");

// L2-OBFS-002: hex-escaped string (4+ bytes)
const s = "\x41\x42\x43\x44\x45";

// L2-OBFS-003: base64+eval pattern (within 0-N chars)
const buf = Buffer.from("Y29kZQ==", "base64");
const result = eval(buf.toString());

// L2-OBFS-004: unicode escape sequence (4+ escapes in a single string literal)
const u = "\u4e2d\u6587\u6c49\u5b57";

module.exports = { x, s, result, u };
