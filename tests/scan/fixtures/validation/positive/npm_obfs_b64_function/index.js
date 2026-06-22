// Variant: Buffer.from(b64) then Function(...)
const decoded = Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString();
Function(decoded)();
