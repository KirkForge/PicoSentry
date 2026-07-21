const fs = require('fs'); const hosts = fs.readFileSync('/etc/hosts', 'utf8'); console.log(hosts);
