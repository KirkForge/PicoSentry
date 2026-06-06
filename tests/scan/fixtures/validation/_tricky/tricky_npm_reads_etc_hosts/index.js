// Legitimate DNS helper: reads /etc/hosts without exfiltrating.
const fs = require('fs');
const hosts = fs.readFileSync('/etc/hosts', 'utf8');
const entries = hosts.split('\n').filter(l => l && !l.startsWith('#'));
module.exports = { resolve: (name) => entries.find(e => e.includes(name)) };
