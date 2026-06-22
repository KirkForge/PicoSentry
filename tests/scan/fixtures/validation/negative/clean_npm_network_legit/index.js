const http = require('http');

function fetchPublic() {
  return new Promise((resolve, reject) => {
    http
      .get('http://httpbin.org/get', (res) => resolve(res.statusCode))
      .on('error', reject);
  });
}

module.exports = { fetchPublic };
