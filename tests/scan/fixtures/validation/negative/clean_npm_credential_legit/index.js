const express = require('express');
const app = express();
app.get('/config', (req, res) => {
  res.json({ token: process.env.API_TOKEN });
});
module.exports = app;
