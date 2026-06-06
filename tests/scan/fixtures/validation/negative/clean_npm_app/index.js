'use strict';

const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.json({ message: 'hello world' });
});

module.exports = app;
