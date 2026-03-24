// routes/usage.js — backwards-compatibility shim.
// All usage/quota logic lives in routes/analyze.js and is served at /api/analyze.
// This file is kept so any legacy imports don't break; it is NOT mounted separately.
module.exports = require('./analyze');
