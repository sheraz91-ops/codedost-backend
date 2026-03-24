const express = require('express');
const { optionalAuth, protect } = require('../middleware/auth');
const { checkUsageLimit } = require('../middleware/usageLimit');
const { validateAnalysis } = require('../middleware/validate');
const {
  getStatus, logAnalysis, checkQuota, getHistory, updateUnderstood,
} = require('../controllers/usageController');

const router = express.Router();

// GET /api/analyze/status  — current quota usage (works for anon + logged-in)
router.get('/status', optionalAuth, getStatus);

// POST /api/analyze/log  — log a completed analysis and increment counter
router.post('/log', optionalAuth, checkUsageLimit, validateAnalysis, logAnalysis);

// POST /api/analyze/check  — pre-flight quota check before calling the AI
router.post('/check', optionalAuth, checkQuota);

// GET /api/analyze/history  — analysis history (logged-in only)
router.get('/history', protect, getHistory);

// PATCH /api/analyze/understood/:logId  — mark a log entry as understood
router.patch('/understood/:logId', protect, updateUnderstood);

module.exports = router;
