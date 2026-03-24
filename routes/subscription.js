const express = require('express');
const { protect } = require('../middleware/auth');
const { getStatus, activate, adminActivate, cancel } = require('../controllers/subscriptionController');

const router = express.Router();

// GET /api/subscription/status
router.get('/status', protect, getStatus);

// POST /api/subscription/activate  — activate Pro via Gumroad license key
router.post('/activate', protect, activate);

// POST /api/subscription/admin-activate  — manually grant Pro (admin only)
router.post('/admin-activate', protect, adminActivate);

// POST /api/subscription/cancel
router.post('/cancel', protect, cancel);

module.exports = router;
