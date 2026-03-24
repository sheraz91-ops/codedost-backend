const express = require('express');
const { protect } = require('../middleware/auth');
const { getProfile, updateProfile, getStats, deleteAccount } = require('../controllers/userController');

const router = express.Router();

// GET /api/user/profile
router.get('/profile', protect, getProfile);

// PATCH /api/user/profile
router.patch('/profile', protect, updateProfile);

// GET /api/user/stats
router.get('/stats', protect, getStats);

// DELETE /api/user/account
router.delete('/account', protect, deleteAccount);

module.exports = router;
