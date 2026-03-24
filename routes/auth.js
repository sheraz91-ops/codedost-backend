const express = require('express');
const { protect } = require('../middleware/auth');
const { validateRegister, validateLogin } = require('../middleware/validate');
const {
  register, login, logout, refresh, getMe, changePassword,
} = require('../controllers/authController');

const router = express.Router();

// POST /api/auth/register
router.post('/register', validateRegister, register);

// POST /api/auth/login
router.post('/login', validateLogin, login);

// POST /api/auth/logout  (requires valid access token)
router.post('/logout', protect, logout);

// POST /api/auth/refresh  (uses refresh token cookie)
router.post('/refresh', refresh);

// GET /api/auth/me  (returns current user)
router.get('/me', protect, getMe);

// PATCH /api/auth/change-password
router.patch('/change-password', protect, changePassword);

module.exports = router;
