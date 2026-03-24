const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');

// ─── HELPERS ─────────────────────────────────────────────────────────────────

// Generate access token (short-lived: 15 min)
const generateAccessToken = (userId) =>
  jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m',
  });

// Generate refresh token (long-lived: 7 days)
const generateRefreshToken = (userId) =>
  jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d',
  });

// Set httpOnly cookies on response
const setCookies = (res, accessToken, refreshToken) => {
  const isProd = process.env.NODE_ENV === 'production';

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 15 * 60 * 1000, // 15 minutes
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/api/auth/refresh',
  });
};

// Clear auth cookies
const clearCookies = (res) => {
  const isProd = process.env.NODE_ENV === 'production';
  res.clearCookie('accessToken', { httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax' });
  res.clearCookie('refreshToken', {
    httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax', path: '/api/auth/refresh',
  });
};


// ─── REGISTER ────────────────────────────────────────────────────────────────
// POST /api/auth/register
const register = async (req, res) => {
  try {
    const { name, email, password, university } = req.body;

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists.',
      });
    }

    // Password hashing handled by pre-save hook in User model
    const user = await User.create({ name, email, password, university: university || undefined });

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Store hashed refresh token for security
    user.refreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await user.save({ validateBeforeSave: false });

    setCookies(res, accessToken, refreshToken);

    res.status(201).json({
      success: true,
      message: 'Account created successfully.',
      user: user.toPublicJSON(),
    });
  } catch (error) {
    console.error('Register error:', error);
    if (error.code === 11000) {
      return res.status(409).json({ success: false, message: 'Email already registered.' });
    }
    res.status(500).json({ success: false, message: 'Registration failed. Please try again.' });
  }
};


// ─── LOGIN ────────────────────────────────────────────────────────────────────
// POST /api/auth/login
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Explicitly include password (excluded by default via select: false)
    const user = await User.findOne({ email }).select('+password');

    if (!user || !user.isActive) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await user.save({ validateBeforeSave: false });

    setCookies(res, accessToken, refreshToken);

    res.json({
      success: true,
      message: 'Logged in successfully.',
      user: user.toPublicJSON(),
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Login failed. Please try again.' });
  }
};


// ─── LOGOUT ──────────────────────────────────────────────────────────────────
// POST /api/auth/logout
const logout = async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user._id, { $unset: { refreshToken: 1 } });
    clearCookies(res);
    res.json({ success: true, message: 'Logged out successfully.' });
  } catch (error) {
    console.error('Logout error:', error);
    clearCookies(res); // Still clear cookies even on DB error
    res.json({ success: true, message: 'Logged out.' });
  }
};


// ─── REFRESH ACCESS TOKEN ─────────────────────────────────────────────────────
// POST /api/auth/refresh
const refresh = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'No refresh token. Please log in again.',
        code: 'NO_REFRESH_TOKEN',
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      clearCookies(res);
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired session. Please log in again.',
        code: 'REFRESH_TOKEN_INVALID',
      });
    }

    // Compare stored hash to prevent refresh token reuse
    const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const user = await User.findOne({ _id: decoded.id, refreshToken: hashedToken });

    if (!user || !user.isActive) {
      clearCookies(res);
      return res.status(401).json({
        success: false,
        message: 'Session invalid. Please log in again.',
        code: 'SESSION_INVALID',
      });
    }

    // Rotate both tokens on every refresh (refresh token rotation)
    const newAccessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    user.refreshToken = crypto.createHash('sha256').update(newRefreshToken).digest('hex');
    await user.save({ validateBeforeSave: false });

    setCookies(res, newAccessToken, newRefreshToken);

    res.json({ success: true, message: 'Token refreshed.', user: user.toPublicJSON() });
  } catch (error) {
    console.error('Refresh error:', error);
    clearCookies(res);
    res.status(500).json({ success: false, message: 'Session refresh failed.' });
  }
};


// ─── GET CURRENT USER ─────────────────────────────────────────────────────────
// GET /api/auth/me
const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }
    res.json({ success: true, user: user.toPublicJSON() });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not fetch user data.' });
  }
};


// ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────
// PATCH /api/auth/change-password
const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Both current and new password are required.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'New password must be at least 8 characters.' });
    }

    const user = await User.findById(req.user._id).select('+password');
    const isMatch = await user.comparePassword(currentPassword);

    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect.' });
    }

    user.password = newPassword; // hashed by pre-save hook
    await user.save();

    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Password change failed.' });
  }
};


module.exports = { register, login, logout, refresh, getMe, changePassword };
