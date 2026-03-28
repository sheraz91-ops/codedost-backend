const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const { protect } = require('../middleware/auth');
const { validateRegister, validateLogin } = require('../middleware/validate');

const router = express.Router();

// ─── HELPERS ─────────────────────────────────────────────────────────────────

// Generate access token (short-lived: 15 min)
const generateAccessToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m',
  });
};

// Generate refresh token (long-lived: 7 days)
const generateRefreshToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d',
  });
};

// Set cookies on response
const setCookies = (res, accessToken, refreshToken) => {
  const isProd = process.env.NODE_ENV === 'production';

  // Access token cookie — short-lived, httpOnly
  res.cookie('accessToken', accessToken, {
    httpOnly: true,           // JS cannot read this cookie — prevents XSS
    secure: isProd,           // HTTPS only in production
    sameSite: isProd ? 'none' : 'lax', // 'none' needed for cross-origin in prod
    maxAge: 15 * 60 * 1000,  // 15 minutes in ms
  });

  // Refresh token cookie — long-lived, httpOnly
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
    path: '/api/auth/refresh', // only sent to refresh endpoint
  });
};

// Clear cookies on logout
const clearCookies = (res) => {
  const isProd = process.env.NODE_ENV === 'production';
  res.clearCookie('accessToken', { httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax' });
  res.clearCookie('refreshToken', { httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax', path: '/api/auth/refresh' });
};


// ─── REGISTER ────────────────────────────────────────────────────────────────
// POST /api/auth/register
router.post('/register', validateRegister, async (req, res) => {
  try {
    const { name, email, password, university } = req.body;

    // Check if email already exists
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({
        success: false,
        message: 'An account with this email already exists.',
      });
    }

    // Create user (password will be hashed by pre-save hook in model)
    const user = await User.create({
      name,
      email,
      password,
      university: university || undefined,
    });

    // ─── GENERATE VERIFICATION TOKEN ───────────────────────────────────
    const { generateVerificationToken, sendVerificationEmail } = require('../services/emailService');
    const verificationToken = generateVerificationToken();
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    // ─── SEND VERIFICATION EMAIL ───────────────────────────────────────
    try {
      await sendVerificationEmail(
        user.email,
        user.name,
        verificationToken,
        process.env.FRONTEND_URL || 'http://localhost:3000'
      );
    } catch (emailError) {
      console.error('Failed to send verification email:', emailError);
      // Don't fail the registration, but log the error
    }

    // Generate JWT tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Store hashed refresh token in DB
    user.refreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await user.save({ validateBeforeSave: false });

    // Set httpOnly cookies
    setCookies(res, accessToken, refreshToken);

    res.status(201).json({
      success: true,
      message: 'Account created successfully. Check your email to verify your account.',
      user: user.toPublicJSON(),
    });

  } catch (error) {
    console.error('Register error:', error);
    if (error.code === 11000) {
      return res.status(400).json({ success: false, message: 'Email already registered.' });
    }
    res.status(500).json({ success: false, message: 'Registration failed. Please try again.' });
  }
});

// ─── VERIFY EMAIL ─────────────────────────────────────────────────────────────
// GET /api/auth/verify-email?token=xxx
router.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Verification token is required.',
      });
    }

    // Find user by verification token
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() }, // Token not expired
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token.',
      });
    }

    // Mark email as verified
    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationExpires = null;
    await user.save({ validateBeforeSave: false });

    // ─── SEND WELCOME EMAIL ───────────────────────────────────────────
    try {
      const { sendWelcomeEmail } = require('../services/emailService');
      await sendWelcomeEmail(user.email, user.name);
    } catch (emailError) {
      console.error('Failed to send welcome email:', emailError);
      // Don't fail the verification, just log the error
    }

    res.json({
      success: true,
      message: 'Email verified successfully! You can now log in.',
      user: user.toPublicJSON(),
    });

  } catch (error) {
    console.error('Verify email error:', error);
    res.status(500).json({ success: false, message: 'Email verification failed.' });
  }
});


// ─── LOGIN ────────────────────────────────────────────────────────────────────
// POST /api/auth/login
router.post('/login', validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user — explicitly include password (it's excluded by default)
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      // Generic message — don't reveal if email exists
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.',
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'This account has been deactivated.',
      });
    }

    // Compare password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.',
      });
    }

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Store hashed refresh token
    user.refreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await user.save({ validateBeforeSave: false });

    // Set cookies
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
});


// ─── LOGOUT ──────────────────────────────────────────────────────────────────
// POST /api/auth/logout
router.post('/logout', protect, async (req, res) => {
  try {
    // Invalidate refresh token in DB
    await User.findByIdAndUpdate(req.user._id, {
      $unset: { refreshToken: 1 }
    });

    // Clear cookies
    clearCookies(res);

    res.json({ success: true, message: 'Logged out successfully.' });

  } catch (error) {
    console.error('Logout error:', error);
    // Still clear cookies even on error
    clearCookies(res);
    res.json({ success: true, message: 'Logged out.' });
  }
});


// ─── REFRESH ACCESS TOKEN ─────────────────────────────────────────────────────
// POST /api/auth/refresh
router.post('/refresh', async (req, res) => {
  try {
    // Read refresh token from cookie
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'No refresh token. Please log in again.',
        code: 'NO_REFRESH_TOKEN',
      });
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (err) {
      clearCookies(res);
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired session. Please log in again.',
        code: 'REFRESH_TOKEN_INVALID',
      });
    }

    // Find user and compare stored hash
    const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const user = await User.findOne({
      _id: decoded.id,
      refreshToken: hashedToken,
    });

    if (!user || !user.isActive) {
      clearCookies(res);
      return res.status(401).json({
        success: false,
        message: 'Session invalid. Please log in again.',
        code: 'SESSION_INVALID',
      });
    }

    // Issue new access token (rotate refresh token too for security)
    const newAccessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    user.refreshToken = crypto.createHash('sha256').update(newRefreshToken).digest('hex');
    await user.save({ validateBeforeSave: false });

    setCookies(res, newAccessToken, newRefreshToken);

    res.json({
      success: true,
      message: 'Token refreshed.',
      user: user.toPublicJSON(),
    });

  } catch (error) {
    console.error('Refresh error:', error);
    clearCookies(res);
    res.status(500).json({ success: false, message: 'Session refresh failed.' });
  }
});


// ─── GET CURRENT USER ─────────────────────────────────────────────────────────
// GET /api/auth/me
router.get('/me', protect, async (req, res) => {
  try {
    // Re-fetch to get latest data
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    res.json({
      success: true,
      user: user.toPublicJSON(),
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not fetch user data.' });
  }
});


// ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────
// PATCH /api/auth/change-password
router.patch('/change-password', protect, async (req, res) => {
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

    user.password = newPassword; // will be hashed by pre-save hook
    await user.save();

    res.json({ success: true, message: 'Password changed successfully.' });

  } catch (error) {
    res.status(500).json({ success: false, message: 'Password change failed.' });
  }
});
// ─── FORGOT PASSWORD ──────────────────────────────────────────────────────
// POST /api/auth/forgot-password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email address.',
      });
    }

    // Find user by email
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      // Don't reveal if email exists (security)
      return res.status(200).json({
        success: true,
        message: 'If an account exists with that email, a password reset link has been sent.',
      });
    }

    // ─── GENERATE RESET TOKEN ─────────────────────────────────────────
    const { generateVerificationToken, sendPasswordResetEmail } = require('../services/emailService');
    const resetToken = generateVerificationToken();
    const tokenExpiry = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    // ─── SEND RESET EMAIL ─────────────────────────────────────────────
    try {
      await sendPasswordResetEmail(
        user.email,
        user.name,
        resetToken,
        process.env.FRONTEND_URL || 'http://localhost:3000'
      );
    } catch (emailError) {
      // If email fails, clear the reset token
      user.passwordResetToken = null;
      user.passwordResetExpires = null;
      await user.save({ validateBeforeSave: false });

      console.error('Failed to send password reset email:', emailError);
      return res.status(500).json({
        success: false,
        message: 'Could not send reset email. Please try again later.',
      });
    }

    res.json({
      success: true,
      message: 'Password reset link has been sent to your email.',
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Password reset failed.' });
  }
});
// ─── RESET PASSWORD ───────────────────────────────────────────────────────
// POST /api/auth/reset-password
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;

    if (!token || !newPassword || !confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Token, new password, and confirmation are required.',
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters.',
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match.',
      });
    }

    // Find user by reset token
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }, // Token not expired
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token.',
      });
    }

    // Update password
    user.password = newPassword; // Will be hashed by pre-save hook
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    await user.save();

    res.json({
      success: true,
      message: 'Password reset successfully. You can now log in with your new password.',
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, message: 'Password reset failed.' });
  }
});

module.exports = router;
