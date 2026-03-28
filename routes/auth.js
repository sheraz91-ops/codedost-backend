const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const { protect } = require('../middleware/auth');
const { validateRegister, validateLogin } = require('../middleware/validate');
const { 
  sendVerificationEmail, 
  sendPasswordResetEmail, 
  sendWelcomeEmail,
  generateVerificationToken 
} = require('../services/emailService');
const {
  signupLimiter,
  loginLimiter,
  forgotPasswordLimiter,
  verifyEmailLimiter,
} = require('../middleware/rateLimiter');

const router = express.Router();

// ─── HELPER FUNCTIONS ──────────────────────────────────────────────────────

// Generate access token (15 min)
const generateAccessToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m',
  });
};

// Generate refresh token (7 days)
const generateRefreshToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d',
  });
};

// Set cookies
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

// Clear cookies
const clearCookies = (res) => {
  const isProd = process.env.NODE_ENV === 'production';
  res.clearCookie('accessToken', { 
    httpOnly: true, 
    secure: isProd, 
    sameSite: isProd ? 'none' : 'lax' 
  });
  res.clearCookie('refreshToken', { 
    httpOnly: true, 
    secure: isProd, 
    sameSite: isProd ? 'none' : 'lax', 
    path: '/api/auth/refresh' 
  });
};


// ─── REGISTER ENDPOINT ─────────────────────────────────────────────────────
// POST /api/auth/register
// 🔒 Rate Limited: 5 signups per 15 minutes per IP
router.post('/register', signupLimiter, validateRegister, async (req, res) => {
  try {
    const { name, email, password, university } = req.body;

    console.log(`📝 Register request for: ${email}`);

    // Check if email already exists
    const existing = await User.findOne({ email });
    if (existing) {
      console.log(`❌ Email already exists: ${email}`);
      return res.status(400).json({
        success: false,
        message: 'An account with this email already exists.',
      });
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password,
      university: university || undefined,
    });

    console.log(`✅ User created: ${email}`);

    // Generate verification token
    const verificationToken = generateVerificationToken();
    const tokenHash = crypto.createHash('sha256').update(verificationToken).digest('hex');

    user.emailVerificationToken = tokenHash;
    user.emailVerificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    // Generate JWT tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await user.save({ validateBeforeSave: false });

    // Send verification email
    try {
      await sendVerificationEmail(
        user.email,
        user.name,
        verificationToken,
        process.env.FRONTEND_URL || 'http://localhost:3000'
      );
      console.log(`📧 Verification email sent to ${email}`);
    } catch (emailError) {
      console.error(`❌ Email sending failed: ${emailError.message}`);
      user.emailVerificationToken = undefined;
      user.emailVerificationExpiry = undefined;
      await user.save({ validateBeforeSave: false });

      return res.status(500).json({
        success: false,
        message: 'Account created but email verification failed. Please try again later.',
      });
    }

    // Set cookies
    setCookies(res, accessToken, refreshToken);

    res.status(201).json({
      success: true,
      message: 'Account created successfully! Check your email to verify.',
      user: user.toPublicJSON(),
    });

  } catch (error) {
    console.error(`❌ Register error: ${error.message}`);
    if (error.code === 11000) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email already registered.' 
      });
    }
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed. Please try again.' 
    });
  }
});


// ─── LOGIN ENDPOINT ────────────────────────────────────────────────────────
// POST /api/auth/login
// 🔒 Rate Limited: 10 attempts per 15 minutes per email+IP
router.post('/login', loginLimiter, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log(`🔐 Login attempt for: ${email}`);

    // Find user and include password
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      console.log(`❌ User not found: ${email}`);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.',
      });
    }

    if (!user.isActive) {
      console.log(`❌ Account deactivated: ${email}`);
      return res.status(401).json({
        success: false,
        message: 'This account has been deactivated.',
      });
    }

    // Compare password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      console.log(`❌ Wrong password for: ${email}`);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.',
      });
    }

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await user.save({ validateBeforeSave: false });

    // Set cookies
    setCookies(res, accessToken, refreshToken);

    console.log(`✅ Login successful: ${email}`);

    res.json({
      success: true,
      message: 'Logged in successfully.',
      user: user.toPublicJSON(),
    });

  } catch (error) {
    console.error(`❌ Login error: ${error.message}`);
    res.status(500).json({ 
      success: false, 
      message: 'Login failed. Please try again.' 
    });
  }
});


// ─── LOGOUT ENDPOINT ───────────────────────────────────────────────────────
// POST /api/auth/logout
router.post('/logout', protect, async (req, res) => {
  try {
    console.log(`🚪 Logout for user: ${req.user.email}`);

    // Remove refresh token from DB
    await User.findByIdAndUpdate(req.user._id, {
      $unset: { refreshToken: 1 }
    });

    // Clear cookies
    clearCookies(res);

    console.log(`✅ Logout successful: ${req.user.email}`);

    res.json({ 
      success: true, 
      message: 'Logged out successfully.' 
    });

  } catch (error) {
    console.error(`❌ Logout error: ${error.message}`);
    clearCookies(res);
    res.json({ 
      success: true, 
      message: 'Logged out.' 
    });
  }
});


// ─── REFRESH TOKEN ENDPOINT ───────────────────────────────────────────────
// POST /api/auth/refresh
router.post('/refresh', async (req, res) => {
  try {
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

    // Find user and verify refresh token
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

    // Generate new tokens
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
    console.error(`❌ Refresh error: ${error.message}`);
    clearCookies(res);
    res.status(500).json({ 
      success: false, 
      message: 'Session refresh failed.' 
    });
  }
});


// ─── GET CURRENT USER ENDPOINT ────────────────────────────────────────────
// GET /api/auth/me
router.get('/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found.' 
      });
    }

    res.json({
      success: true,
      user: user.toPublicJSON(),
    });
  } catch (error) {
    console.error(`❌ Get user error: ${error.message}`);
    res.status(500).json({ 
      success: false, 
      message: 'Could not fetch user data.' 
    });
  }
});


// ─── CHANGE PASSWORD ENDPOINT ─────────────────────────────────────────────
// PATCH /api/auth/change-password
router.patch('/change-password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Both current and new password are required.' 
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: 'New password must be at least 8 characters.' 
      });
    }

    const user = await User.findById(req.user._id).select('+password');
    const isMatch = await user.comparePassword(currentPassword);

    if (!isMatch) {
      return res.status(400).json({ 
        success: false, 
        message: 'Current password is incorrect.' 
      });
    }

    user.password = newPassword;
    await user.save();

    console.log(`✅ Password changed for: ${user.email}`);

    res.json({ 
      success: true, 
      message: 'Password changed successfully.' 
    });

  } catch (error) {
    console.error(`❌ Change password error: ${error.message}`);
    res.status(500).json({ 
      success: false, 
      message: 'Password change failed.' 
    });
  }
});


// ─── FORGOT PASSWORD ENDPOINT ──────────────────────────────────────────────
// POST /api/auth/forgot-password
// 🔒 Rate Limited: 3 attempts per 1 hour per email
router.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required.' 
      });
    }

    console.log(`🔑 Forgot password request for: ${email}`);

    const user = await User.findOne({ email });

    // Don't reveal if email exists (security best practice)
    if (!user) {
      return res.status(200).json({
        success: true,
        message: 'If email exists, password reset link sent.',
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    user.passwordResetToken = resetTokenHash;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await user.save({ validateBeforeSave: false });

    // Send reset email
    try {
      await sendPasswordResetEmail(
        user.email,
        user.name,
        resetToken,
        process.env.FRONTEND_URL || 'http://localhost:3000'
      );
      console.log(`📧 Password reset email sent to ${email}`);
    } catch (emailError) {
      console.error(`❌ Email sending failed: ${emailError.message}`);
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      return res.status(500).json({
        success: false,
        message: 'Could not send password reset email.',
      });
    }

    res.json({
      success: true,
      message: 'Password reset link sent to email.',
    });

  } catch (error) {
    console.error(`❌ Forgot password error: ${error.message}`);
    res.status(500).json({ 
      success: false, 
      message: 'An error occurred.' 
    });
  }
});


// ─── RESET PASSWORD ENDPOINT ───────────────────────────────────────────────
// POST /api/auth/reset-password
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token and password are required.' 
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 8 characters.' 
      });
    }

    console.log(`🔑 Password reset attempt`);

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: tokenHash,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      console.log(`❌ Invalid or expired reset token`);
      return res.status(400).json({
        success: false,
        message: 'Reset token invalid or expired.',
      });
    }

    user.password = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();

    console.log(`✅ Password reset successful for: ${user.email}`);

    res.json({
      success: true,
      message: 'Password reset successful. Log in with your new password.',
    });

  } catch (error) {
    console.error(`❌ Reset password error: ${error.message}`);
    res.status(500).json({ 
      success: false, 
      message: 'An error occurred.' 
    });
  }
});


// ─── VERIFY EMAIL ENDPOINT ────────────────────────────────────────────────
// POST /api/auth/verify-email
// 🔒 Rate Limited: 10 attempts per 1 hour per IP
router.post('/verify-email', verifyEmailLimiter, async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ 
        success: false, 
        message: 'Verification token is required.' 
      });
    }

    console.log(`✉️  Email verification attempt`);

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      emailVerificationToken: tokenHash,
      emailVerificationExpiry: { $gt: Date.now() },
    });

    if (!user) {
      console.log(`❌ Invalid or expired verification token`);
      return res.status(400).json({
        success: false,
        message: 'Verification token invalid or expired.',
      });
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpiry = undefined;

    await user.save({ validateBeforeSave: false });

    // Send welcome email
    try {
      await sendWelcomeEmail(user.email, user.name);
      console.log(`📧 Welcome email sent to ${user.email}`);
    } catch (emailError) {
      console.error(`⚠️  Welcome email failed (non-critical): ${emailError.message}`);
    }

    console.log(`✅ Email verified for: ${user.email}`);

    res.json({
      success: true,
      message: 'Email verified successfully! You can now access all features.',
      user: user.toPublicJSON(),
    });

  } catch (error) {
    console.error(`❌ Email verification error: ${error.message}`);
    res.status(500).json({ 
      success: false, 
      message: 'Verification failed.' 
    });
  }
});


// ─── RESEND VERIFICATION EMAIL ENDPOINT ────────────────────────────────────
// POST /api/auth/send-verification
router.post('/send-verification', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        message: 'Your email is already verified.',
      });
    }

    console.log(`✉️  Resending verification email to: ${user.email}`);

    // Generate new verification token
    const verificationToken = generateVerificationToken();
    const tokenHash = crypto.createHash('sha256').update(verificationToken).digest('hex');

    user.emailVerificationToken = tokenHash;
    user.emailVerificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await user.save({ validateBeforeSave: false });

    // Send verification email
    try {
      await sendVerificationEmail(
        user.email,
        user.name,
        verificationToken,
        process.env.FRONTEND_URL || 'http://localhost:3000'
      );
      console.log(`📧 Verification email resent to ${user.email}`);
    } catch (emailError) {
      console.error(`❌ Email sending failed: ${emailError.message}`);
      return res.status(500).json({
        success: false,
        message: 'Could not send verification email.',
      });
    }

    res.json({
      success: true,
      message: 'Verification email sent to your inbox.',
    });

  } catch (error) {
    console.error(`❌ Send verification error: ${error.message}`);
    res.status(500).json({ 
      success: false, 
      message: 'An error occurred.' 
    });
  }
});


module.exports = router;