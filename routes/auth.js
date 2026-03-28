const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const { protect } = require('../middleware/auth');
const { validateRegister, validateLogin } = require('../middleware/validate');
const { getTransporter } = require('../services/emailService');

const router = express.Router();

// ─── EMAIL TRANSPORTER SETUP ──────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,        
  port: process.env.SMTP_PORT,        
  auth: {
    user: process.env.SMTP_USER,      
    pass: process.env.SMTP_PASS,      
  },
});
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
    console.log("Registering user...", req.body);

    const { name, email, password, university } = req.body;

    // Check existing user
    const existing = await User.findOne({ email });
    if (existing) {
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

    // ─── GENERATE VERIFICATION TOKEN ───
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    // ─── SEND EMAIL ───
    try {
      const transporter = await getTransporter();

      const verificationLink = `${process.env.FRONTEND_URL}/codedost.html?verify_token=${verificationToken}`;

      await transporter.sendMail({
        from: `CodeDost <${process.env.EMAIL_USER}>`, // ✅ FIXED
        to: user.email,
        subject: '🔐 Verify Your Email',
        html: `
           <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f5f7fa; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0;">✉️ Verify Your Email</h1>
        </div>
        
        <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333;">Welcome, ${name}!</h2>
          
          <p style="color: #666; line-height: 1.8;">Thank you for signing up to <strong>CodeDost</strong>! We're excited to have you on board.</p>
          
          <p style="color: #666; line-height: 1.8;">To get started, please verify your email address by clicking the button below:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationLink}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; font-weight: 600; display: inline-block;">
              Verify Email Address
            </a>
          </div>
          
          <p style="color: #999; font-size: 14px; text-align: center;">Or copy and paste this link:</p>
          <p style="background-color: #f5f7fa; padding: 15px; border-radius: 5px; color: #555; word-break: break-all; font-size: 12px;">${verificationLink}</p>
          
          <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px;">
            <p style="color: #856404; margin: 0;"><strong>⏱️ Important:</strong> This link expires in <strong>24 hours</strong>.</p>
          </div>
          
          <p style="color: #999; font-size: 13px; margin-top: 30px;">If you didn't create this account, please ignore this email.</p>
        </div>
        
        <div style="background-color: #f5f7fa; padding: 20px; text-align: center; border-top: 1px solid #e0e0e0;">
          <p style="color: #999; font-size: 12px; margin: 0;">© ${new Date().getFullYear()} CodeDost. All rights reserved.</p>
        </div>
      </div>
        `,
      });

      console.log("✅ Email sent to:", user.email);

    } catch (emailError) {
      console.error('❌ Email failed:', emailError.message);
    }

    // ─── TOKENS ───
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshToken = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    await user.save({ validateBeforeSave: false });

    // Cookies
    setCookies(res, accessToken, refreshToken);

    res.status(201).json({
      success: true,
      message: 'Account created. Please verify your email.',
      user: user.toPublicJSON(),
    });

  } catch (error) {
    console.error('Register error:', error);

    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered.',
      });
    }

    res.status(500).json({
      success: false,
      message: 'Registration failed.',
    });
  }
});
// ─── VERIFY EMAIL ─────────────────────────────────────────────────────────────
// GET /api/auth/verify-email?token=xxx
router.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    console.log(token)
    
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
    console.log(user)
    
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

    // ─── SEND WELCOME EMAIL TO USER ───────────────────────────────────
    // ✅ CHANGED: Email goes to user.email (not to process.env.SMTP_USER)
    try {
      const transporter = await getTransporter();
      await transporter.sendMail({
        from: 'CodeDost <noreply@codedost.pk>',
        to: user.email,  // ✅ CHANGED: Email goes to user, not you
        subject: '✅ CodeDost - Welcome!',
        html: `
          <div style="font-family: Arial, sans-serif; background: #f3f4f6; padding: 20px;">
            <div style="background: white; max-width: 500px; margin: 0 auto; padding: 30px; border-radius: 10px;">
              <h2 style="color: #10b981; text-align: center;">✅ Welcome to CodeDost!</h2>
              <p style="color: #374151;">Salam ${user.name}!</p>
              <p style="color: #374151;">Tumhara email successfully verify ho gaya. Ab tum CodeDost use kar sakte ho!</p>
              <p style="color: #374151; margin: 20px 0;">Ab tum login karke code analyze kar sakte ho:</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/codedost.html" style="background: #3b82f6; color: white; padding: 12px 40px; text-decoration: none; border-radius: 6px; font-weight: bold;">Go to CodeDost</a>
              </div>
              <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
              <p style="color: #9ca3af; font-size: 12px; text-align: center;">
                Happy coding! 🇵🇰
              </p>
            </div>
          </div>
        `
      });
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


// ─── FORGOT PASSWORD ──────────────────────────────────────────────────────────
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
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    // ─── SEND RESET EMAIL TO USER ─────────────────────────────────────
    // ✅ CHANGED: Email goes to user.email (not to process.env.SMTP_USER)
    try {
      const transporter = await getTransporter();
      const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/codedost.html?reset_token=${resetToken}`;
      
      await transporter.sendMail({
        from: 'CodeDost <noreply@codedost.pk>',
        to: user.email,  // ✅ CHANGED: Email goes to user, not you
        subject: '🔑 CodeDost - Password Reset',
        html: `
          <div style="font-family: Arial, sans-serif; background: #f3f4f6; padding: 20px;">
            <div style="background: white; max-width: 500px; margin: 0 auto; padding: 30px; border-radius: 10px;">
              <h2 style="color: #1f2937; text-align: center;">🔑 Password Reset</h2>
              <p style="color: #374151;">Salam ${user.name}!</p>
              <p style="color: #374151;">Tumhare CodeDost account ke liye password reset request aayi hai.</p>
              <p style="color: #374151; margin: 20px 0;">Password reset karne ke liye neeche click karo:</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${resetLink}" style="background: #10b981; color: white; padding: 12px 40px; text-decoration: none; border-radius: 6px; font-weight: bold;">Reset Password</a>
              </div>
              <p style="color: #6b7280; font-size: 12px; word-break: break-all;">
                Ya ye link copy karo:<br>
                <code style="background: #f3f4f6; padding: 5px 10px;">${resetLink}</code>
              </p>
              <p style="color: #6b7280; font-size: 12px; margin-top: 10px;">
                Link 1 hour ke liye valid hai.
              </p>
              <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
              <p style="color: #9ca3af; font-size: 12px; text-align: center;">
                Agar tumne ye request nahi ki, toh is email ko ignore karo.
              </p>
            </div>
          </div>
        `
      });
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


// ─── RESET PASSWORD ───────────────────────────────────────────────────────────
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

    // ─── SEND CONFIRMATION EMAIL TO USER ──────────────────────────────
    // ✅ CHANGED: Email goes to user.email (not to process.env.SMTP_USER)
    try {
      await transporter.sendMail({
        from: 'CodeDost <noreply@codedost.pk>',
        to: user.email,  // ✅ CHANGED: Email goes to user, not you
        subject: '✅ CodeDost - Password Changed',
        html: `
          <div style="font-family: Arial, sans-serif; background: #f3f4f6; padding: 20px;">
            <div style="background: white; max-width: 500px; margin: 0 auto; padding: 30px; border-radius: 10px;">
              <h2 style="color: #10b981; text-align: center;">✅ Password Updated</h2>
              <p style="color: #374151;">Salam ${user.name}!</p>
              <p style="color: #374151;">Tumhara CodeDost password successfully change ho gaya!</p>
              <p style="color: #374151; margin: 20px 0;">Ab tum apna naya password use karke login kar sakte ho:</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/codedost.html" style="background: #3b82f6; color: white; padding: 12px 40px; text-decoration: none; border-radius: 6px; font-weight: bold;">Go to CodeDost</a>
              </div>
              <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
              <p style="color: #9ca3af; font-size: 12px; text-align: center;">
                Agar ye tumne nahi kiya, toh turant support contact karo.
              </p>
            </div>
          </div>
        `
      });
    } catch (emailError) {
      console.error('Failed to send confirmation email:', emailError);
      // Still consider the password reset successful even if email fails
    }

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