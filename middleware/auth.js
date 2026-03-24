const jwt = require('jsonwebtoken');
const User = require('../models/User');

// ─── VERIFY JWT ACCESS TOKEN ─────────────────────────────────────────────────
// Reads token from httpOnly cookie OR Authorization header
const protect = async (req, res, next) => {
  try {
    let token = null;

    // 1. Check httpOnly cookie first (most secure)
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }
    // 2. Fall back to Authorization header (for mobile/Postman testing)
    else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. Please log in.',
      });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          message: 'Session expired. Please log in again.',
          code: 'TOKEN_EXPIRED',
        });
      }
      return res.status(401).json({
        success: false,
        message: 'Invalid token.',
        code: 'TOKEN_INVALID',
      });
    }

    // Find user
    const user = await User.findById(decoded.id).select('-password -refreshToken');
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User no longer exists.',
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account has been deactivated.',
      });
    }

    // Attach user to request
    req.user = user;
    next();

  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ success: false, message: 'Server error during authentication.' });
  }
};


// ─── OPTIONAL AUTH ───────────────────────────────────────────────────────────
// Does not block if no token — just sets req.user = null
// Used for routes that work for both logged-in and anonymous users
const optionalAuth = async (req, res, next) => {
  try {
    let token = null;

    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    } else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      req.user = null;
      return next();
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select('-password -refreshToken');
      req.user = user && user.isActive ? user : null;
    } catch {
      req.user = null;
    }

    next();
  } catch (error) {
    req.user = null;
    next();
  }
};


// ─── REQUIRE SPECIFIC ROLE ──────────────────────────────────────────────────
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Not authenticated.' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required role: ${roles.join(' or ')}.`,
      });
    }
    next();
  };
};


// ─── REQUIRE PRO PLAN ────────────────────────────────────────────────────────
const requirePro = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Please log in.' });
  }
  if (req.user.subscription?.plan !== 'pro' || !req.user.subscription?.isActive) {
    return res.status(403).json({
      success: false,
      message: 'Pro subscription required.',
      code: 'PRO_REQUIRED',
    });
  }
  next();
};


module.exports = { protect, optionalAuth, requireRole, requirePro };
