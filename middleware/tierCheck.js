const crypto = require('crypto');
const AnonymousUsage = require('../models/AnonymousUsage');

// ─── GENERATE ANONYMOUS FINGERPRINT ─────────────────────────────────────────
// Creates a privacy-safe identifier from IP + User-Agent
const getFingerprint = (req) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';
  return crypto.createHash('sha256').update(ip + ua).digest('hex');
};


// ─── CHECK AND ENFORCE USAGE LIMITS ─────────────────────────────────────────
// Call this before any analysis endpoint
const checkUsageLimit = async (req, res, next) => {
  try {
    const codeLines = (req.body.code || '').split('\n').length;

    // ── CASE 1: Logged-in user ───────────────────────────────────────────────
    if (req.user) {
      const user = req.user;
      const limits = user.getTierLimits();

      // Reset monthly counter if new month
      user.resetMonthlyUsageIfNeeded();

      // Check line limit
      if (codeLines > limits.maxLines) {
        return res.status(429).json({
          success: false,
          message: `Code too long. Your plan allows up to ${limits.maxLines} lines per analysis.`,
          code: 'LINE_LIMIT_EXCEEDED',
          limit: limits.maxLines,
          submitted: codeLines,
        });
      }

      // Check monthly limit
      if (user.usage.errorsThisMonth >= limits.monthlyLimit) {
        const plan = user.subscription?.plan || 'free';
        return res.status(429).json({
          success: false,
          message: plan === 'free'
            ? `Monthly limit reached (${limits.monthlyLimit} analyses/month). Upgrade to Pro for unlimited access.`
            : `Monthly limit reached (${limits.monthlyLimit} analyses/month).`,
          code: 'MONTHLY_LIMIT_REACHED',
          used: user.usage.errorsThisMonth,
          limit: limits.monthlyLimit,
          plan,
        });
      }

      // Attach limit info to request for later use
      req.usageInfo = {
        tier: plan === 'pro' ? 'pro' : 'free',
        remaining: limits.monthlyLimit - user.usage.errorsThisMonth - 1,
      };

      return next();
    }

    // ── CASE 2: Anonymous user ────────────────────────────────────────────────
    const anonLimit = parseInt(process.env.ANONYMOUS_MONTHLY_LIMIT) || 5;
    const anonMaxLines = parseInt(process.env.ANONYMOUS_MAX_LINES) || 300;

    // Check line limit
    if (codeLines > anonMaxLines) {
      return res.status(429).json({
        success: false,
        message: `Code too long. Anonymous users can submit up to ${anonMaxLines} lines. Log in to get ${process.env.FREE_MAX_LINES || 1000} lines.`,
        code: 'LINE_LIMIT_EXCEEDED',
        limit: anonMaxLines,
        submitted: codeLines,
      });
    }

    // Find or create anonymous usage record
    const fingerprint = getFingerprint(req);
    let anonUsage = await AnonymousUsage.findOne({ fingerprint });

    if (!anonUsage) {
      anonUsage = new AnonymousUsage({ fingerprint });
    }

    // Reset monthly counter if new month
    anonUsage.resetIfNewMonth();

    // Check monthly limit
    if (anonUsage.errorsThisMonth >= anonLimit) {
      return res.status(429).json({
        success: false,
        message: `Monthly limit reached (${anonLimit} analyses/month without login). Create a free account for ${process.env.FREE_MONTHLY_LIMIT || 20} analyses/month.`,
        code: 'ANONYMOUS_LIMIT_REACHED',
        used: anonUsage.errorsThisMonth,
        limit: anonLimit,
      });
    }

    // Attach to request for post-analysis increment
    req.anonUsage = anonUsage;
    req.usageInfo = {
      tier: 'anonymous',
      remaining: anonLimit - anonUsage.errorsThisMonth - 1,
    };

    next();

  } catch (error) {
    console.error('Usage limit middleware error:', error);
    // On error, allow the request through (don't block users due to our errors)
    next();
  }
};


// ─── INCREMENT USAGE AFTER SUCCESSFUL ANALYSIS ───────────────────────────────
const incrementUsage = async (req) => {
  try {
    if (req.user) {
      // Increment logged-in user
      req.user.usage.errorsThisMonth += 1;
      req.user.usage.totalErrorsAllTime += 1;
      req.user.usage.lastAnalysisAt = new Date();
      await req.user.save();
    } else if (req.anonUsage) {
      // Increment anonymous user
      req.anonUsage.errorsThisMonth += 1;
      req.anonUsage.totalErrors += 1;
      req.anonUsage.lastSeenAt = new Date();
      await req.anonUsage.save();
    }
  } catch (error) {
    console.error('Usage increment error:', error);
    // Non-critical — do not throw
  }
};


module.exports = { checkUsageLimit, incrementUsage, getFingerprint };
