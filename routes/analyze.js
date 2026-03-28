const express = require('express');
const AnalysisLog = require('../models/AnalysisLog');
const User = require('../models/User');
const { optionalAuth, protect } = require('../middleware/auth');
const { checkUsageLimit, incrementUsage, getFingerprint } = require('../middleware/usageLimit');
const { validateAnalysis } = require('../middleware/validate');

const router = express.Router();
// /status - GET usage status
// /log - POST log an analysis (called after successful analysis)
// /check - POST pre-flight check before analysis
// /history - GET my analysis history
// /understood/:logId - PATCH mark if I understood the feedback

// ─── CHECK USAGE STATUS ──────────────────────────────────────────────────────
// GET /api/usage/status
// Returns how many analyses the current user has used this month
router.get('/status', optionalAuth, async (req, res) => {
  try {
    if (req.user) {
      // Logged-in user
      const user = await User.findById(req.user._id);
      user.resetMonthlyUsageIfNeeded();
      const limits = user.getTierLimits();

      return res.json({
        success: true,
        tier: user.subscription?.plan || 'free',
        used: user.usage.errorsThisMonth,
        limit: limits.monthlyLimit,
        remaining: Math.max(0, limits.monthlyLimit - user.usage.errorsThisMonth),
        maxLines: limits.maxLines,
        resetDate: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1),
      });
    }

    // Anonymous user
    const AnonymousUsage = require('../models/AnonymousUsage');
    const fingerprint = getFingerprint(req);
    const anonUsage = await AnonymousUsage.findOne({ fingerprint });
    const limit = parseInt(process.env.ANONYMOUS_MONTHLY_LIMIT) || 5;
    const used = anonUsage ? anonUsage.errorsThisMonth : 0;

    return res.json({
      success: true,
      tier: 'anonymous',
      used,
      limit,
      remaining: Math.max(0, limit - used),
      maxLines: parseInt(process.env.ANONYMOUS_MAX_LINES) || 300,
      resetDate: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1),
    });

  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not fetch usage status.' });
  }
});


// ─── LOG AN ANALYSIS ─────────────────────────────────────────────────────────
// POST /api/usage/log
// Called by frontend AFTER a successful analysis
// Also enforces limits BEFORE the analysis
router.post('/log', optionalAuth, checkUsageLimit, validateAnalysis, async (req, res) => {
  try {
    const { code, language, errorType, mistakeCategory, severity, provider, mode } = req.body;
    const lineCount = (code || '').split('\n').length;

    // Create log entry
    const logData = {
      userId: req.user ? req.user._id : null,
      anonymousId: req.user ? null : getFingerprint(req),
      tier: req.usageInfo?.tier || (req.user ? (req.user.subscription?.plan || 'free') : 'anonymous'),
      language: language || 'python',
      errorType: errorType || null,
      mistakeCategory: mistakeCategory || null,
      severity: severity || null,
      lineCount,
      provider: provider || 'groq',
      mode: mode || 'urdu',
      month: new Date().toISOString().slice(0, 7),
    };

    await AnalysisLog.create(logData);

    // Increment usage counters
    await incrementUsage(req);

    res.json({
      success: true,
      message: 'Analysis logged.',
      remaining: req.usageInfo?.remaining ?? null,
    });

  } catch (error) {
    console.error('Log analysis error:', error);
    res.status(500).json({ success: false, message: 'Could not log analysis.' });
  }
});


// ─── CHECK BEFORE ANALYSIS (pre-flight check) ────────────────────────────────
// POST /api/usage/check
// Frontend calls this BEFORE sending to Groq to check if user is allowed
router.post('/check', optionalAuth, async (req, res) => {
  try {
    const { lineCount } = req.body;
    const lines = parseInt(lineCount) || 0;

    if (req.user) {
      const user = await User.findById(req.user._id);
      user.resetMonthlyUsageIfNeeded();
      const limits = user.getTierLimits();

      if (lines > limits.maxLines) {
        return res.json({
          success: false,
          allowed: false,
          reason: 'LINE_LIMIT',
          message: `Code too long. Your plan allows ${limits.maxLines} lines max.`,
          limit: limits.maxLines,
        });
      }

      if (user.usage.errorsThisMonth >= limits.monthlyLimit) {
        return res.json({
          success: false,
          allowed: false,
          reason: 'MONTHLY_LIMIT',
          message: `Monthly limit reached (${limits.monthlyLimit}/month). ${user.subscription?.plan === 'free' ? 'Upgrade to Pro for unlimited.' : ''}`,
          used: user.usage.errorsThisMonth,
          limit: limits.monthlyLimit,
        });
      }

      return res.json({
        success: true,
        allowed: true,
        remaining: limits.monthlyLimit - user.usage.errorsThisMonth,
      });
    }

    // Anonymous
    const AnonymousUsage = require('../models/AnonymousUsage');
    const fingerprint = getFingerprint(req);
    const anonUsage = await AnonymousUsage.findOne({ fingerprint });
    const limit = parseInt(process.env.ANONYMOUS_MONTHLY_LIMIT) || 5;
    const maxLines = parseInt(process.env.ANONYMOUS_MAX_LINES) || 300;
    const used = anonUsage ? anonUsage.errorsThisMonth : 0;

    if (lines > maxLines) {
      return res.json({
        success: false,
        allowed: false,
        reason: 'LINE_LIMIT',
        message: `Code too long. Anonymous users can submit up to ${maxLines} lines. Log in for more.`,
        limit: maxLines,
      });
    }

    if (used >= limit) {
      return res.json({
        success: false,
        allowed: false,
        reason: 'MONTHLY_LIMIT',
        message: `Monthly limit reached (${limit}/month without login). Create a free account for ${process.env.FREE_MONTHLY_LIMIT || 20}/month.`,
        used,
        limit,
      });
    }

    return res.json({
      success: true,
      allowed: true,
      remaining: limit - used,
    });

  } catch (error) {
    // On error, allow request (fail open for better UX)
    res.json({ success: true, allowed: true });
  }
});


// ─── GET MY ANALYSIS HISTORY ──────────────────────────────────────────────────
// GET /api/usage/history
router.get('/history', protect, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const logs = await AnalysisLog.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('language errorType mistakeCategory severity mode createdAt understood');

    const total = await AnalysisLog.countDocuments({ userId: req.user._id });

    res.json({
      success: true,
      logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });

  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not fetch history.' });
  }
});


// ─── UPDATE UNDERSTOOD STATUS ─────────────────────────────────────────────────
// PATCH /api/usage/understood/:logId
router.patch('/understood/:logId', protect, async (req, res) => {
  try {
    const log = await AnalysisLog.findOneAndUpdate(
      { _id: req.params.logId, userId: req.user._id },
      { understood: req.body.understood },
      { new: true }
    );

    if (!log) {
      return res.status(404).json({ success: false, message: 'Log entry not found.' });
    }

    res.json({ success: true, log });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not update.' });
  }
});


module.exports = router;
