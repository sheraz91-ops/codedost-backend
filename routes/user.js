const express = require('express');
const User = require('../models/User');
const AnalysisLog = require('../models/AnalysisLog');
const { protect } = require('../middleware/auth');

const router = express.Router();


// ─── GET MY PROFILE ──────────────────────────────────────────────────────────
// GET /api/user/profile
router.get('/profile', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json({ success: true, user: user.toPublicJSON() });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not fetch profile.' });
  }
});


// ─── UPDATE PROFILE ──────────────────────────────────────────────────────────
// PATCH /api/user/profile
router.patch('/profile', protect, async (req, res) => {
  try {
    const allowed = ['name', 'university'];
    const updates = {};

    allowed.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ success: false, message: 'No valid fields to update.' });
    }

    const user = await User.findByIdAndUpdate(req.user._id, updates, {
      new: true,
      runValidators: true,
    });

    res.json({
      success: true,
      message: 'Profile updated.',
      user: user.toPublicJSON(),
    });

  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not update profile.' });
  }
});


// ─── GET MY STATS ─────────────────────────────────────────────────────────────
// GET /api/user/stats
router.get('/stats', protect, async (req, res) => {
  try {
    const userId = req.user._id;

    // Error category breakdown
    const categoryBreakdown = await AnalysisLog.aggregate([
      { $match: { userId } },
      { $group: { _id: '$mistakeCategory', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    // Language breakdown
    const languageBreakdown = await AnalysisLog.aggregate([
      { $match: { userId } },
      { $group: { _id: '$language', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    // Monthly activity (last 6 months)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const monthlyActivity = await AnalysisLog.aggregate([
      { $match: { userId, createdAt: { $gte: sixMonthsAgo } } },
      { $group: { _id: '$month', count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ]);

    // Understanding rate
    const understoodStats = await AnalysisLog.aggregate([
      { $match: { userId, understood: { $ne: null } } },
      { $group: {
        _id: null,
        total: { $sum: 1 },
        understood: { $sum: { $cond: ['$understood', 1, 0] } },
      }},
    ]);

    const understanding = understoodStats[0] || { total: 0, understood: 0 };
    const understandingRate = understanding.total > 0
      ? Math.round((understanding.understood / understanding.total) * 100)
      : null;

    // Total counts
    const user = await User.findById(userId);

    res.json({
      success: true,
      stats: {
        totalAnalyses: user.usage.totalErrorsAllTime,
        thisMonth: user.usage.errorsThisMonth,
        categoryBreakdown: categoryBreakdown.map(c => ({
          category: c._id || 'unknown',
          count: c.count,
        })),
        languageBreakdown: languageBreakdown.map(l => ({
          language: l._id || 'unknown',
          count: l.count,
        })),
        monthlyActivity: monthlyActivity.map(m => ({
          month: m._id,
          count: m.count,
        })),
        understandingRate,
        understoodCount: understanding.understood,
        ratedCount: understanding.total,
      },
    });

  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ success: false, message: 'Could not fetch stats.' });
  }
});


// ─── DELETE ACCOUNT ───────────────────────────────────────────────────────────
// DELETE /api/user/account
router.delete('/account', protect, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ success: false, message: 'Password required to delete account.' });
    }

    const user = await User.findById(req.user._id).select('+password');
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Incorrect password.' });
    }

    // Anonymise logs instead of deleting them (for analytics)
    await AnalysisLog.updateMany(
      { userId: req.user._id },
      { $set: { userId: null } }
    );

    await User.findByIdAndDelete(req.user._id);

    // Clear cookies
    const isProd = process.env.NODE_ENV === 'production';
    res.clearCookie('accessToken', { httpOnly: true, secure: isProd });
    res.clearCookie('refreshToken', { httpOnly: true, secure: isProd });

    res.json({ success: true, message: 'Account deleted successfully.' });

  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not delete account.' });
  }
});


module.exports = router;
