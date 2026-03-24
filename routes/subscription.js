const express = require('express');
const User = require('../models/User');
const { protect, requirePro } = require('../middleware/auth');

const router = express.Router();


// ─── GET SUBSCRIPTION STATUS ──────────────────────────────────────────────────
// GET /api/subscription/status
router.get('/status', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const limits = user.getTierLimits();

    res.json({
      success: true,
      plan: user.subscription?.plan || 'free',
      isPro: user.isPro,
      subscription: {
        plan: user.subscription?.plan || 'free',
        isActive: user.subscription?.isActive || false,
        startDate: user.subscription?.startDate || null,
        endDate: user.subscription?.endDate || null,
      },
      limits,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not fetch subscription.' });
  }
});


// ─── ACTIVATE PRO VIA GUMROAD LICENSE KEY ────────────────────────────────────
// POST /api/subscription/activate
// User buys on Gumroad, gets a license key, enters it here
router.post('/activate', protect, async (req, res) => {
  try {
    const { licenseKey } = req.body;

    if (!licenseKey || licenseKey.trim().length < 10) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid license key.',
      });
    }

    // Verify with Gumroad API
    const verifyResponse = await verifyGumroadLicense(licenseKey.trim());

    if (!verifyResponse.valid) {
      return res.status(400).json({
        success: false,
        message: verifyResponse.reason || 'Invalid or already used license key.',
      });
    }

    // Check if this key has already been used by another account
    const existingUser = await User.findOne({
      'subscription.gumroadLicenseKey': licenseKey.trim(),
      _id: { $ne: req.user._id },
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'This license key is already in use by another account.',
      });
    }

    // Activate Pro
    const user = await User.findByIdAndUpdate(
      req.user._id,
      {
        role: 'pro',
        'subscription.plan': 'pro',
        'subscription.isActive': true,
        'subscription.startDate': new Date(),
        'subscription.endDate': new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        'subscription.gumroadLicenseKey': licenseKey.trim(),
      },
      { new: true }
    );

    res.json({
      success: true,
      message: 'Pro plan activated successfully! Enjoy unlimited access.',
      user: user.toPublicJSON(),
    });

  } catch (error) {
    console.error('Activate subscription error:', error);
    res.status(500).json({ success: false, message: 'Could not activate subscription.' });
  }
});


// ─── MANUAL PRO ACTIVATION (Admin only) ──────────────────────────────────────
// POST /api/subscription/admin-activate
router.post('/admin-activate', protect, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin access required.' });
    }

    const { userId, daysToAdd } = req.body;
    const days = parseInt(daysToAdd) || 30;

    const user = await User.findByIdAndUpdate(
      userId,
      {
        role: 'pro',
        'subscription.plan': 'pro',
        'subscription.isActive': true,
        'subscription.startDate': new Date(),
        'subscription.endDate': new Date(Date.now() + days * 24 * 60 * 60 * 1000),
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    res.json({ success: true, message: `Pro activated for ${days} days.`, user: user.toPublicJSON() });

  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not activate.' });
  }
});


// ─── CANCEL SUBSCRIPTION ──────────────────────────────────────────────────────
// POST /api/subscription/cancel
router.post('/cancel', protect, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user._id,
      {
        role: 'free',
        'subscription.plan': 'free',
        'subscription.isActive': false,
      },
      { new: true }
    );

    res.json({
      success: true,
      message: 'Subscription cancelled. You have been moved to the free plan.',
      user: user.toPublicJSON(),
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Could not cancel subscription.' });
  }
});


// ─── GUMROAD LICENSE VERIFICATION ─────────────────────────────────────────────
// Calls Gumroad API to verify a license key is genuine
async function verifyGumroadLicense(licenseKey) {
  try {
    const response = await fetch('https://api.gumroad.com/v2/licenses/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        product_permalink: 'cfevjo', // your Gumroad product URL slug
        license_key: licenseKey,
        increment_uses_count: 'false',
      }),
    });

    const data = await response.json();

    if (!data.success) {
      return { valid: false, reason: 'License key not found.' };
    }

    if (data.uses > 1) {
      return { valid: false, reason: 'This license key has already been used.' };
    }

    return { valid: true, data };

  } catch (error) {
    console.error('Gumroad verification error:', error);
    // If Gumroad is down, fail safe — reject the key
    return { valid: false, reason: 'Could not verify license. Please try again.' };
  }
}


module.exports = router;
