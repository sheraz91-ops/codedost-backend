const mongoose = require('mongoose');

// ─── SUBSCRIPTION PLAN SCHEMA ────────────────────────────────────────────────
// Stores named subscription plans with their feature limits.
// Individual user subscriptions are tracked in the User model;
// this collection defines the available plans and their quotas.
const subscriptionPlanSchema = new mongoose.Schema({

  name: {
    type: String,
    enum: ['free', 'pro'],
    required: true,
    unique: true,
  },

  displayName: {
    type: String,
    required: true,
  },

  // Monthly analysis quota (-1 = unlimited)
  monthlyLimit: {
    type: Number,
    required: true,
    default: 20,
  },

  // Max lines of code per submission (-1 = unlimited)
  maxLines: {
    type: Number,
    required: true,
    default: 1000,
  },

  // Price in USD (0 = free)
  priceUSD: {
    type: Number,
    default: 0,
  },

  features: {
    type: [String],
    default: [],
  },

  isActive: {
    type: Boolean,
    default: true,
  },

}, { timestamps: true });


module.exports = mongoose.model('SubscriptionPlan', subscriptionPlanSchema);
