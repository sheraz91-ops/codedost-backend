const mongoose = require('mongoose');

// ─── GUEST USAGE SCHEMA ──────────────────────────────────────────────────────
// Tracks usage for users who have not created an account, identified by a
// SHA-256 fingerprint of IP + User-Agent (no raw PII stored).
// Model name: GuestUsage (distinct from AnonymousUsage).
// New code should prefer AnonymousUsage for anonymous tracking; this model
// is available for sessions that need a separate collection.
const guestUsageSchema = new mongoose.Schema({

  fingerprint: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },

  errorsThisMonth: {
    type: Number,
    default: 0,
  },

  currentMonth: {
    type: String,
    default: () => new Date().toISOString().slice(0, 7),
  },

  totalErrors: {
    type: Number,
    default: 0,
  },

  lastSeenAt: {
    type: Date,
    default: Date.now,
  },

}, { timestamps: true });


guestUsageSchema.methods.resetIfNewMonth = function () {
  const currentMonth = new Date().toISOString().slice(0, 7);
  if (this.currentMonth !== currentMonth) {
    this.errorsThisMonth = 0;
    this.currentMonth = currentMonth;
  }
};

// Auto-delete guest records after 90 days of inactivity
guestUsageSchema.index(
  { lastSeenAt: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 90 }
);


module.exports = mongoose.model('GuestUsage', guestUsageSchema);
