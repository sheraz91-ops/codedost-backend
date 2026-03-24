const mongoose = require('mongoose');

// ─── ANONYMOUS USAGE SCHEMA ──────────────────────────────────────────────────
// Tracks usage for users who have not logged in
// Identified by a hash of their IP address + User-Agent
const anonymousUsageSchema = new mongoose.Schema({

  // SHA256 hash of IP + User-Agent (never store raw IP for privacy)
  fingerprint: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },

  // Current month usage
  errorsThisMonth: {
    type: Number,
    default: 0,
  },

  // Which month we are tracking
  currentMonth: {
    type: String,
    default: () => new Date().toISOString().slice(0, 7),
  },

  // All-time total
  totalErrors: {
    type: Number,
    default: 0,
  },

  lastSeenAt: {
    type: Date,
    default: Date.now,
  },

}, { timestamps: true });


// ─── INSTANCE METHOD: Reset if new month ────────────────────────────────────
anonymousUsageSchema.methods.resetIfNewMonth = function () {
  const currentMonth = new Date().toISOString().slice(0, 7);
  if (this.currentMonth !== currentMonth) {
    this.errorsThisMonth = 0;
    this.currentMonth = currentMonth;
  }
};


// TTL index — auto-delete anonymous records after 90 days of inactivity
anonymousUsageSchema.index(
  { lastSeenAt: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 90 } // 90 days
);


module.exports = mongoose.model('AnonymousUsage', anonymousUsageSchema);
