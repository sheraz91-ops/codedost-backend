const mongoose = require('mongoose');

// ─── ANALYSIS LOG SCHEMA ─────────────────────────────────────────────────────
// Stores every code analysis — for analytics, rate limiting, and admin dashboard
const analysisLogSchema = new mongoose.Schema({

  // Who made the request
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null, // null = anonymous user
  },

  // For anonymous users — track by IP + fingerprint
  anonymousId: {
    type: String, // hash of IP + user agent
    default: null,
  },

  // What tier was used
  tier: {
    type: String,
    enum: ['anonymous', 'free', 'pro'],
    required: true,
  },

  // The analysis
  language: {
    type: String,
    enum: ['python', 'javascript', 'java', 'cpp', 'html', 'sql'],
    required: true,
  },

  errorType: {
    type: String, // e.g. "SyntaxError", "TypeError"
    trim: true,
  },

  mistakeCategory: {
    type: String, // e.g. "syntax_error", "type_error"
    trim: true,
  },

  severity: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced'],
  },

  // Line count of submitted code
  lineCount: {
    type: Number,
    default: 0,
  },

  // AI provider used
  provider: {
    type: String,
    enum: ['groq', 'gemini', 'openrouter'],
    default: 'groq',
  },

  // Language mode selected
  mode: {
    type: String,
    enum: ['urdu', 'mixed', 'english'],
    default: 'urdu',
  },

  // Whether user marked as "understood"
  understood: {
    type: Boolean,
    default: null, // null = not rated
  },

  // Month for easy aggregation (format: "2026-03")
  month: {
    type: String,
    default: () => new Date().toISOString().slice(0, 7),
  },

}, { timestamps: true });


// ─── INDEXES ──────────────────────────────────────────────────────────────────
analysisLogSchema.index({ userId: 1, month: 1 });
analysisLogSchema.index({ anonymousId: 1, month: 1 });
analysisLogSchema.index({ createdAt: -1 });
analysisLogSchema.index({ mistakeCategory: 1 });
analysisLogSchema.index({ language: 1 });


module.exports = mongoose.model('AnalysisLog', analysisLogSchema);
