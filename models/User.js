const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// ─── USER SCHEMA ────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({

  // Basic identity
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters'],
    maxlength: [50, 'Name cannot exceed 50 characters'],
  },

  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email'],
  },

  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false, // never returned in queries by default
  },

  // Account status
  role: {
    type: String,
    enum: ['free', 'pro', 'admin'],
    default: 'free',
  },

  isEmailVerified: {
    type: Boolean,
    default: false,
  },

  isActive: {
    type: Boolean,
    default: true,
  },

  // University info (optional — for pilot tracking)
  university: {
    type: String,
    trim: true,
    maxlength: 100,
  },

  // Subscription details
  subscription: {
    plan: {
      type: String,
      enum: ['free', 'pro'],
      default: 'free',
    },
    startDate: Date,
    endDate: Date,
    gumroadLicenseKey: String, // if using Gumroad for payment verification
    isActive: {
      type: Boolean,
      default: false,
    },
  },

  // Monthly usage tracking — resets every month
  usage: {
    // Current month usage
    errorsThisMonth: {
      type: Number,
      default: 0,
    },
    // Track which month we are currently in (format: "2026-03")
    currentMonth: {
      type: String,
      default: () => new Date().toISOString().slice(0, 7),
    },
    // All-time totals
    totalErrorsAllTime: {
      type: Number,
      default: 0,
    },
    // Last time the user submitted an analysis
    lastAnalysisAt: Date,
  },

  // Refresh token (stored hashed for security)
  refreshToken: {
    type: String,
    select: false,
  },

  // Password reset
  passwordResetToken: {
    type: String,
    select: false,
  },
  passwordResetExpires: {
    type: Date,
    select: false,
  },

  // Timestamps
}, { timestamps: true }); // adds createdAt and updatedAt automatically


// ─── INDEXES ─────────────────────────────────────────────────────────────────
userSchema.index({ email: 1 });
userSchema.index({ 'subscription.plan': 1 });
userSchema.index({ createdAt: -1 });


// ─── PRE-SAVE HOOK: Hash password before saving ───────────────────────────
userSchema.pre('save', async function (next) {
  // Only hash if password was actually modified (not on other updates)
  if (!this.isModified('password')) return next();

  try {
    // Salt rounds: 12 = very secure, slow. 10 = secure, faster.
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});


// ─── INSTANCE METHOD: Compare password ───────────────────────────────────────
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};


// ─── INSTANCE METHOD: Reset usage if new month ───────────────────────────────
userSchema.methods.resetMonthlyUsageIfNeeded = function () {
  const currentMonth = new Date().toISOString().slice(0, 7); // "2026-03"
  if (this.usage.currentMonth !== currentMonth) {
    this.usage.errorsThisMonth = 0;
    this.usage.currentMonth = currentMonth;
  }
};


// ─── INSTANCE METHOD: Get tier limits ─────────────────────────────────────────
userSchema.methods.getTierLimits = function () {
  const plan = this.subscription?.plan || 'free';
  if (plan === 'pro') {
    return {
      monthlyLimit: parseInt(process.env.PRO_MONTHLY_LIMIT) || 999999,
      maxLines: parseInt(process.env.PRO_MAX_LINES) || 999999,
    };
  }
  return {
    monthlyLimit: parseInt(process.env.FREE_MONTHLY_LIMIT) || 20,
    maxLines: parseInt(process.env.FREE_MAX_LINES) || 1000,
  };
};


// ─── VIRTUAL: Is Pro ─────────────────────────────────────────────────────────
userSchema.virtual('isPro').get(function () {
  return this.subscription?.plan === 'pro' && this.subscription?.isActive === true;
});


// ─── VIRTUAL: Public profile (safe to send to frontend) ───────────────────────
userSchema.methods.toPublicJSON = function () {
  return {
    id: this._id,
    name: this.name,
    email: this.email,
    role: this.role,
    university: this.university,
    plan: this.subscription?.plan || 'free',
    isPro: this.isPro,
    usage: {
      errorsThisMonth: this.usage.errorsThisMonth,
      currentMonth: this.usage.currentMonth,
      totalErrorsAllTime: this.usage.totalErrorsAllTime,
      lastAnalysisAt: this.usage.lastAnalysisAt,
    },
    createdAt: this.createdAt,
  };
};


module.exports = mongoose.model('User', userSchema);
