const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    isEmailVerified: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    university: { type: String },
    subscriptionDetails: { type: Object },
    usageTracking: { type: Object },
    refreshToken: { type: String },
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },
    emailVerificationToken: { type: String },
    emailVerificationExpiry: { type: Date },
}, { timestamps: true });

// Pre-save hook for password hashing
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Instance method to compare passwords
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Indexes
UserSchema.index({ email: 1 });
UserSchema.index({ isEmailVerified: 1 });
UserSchema.index({ isActive: 1 });

module.exports = mongoose.model('User', UserSchema);