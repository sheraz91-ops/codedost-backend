const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    // existing fields
    emailVerificationToken: {
        type: String,
        index: true,
    },
    emailVerificationExpiry: {
        type: Date,
        index: true,
    },
    // other fields
});

const User = mongoose.model('User', userSchema);

module.exports = User;