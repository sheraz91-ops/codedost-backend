const nodemailer = require('nodemailer');

// Create a transporter for nodemailer
the transporter = nodemailer.createTransport({
    host: 'smtp.example.com', // replace with your SMTP host
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: 'your-email@example.com', // replace with your email
        pass: 'your-email-password' // replace with your email password
    }
});

// Function to send verification email
const sendVerificationEmail = (to, token) => {
    const url = `http://example.com/verify?token=${token}`;
    const mailOptions = {
        from: 'no-reply@example.com', // sender address
        to, // receiver's email
        subject: 'Email Verification',
        text: `Please verify your email by clicking on this link: ${url}`,
    };
    return transporter.sendMail(mailOptions);
};

// Function to send password reset email
const sendPasswordResetEmail = (to, token) => {
    const url = `http://example.com/reset-password?token=${token}`;
    const mailOptions = {
        from: 'no-reply@example.com', // sender address
        to, // receiver's email
        subject: 'Password Reset',
        text: `To reset your password, click on this link: ${url}`,
    };
    return transporter.sendMail(mailOptions);
};

// Function to send welcome email
const sendWelcomeEmail = (to, name) => {
    const mailOptions = {
        from: 'no-reply@example.com', // sender address
        to, // receiver's email
        subject: 'Welcome!',
        text: `Welcome, ${name}! We're glad to have you on board!`,
    };
    return transporter.sendMail(mailOptions);
};

module.exports = {
    sendVerificationEmail,
    sendPasswordResetEmail,
    sendWelcomeEmail,
};