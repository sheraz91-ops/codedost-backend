const nodemailer = require('nodemailer');

// Create a transporter object using the default SMTP transport
const transporter = nodemailer.createTransport({
    host: 'smtp.example.com', // Replace with your email provider's SMTP server
    port: 587, // Use 465 for SSL
    secure: false, // true for 465, false for other ports
    auth: {
        user: 'your-email@example.com', // Replace with your email
        pass: 'your-email-password' // Replace with your password
    },
});

// Send an email
const sendEmail = async (to, subject, text) => {
    const info = await transporter.sendMail({
        from: 'your-email@example.com', // sender address
        to: to, // list of receivers
        subject: subject, // Subject line
        text: text, // plain text body
    });
    console.log('Message sent: %s', info.messageId);
};

module.exports = { sendEmail };