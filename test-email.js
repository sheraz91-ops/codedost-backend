// test-email.js
require('dotenv').config();
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.BREVO_USER,
    pass: process.env.BREVO_PASS,
  },
});

transporter.verify((err, success) => {
  if (err) console.log('❌ Error:', err.message);
  else console.log('✅ Brevo connected!');
});