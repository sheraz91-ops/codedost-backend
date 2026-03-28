const nodemailer = require('nodemailer');

let transporter;

const getTransporter = async () => {
  if (transporter) return transporter;

  transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,          // smtp.gmail.com
    port: Number(process.env.EMAIL_PORT),  // 587
    secure: false,                         // ⚠️ must be false
    auth: {
      user: process.env.EMAIL_USER,        // your gmail
      pass: process.env.EMAIL_PASS,        // app password
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  transporter.verify((err) => {
    if (err) {
      console.log("❌ Email error:", err);
    } else {
      console.log("✅ Gmail SMTP ready");
    }
  });

  return transporter;
};

module.exports = { getTransporter };