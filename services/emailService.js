const nodemailer = require('nodemailer');

let transporter;

const getTransporter = async () => {
  if (transporter) return transporter;

  transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.BREVO_USER,  // tumhari brevo email
      pass: process.env.BREVO_PASS,  // brevo SMTP key
    },
  });

  return transporter;
};

module.exports = { getTransporter };