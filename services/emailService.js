const nodemailer = require('nodemailer');
const crypto = require('crypto');

let transporter;
let transporterMode = 'smtp';

const getTransporter = async () => {
  if (transporter) {
    return transporter;
  }

  const emailHost = process.env.EMAIL_HOST || 'sandbox.smtp.mailtrap.io';
  const emailPort = parseInt(process.env.EMAIL_PORT, 10) || 2525;
  const emailSecure = process.env.EMAIL_SECURE === 'true';
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;
console.log("EMAIL_USER:", process.env.EMAIL_USER);
console.log("Transporter mode:", transporterMode);
  if (emailUser && emailPass) {
    transporterMode = 'smtp';
    transporter = nodemailer.createTransport({
      host: emailHost,
      port: emailPort,
      secure: emailSecure,
      auth: {
        user: emailUser,
        pass: emailPass,
      },
    });
  } else if (process.env.NODE_ENV !== 'production') {
    try {
      const testAccount = await nodemailer.createTestAccount();
      transporterMode = 'ethereal';
      transporter = nodemailer.createTransport({
        host: testAccount.smtp.host,
        port: testAccount.smtp.port,
        secure: testAccount.smtp.secure,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
      });
      console.warn('⚠️ EMAIL_USER or EMAIL_PASS not set. Using Ethereal test email account for development.');
      console.warn(`⚠️ Preview messages at https://ethereal.email/messages`);
    } catch (error) {
      transporterMode = 'json';
      console.warn('⚠️ Could not create Nodemailer test account. Falling back to JSON transport for development.');
      console.warn(`⚠️ ${error.message}`);
      transporter = nodemailer.createTransport({ jsonTransport: true });
      console.warn('⚠️ Emails will be generated as JSON and not actually sent.');
    }
  } else {
    const error = new Error('Missing EMAIL_USER and EMAIL_PASS for SMTP transport. Set SMTP credentials in .env before starting the app.');
    console.error('❌ Email service initialization failed:', error.message);
    throw error;
  }

  transporter.verify((error, success) => {
    if (error) {
      console.error('❌ Email service connection failed:', error);
    } else {
      console.log('✅ Email service ready!');
    }
  });

  return transporter;
};

const logMailInfo = (info) => {
  if (transporterMode === 'ethereal') {
    const previewUrl = nodemailer.getTestMessageUrl(info);
    if (previewUrl) {
      console.warn(`📨 Preview email at: ${previewUrl}`);
    }
  } else if (transporterMode === 'json') {
    console.warn('📨 JSON transport active. Email payload generated but not sent.');
    console.warn(JSON.stringify(info, null, 2));
  }
};

const getDefaultFromAddress = () => {
  return process.env.EMAIL_FROM || 'noreply@codedost.com';
};

// ─── GENERATE VERIFICATION TOKEN ──────────────────────────────────────────
const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// ─── SEND VERIFICATION EMAIL ─────────────────────────────────────────────
const sendVerificationEmail = async (email, name, token, frontendUrl) => {
  try {
    const verificationLink = `${frontendUrl}/?token=${token}`;
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f5f7fa; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0;">✉️ Verify Your Email</h1>
        </div>
        
        <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333;">Welcome, ${name}!</h2>
          
          <p style="color: #666; line-height: 1.8;">Thank you for signing up to <strong>CodeDost</strong>! We're excited to have you on board.</p>
          
          <p style="color: #666; line-height: 1.8;">To get started, please verify your email address by clicking the button below:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationLink}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; font-weight: 600; display: inline-block;">
              Verify Email Address
            </a>
          </div>
          
          <p style="color: #999; font-size: 14px; text-align: center;">Or copy and paste this link:</p>
          <p style="background-color: #f5f7fa; padding: 15px; border-radius: 5px; color: #555; word-break: break-all; font-size: 12px;">${verificationLink}</p>
          
          <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px;">
            <p style="color: #856404; margin: 0;"><strong>⏱️ Important:</strong> This link expires in <strong>24 hours</strong>.</p>
          </div>
          
          <p style="color: #999; font-size: 13px; margin-top: 30px;">If you didn't create this account, please ignore this email.</p>
        </div>
        
        <div style="background-color: #f5f7fa; padding: 20px; text-align: center; border-top: 1px solid #e0e0e0;">
          <p style="color: #999; font-size: 12px; margin: 0;">© ${new Date().getFullYear()} CodeDost. All rights reserved.</p>
        </div>
      </div>
    `;

    const transport = await getTransporter();
    const info = await transport.sendMail({
      from: getDefaultFromAddress(),
      to: email,
      subject: '🔐 Verify Your Email - CodeDost',
      html: htmlContent,
    });

    console.log(`✅ Verification email sent to ${email}`);
    logMailInfo(info);
    return true;
  } catch (error) {
    console.error('❌ Verification email failed:', error.message);
    throw error;
  }
};

// ─── SEND PASSWORD RESET EMAIL ───────────────────────────────────────────
const sendPasswordResetEmail = async (email, name, resetToken, frontendUrl) => {
  try {
    const resetLink = `${frontendUrl}/reset-password?token=${resetToken}`;
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f5f7fa; padding: 20px;">
        <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0;">🔐 Password Reset</h1>
        </div>
        
        <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333;">Hi ${name},</h2>
          
          <p style="color: #666; line-height: 1.8;">We received a request to reset your password. Click the button below to proceed:</p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; font-weight: 600; display: inline-block;">
              Reset Password
            </a>
          </div>
          
          <p style="color: #999; font-size: 14px; text-align: center;">Or copy and paste this link:</p>
          <p style="background-color: #f5f7fa; padding: 15px; border-radius: 5px; color: #555; word-break: break-all; font-size: 12px;">${resetLink}</p>
          
          <div style="background-color: #f8d7da; border-left: 4px solid #f5576c; padding: 15px; margin: 20px 0; border-radius: 4px;">
            <p style="color: #721c24; margin: 0;"><strong>⏱️ Note:</strong> This link expires in <strong>1 hour</strong>.</p>
          </div>
          
          <p style="color: #e74c3c; font-weight: 600; margin-top: 20px;">If you didn't request this, ignore this email. Your account is secure.</p>
        </div>
        
        <div style="background-color: #f5f7fa; padding: 20px; text-align: center; border-top: 1px solid #e0e0e0;">
          <p style="color: #999; font-size: 12px; margin: 0;">© ${new Date().getFullYear()} CodeDost. All rights reserved.</p>
        </div>
      </div>
    `;

    const transport = await getTransporter();
    const info = await transport.sendMail({
      from: getDefaultFromAddress(),
      to: email,
      subject: '🔑 Reset Your Password - CodeDost',
      html: htmlContent,
    });

    console.log(`✅ Password reset email sent to ${email}`);
    logMailInfo(info);
    return true;
  } catch (error) {
    console.error('❌ Password reset email failed:', error.message);
    throw error;
  }
};

// ─── SEND WELCOME EMAIL ──────────────────────────────────────────────────
const sendWelcomeEmail = async (email, name) => {
  try {
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f5f7fa; padding: 20px;">
        <div style="background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0;">🎉 Welcome to CodeDost!</h1>
        </div>
        
        <div style="background-color: white; padding: 30px; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333;">Hi ${name},</h2>
          
          <p style="color: #666; line-height: 1.8;">Your email has been verified successfully! Your account is now ready to use.</p>
          
          <h3 style="color: #333;">What you can do now:</h3>
          
          <ul style="color: #666; line-height: 2;">
            <li>🔍 <strong>Analyze Code Errors</strong> - Get instant AI-powered explanations</li>
            <li>📊 <strong>Track Usage</strong> - Monitor your monthly limits</li>
            <li>⭐ <strong>Upgrade to Pro</strong> - Unlock unlimited features</li>
            <li>🛠️ <strong>API Access</strong> - Integrate into your workflow</li>
          </ul>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.FRONTEND_URL}/dashboard" style="background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; font-weight: 600; display: inline-block;">
              Go to Dashboard
            </a>
          </div>
        </div>
        
        <div style="background-color: #f5f7fa; padding: 20px; text-align: center; border-top: 1px solid #e0e0e0;">
          <p style="color: #999; font-size: 12px; margin: 0;">© ${new Date().getFullYear()} CodeDost. All rights reserved.</p>
        </div>
      </div>
    `;

    const transport = await getTransporter();
    const info = await transport.sendMail({
      from: getDefaultFromAddress(),
      to: email,
      subject: '🎉 Welcome to CodeDost!',
      html: htmlContent,
    });

    console.log(`✅ Welcome email sent to ${email}`);
    logMailInfo(info);
    return true;
  } catch (error) {
    console.error('❌ Welcome email failed:', error.message);
    throw error;
  }
};

module.exports = {
  generateVerificationToken,
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendWelcomeEmail,
};