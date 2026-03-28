require('dotenv').config(); // ← MUST be line 1, before anything else

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const morgan = require('morgan');

// Import database connection
const connectDB = require('./config/db');

// Import routes
const authRoutes = require('./routes/auth');

const app = express();

// ─── CONNECT TO DATABASE ──────────────────────────────────────────────────
connectDB();

// ─── SECURITY MIDDLEWARE ──────────────────────────────────────────────────
app.use(helmet()); // Add security headers
console.log('✅ Security headers enabled (Helmet)');

// ─── LOGGING ───────────────────────────────────────────────────────────────
app.use(morgan('combined')); // Log all requests
console.log('✅ Request logging enabled (Morgan)');

// ─── CORS CONFIGURATION ───────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true, // Allow cookies
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
console.log('✅ CORS enabled for:', process.env.FRONTEND_URL || 'http://localhost:3000');

// ─── BODY PARSER ──────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ limit: '10kb', extended: true }));
app.use(cookieParser());
console.log('✅ Body parser enabled');

// ─── HEALTH CHECK ENDPOINT ────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ 
    status: '✅ Server is running',
    timestamp: new Date().toISOString(),
  });
});
console.log('✅ Health check endpoint ready');

// ─── API ROUTES ─────────────────────────��─────────────────────────────────
app.use('/api/auth', authRoutes);
console.log('✅ Auth routes registered');

// ─── ERROR HANDLING MIDDLEWARE ────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.message);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Server error',
  });
});

// ─── 404 HANDLER ──────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
  });
});

// ─── START SERVER ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║         🚀 CodeDost Backend Server Started 🚀          ║');
  console.log('╚════════════════════════════════════════════════════════╝');
  console.log(`\n✅ Server running on http://localhost:${PORT}`);
  console.log(`✅ Health check: http://localhost:${PORT}/health`);
  console.log(`\n📝 Press Ctrl+C to stop the server\n`);
});

module.exports = app;