require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');

// ── CONNECT TO MONGODB ────────────────────────────────────────
connectDB();

const app = express();

// ── SECURITY HEADERS (Helmet) ─────────────────────────────────
app.use(helmet());

// ── CORS ──────────────────────────────────────────────────────
const allowedOrigins = [
  process.env.FRONTEND_URL,
  process.env.ALLOWED_ORIGIN,
  'https://code-dost.vercel.app',
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5500',
].filter(Boolean);

app.use((req, res, next) => {
  if (process.env.NODE_ENV === "development") {
return  next();
} else {
  const allowed = [
  process.env.FRONTEND_URL,
  process.env.ALLOWED_ORIGIN,
  'https://code-dost.vercel.app',
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5500',
];

  const origin = req.headers.origin || "";
  const referer = req.headers.referer || "";

  const isValid =
    allowed.some(url => origin === url) ||
    allowed.some(url => referer.startsWith(url));

  if (!isValid) {
    return res.status(403).json({ error: "Forbidden" });
  }
}

  next();
});

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, origin); // ✅ exact origin (NO *)
    }

    return callback(new Error(`CORS: Origin ${origin} not allowed`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // ✅ FIXED (no wildcard issue)

// ── BODY PARSERS ──────────────────────────────────────────────
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET));

// ── TRUST PROXY ───────────────────────────────────────────────
app.set('trust proxy', 1);

// ── GLOBAL RATE LIMITER ───────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests. Please try again in 15 minutes.',
  },
});
app.use('/api', globalLimiter);

// ── AUTH RATE LIMITER ─────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    error: 'Too many login attempts. Please try again in 15 minutes.',
  },
});

// ── ROUTES ────────────────────────────────────────────────────
app.use('/api/auth', authLimiter, require('./routes/auth'));
app.use('/api/analyze', require('./routes/analyze'));
app.use('/api/subscription', require('./routes/subscription'));
app.use('/api/counter', authLimiter , require('./routes/counter'));

// ── HEALTH CHECK ──────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'CodeDost API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
  });
});

// ── 404 HANDLER ───────────────────────────────────────────────
app.use('*', (req, res) => {
  res.status(404).json({ success: false, error: 'Route not found.' });
});

// ── GLOBAL ERROR HANDLER ──────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Global error:', err);

  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ success: false, error: err.message });
  }

  if (err.name === 'CastError') {
    return res.status(400).json({ success: false, error: 'Invalid ID format.' });
  }

  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(409).json({
      success: false,
      error: `An account with this ${field} already exists.`,
    });
  }

  res.status(err.status || 500).json({
    success: false,
    error:
      process.env.NODE_ENV === 'production'
        ? 'Server error. Please try again.'
        : err.message,
  });
});

// ── START SERVER ──────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(
    `CodeDost API running on port ${PORT} [${
      process.env.NODE_ENV || 'development'
    }]`
  );
});