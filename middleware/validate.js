const { body, validationResult } = require('express-validator');

// ─── REUSABLE: Send validation errors ─────────────────────────────────────
const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed.',
      errors: errors.array().map(e => ({ field: e.path, message: e.msg })),
    });
  }
  next();
};

// ─── REGISTER VALIDATION ──────────────────────────────────────────────────
const validateRegister = [
  body('name')
    .trim()
    .notEmpty().withMessage('Name is required.')
    .isLength({ min: 2, max: 50 }).withMessage('Name must be 2–50 characters.'),

  body('email')
    .trim()
    .notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Invalid email address.')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required.')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters.')
    .matches(/\d/).withMessage('Password must contain at least one number.')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.'),

  body('university')
    .optional()
    .trim()
    .isLength({ max: 100 }).withMessage('University name too long.'),

  handleValidation,
];

// ─── LOGIN VALIDATION ─────────────────────────────────────────────────────
const validateLogin = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Invalid email address.')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required.'),

  handleValidation,
];

// ─── ANALYSIS VALIDATION ──────────────────────────────────────────────────
const validateAnalysis = [
  body('code')
    .notEmpty().withMessage('Code is required.'),

  body('language')
    .notEmpty().withMessage('Language is required.')
    .isIn(['python', 'javascript', 'java', 'cpp', 'html', 'sql'])
    .withMessage('Invalid language.'),

  body('mode')
    .optional()
    .isIn(['urdu', 'mixed', 'english'])
    .withMessage('Invalid mode.'),

  handleValidation,
];

module.exports = { validateRegister, validateLogin, validateAnalysis, handleValidation };
