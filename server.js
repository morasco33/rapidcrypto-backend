// --- server.js (Your Full Backend - ADAPTED with PREFERRED CORS + Investment Fix) ---
require('dotenv').config();

// ... [dotenv debug logs remain unchanged] ...

const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const { body, validationResult, query } = require('express-validator');

const app = express();

const PORT = process.env.PORT || 3001;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const APP_NAME = process.env.APP_NAME || 'RapidCrypto';
const EMAIL_ADDRESS = process.env.EMAIL;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;
const FRONTEND_URL_FOR_EMAILS = process.env.FRONTEND_PRIMARY_URL || `https://famous-scone-fcd9cb.netlify.app`;

// --- Middleware ---
app.use(helmet());
const allowedOrigins = [
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'https://famous-scone-fcd9cb.netlify.app',
  'https://rapidcrypto.org',
  'https://www.rapidcrypto.org',
  process.env.NETLIFY_DEPLOY_URL,
  process.env.FRONTEND_PRIMARY_URL,
  process.env.FRONTEND_WWW_URL
].filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin && NODE_ENV !== 'production') return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());

// --- MongoDB ---
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected...'))
  .catch(err => { console.error('❌ MongoDB connection error:', err.message); process.exit(1); });

// --- Models ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  walletAddress: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verified: { type: Boolean, default: false },
  balance: { type: Number, default: 0.00 },
  assets: [{ name: String, symbol: String, amount: Number }]
}, { timestamps: true });

userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

userSchema.methods.comparePassword = async function(pw) {
  return bcrypt.compare(pw, this.password);
};

const User = mongoose.model('User', userSchema);

const investmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  planId: String,
  planName: String,
  initialAmount: Number,
  currentValue: Number,
  profitRate: Number,
  interestPeriodMs: Number,
  lastInterestAccrualTime: Date,
  startDate: Date,
  maturityDate: Date,
  withdrawalUnlockTime: Date,
  status: String
}, { timestamps: true });
const Investment = mongoose.model('Investment', investmentSchema);

const Transaction = mongoose.model('Transaction', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: String,
  amount: Number,
  description: String,
  relatedInvestmentId: mongoose.Schema.Types.ObjectId,
  timestamp: { type: Date, default: Date.now }
}));

// --- Auth Middleware ---
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ message: 'User not found' });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token invalid or expired' });
  }
};

// --- Investment Plans ---
const INVESTMENT_PLANS = {
  silver: { id: 'silver', name: 'Silver Plan', minAmount: 1500, maxAmount: 10000, profitRatePercent: 2, interestPeriodHours: 48, maturityPeriodDays: 2, withdrawalLockDays: 2 },
  gold: { id: 'gold', name: 'Gold Plan', minAmount: 2500, maxAmount: 25000, profitRatePercent: 5, interestPeriodHours: 24, maturityPeriodDays: 2, withdrawalLockDays: 2 }
};
function getPlanDurationsInMs(plan) {
  return {
    interestPeriodMs: plan.interestPeriodHours * 3600000,
    maturityPeriodMs: plan.maturityPeriodDays * 86400000,
    withdrawalLockPeriodMs: plan.withdrawalLockDays * 86400000
  };
}

// --- Routes ---
app.post('/api/investments', authenticate, [
  body('planId').notEmpty(),
  body('amount').isFloat({ gt: 0 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const { planId, amount } = req.body;
    const plan = INVESTMENT_PLANS[planId];
    if (!plan) throw new Error('Invalid plan');
    if (amount < plan.minAmount || amount > plan.maxAmount) {
      throw new Error(`Amount must be between $${plan.minAmount} and $${plan.maxAmount}`);
    }

    const user = await User.findById(req.user._id).session(session);
    if (!user || user.balance < amount) throw new Error('Insufficient balance');

    user.balance -= amount;
    const now = new Date();
    const durations = getPlanDurationsInMs(plan);

    const inv = new Investment({
      userId: user._id,
      planId: plan.id,
      planName: plan.name,
      initialAmount: amount,
      currentValue: amount,
      profitRate: plan.profitRatePercent,
      interestPeriodMs: durations.interestPeriodMs,
      lastInterestAccrualTime: now,
      startDate: now,
      maturityDate: new Date(now.getTime() + durations.maturityPeriodMs),
      withdrawalUnlockTime: new Date(now.getTime() + durations.withdrawalLockPeriodMs),
      status: 'active'
    });

    const trx = new Transaction({
      userId: user._id,
      type: 'plan_investment',
      amount: -amount,
      description: `Invested $${amount} in ${plan.name}`,
      relatedInvestmentId: inv._id
    });

    await user.save({ session });
    await inv.save({ session });
    await trx.save({ session });

    await session.commitTransaction();
    res.status(201).json({ success: true, newBalance: user.balance, investment: inv });
  } catch (e) {
    await session.abortTransaction();
    res.status(400).json({ success: false, message: e.message });
  } finally {
    session.endSession();
  }
});

app.get('/api/profile', authenticate, async (req, res) => {
  const user = await User.findById(req.user._id);
  if (!user) return res.status(404).json({ success: false, message: 'User not found' });
  res.status(200).json({ success: true, user });
});

app.all('/api/*', (req, res) => res.status(404).json({ success: false, message: 'API endpoint not found.' }));

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
