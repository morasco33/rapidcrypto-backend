// --- server.js (Complete Version with Investment Fix and Balance Deduction) ---
require('dotenv').config();

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
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const EMAIL_ADDRESS = process.env.EMAIL;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;
const FRONTEND_URL_FOR_EMAILS = process.env.FRONTEND_PRIMARY_URL || `http://localhost:5500`;

app.use(helmet());

const allowedOrigins = [
  'http://localhost:5500',
  'https://famous-scone-fcd9cb.netlify.app',
  'https://rapidcrypto.org',
  'https://www.rapidcrypto.org',
  process.env.FRONTEND_PRIMARY_URL,
  process.env.FRONTEND_WWW_URL
].filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
};
app.use(cors(corsOptions));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => { console.error('MongoDB connection error:', err.message); process.exit(1); });

const userSchema = new mongoose.Schema({
  username: String,
  walletAddress: String,
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verified: { type: Boolean, default: false },
  balance: { type: Number, default: 0.00 },
  assets: [{ name: String, symbol: String, amount: { type: Number, default: 0 } }]
}, { timestamps: true });

userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

const User = mongoose.model('User', userSchema);

const investmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
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

const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) throw new Error('User not found');
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

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

// --- API Routes ---
// (Your existing API routes will go here. Ensure they use FRONTEND_URL_FOR_EMAILS for links)
// Example for register route:
app.post('/api/register', authActionLimiter, [body('username').trim().isLength({min:3,max:30}).escape(), body('email').isEmail().normalizeEmail(), body('password').isLength({min:6,max:100})], async (req, res, next) => {
    const errors = validationResult(req); if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    try { const {username,email,password}=req.body; if(await User.findOne({email:email.toLowerCase()})) return res.status(400).json({success:false,message:'Email registered.'});
        const verificationToken=generateCryptoToken(); const user=await User.create({username,email:email.toLowerCase(),password,walletAddress:generateWalletAddress(),emailVerificationToken:verificationToken,emailVerificationTokenExpiry:Date.now()+(24*60*60*1000),balance:0,assets:[]});
        const verificationLink=`${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${verificationToken}&email=${encodeURIComponent(user.email)}`; // Use new const
        await sendEmail({to:user.email,subject:`Verify Your Email for ${APP_NAME}`,html:`<p>Hi ${user.username}, please verify your email by clicking <a href="${verificationLink}">here</a>.</p>`});
        res.status(201).json({success:true,message:'Registered! Verification email sent.'});
    } catch(e){ console.error("Error in /api/register: ", e); next(e);}
});
// ... (REST OF YOUR EXISTING API ROUTES: /api/verify-email, /api/login, /api/profile, /api/investment-plans, etc.) ...
// Make sure to adjust any email link constructions to use FRONTEND_URL_FOR_EMAILS
app.get('/api/verify-email', [query('email').isEmail().normalizeEmail(),query('token').isHexadecimal().isLength({min:64,max:64})], async (req, res, next) => { 
    const errors = validationResult(req); if (!errors.isEmpty()) return res.status(400).json({success:false,message:"Invalid params."});
    try { const {email,token}=req.query; const user=await User.findOne({email,emailVerificationToken:token,emailVerificationTokenExpiry:{$gt:Date.now()}});
        if(!user) return res.status(400).json({success:false,message:'Invalid/expired link.'});
        user.verified=true;user.emailVerificationToken=undefined;user.emailVerificationTokenExpiry=undefined; await user.save({validateBeforeSave:false});
        res.status(200).json({success:true,message:'Email verified.'});
    } catch(e){next(e);}
});
app.post('/api/resend-verification-email', authActionLimiter, [body('email').isEmail().normalizeEmail()], async (req, res, next) => { 
    const errors = validationResult(req); if (!errors.isEmpty()) return res.status(400).json({success:false,message:"Valid email needed."});
    try { const {email}=req.body; const user=await User.findOne({email});
        if(!user||user.verified) return res.status(200).json({success:true,message:user&&user.verified?'Email verified.':'If account exists, link sent.'});
        user.emailVerificationToken=generateCryptoToken();user.emailVerificationTokenExpiry=Date.now()+(24*60*60*1000); await user.save({validateBeforeSave:false});
        const link=`${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${user.emailVerificationToken}&email=${encodeURIComponent(user.email)}`; await sendEmail({to:user.email,subject:`Resent Verify ${APP_NAME}`,html:`<p>New link: <a href="${link}">Verify</a>.</p>`});
        res.status(200).json({success:true,message:'New verification link sent.'});
    } catch(e){next(e);}
});
app.post('/api/login', authActionLimiter, [body('email').isEmail().normalizeEmail(),body('password').notEmpty()], async (req, res, next) => { 
    const errors = validationResult(req); if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    try { const {email,password}=req.body; const user=await User.findOne({email:email.toLowerCase()}).select('+password');
        if(!user||!(await user.comparePassword(password))) return res.status(401).json({success:false,message:'Invalid credentials.'});
        if(!user.verified) return res.status(403).json({success:false,message:'Email not verified.',needsVerification:true});
        const token=jwt.sign({id:user._id},JWT_SECRET,{expiresIn:'1h'});
        const userResponse={_id:user._id,username:user.username,email:user.email,walletAddress:user.walletAddress,balance:user.balance,verified:user.verified,assets:user.assets};
        res.status(200).json({success:true,token,user:userResponse,message:'Login successful!'});
    } catch(e){next(e);}
});
app.get('/api/profile', authenticate, (req, res) => res.status(200).json({success:true,user:req.user}));
app.post('/api/user/set-withdrawal-pin', authenticate, [body('newPin').isNumeric().isLength({min:5,max:5}),body('confirmNewPin').custom((v,{req})=>v===req.body.newPin),body('currentPassword').optional()], async (req, res, next) => { 
    const errors = validationResult(req); if (!errors.isEmpty()) return res.status(400).json({success:false,message:"Invalid PIN data."});
    try { const {currentPassword,newPin}=req.body; const user=await User.findById(req.user._id).select('+password +withdrawalPinHash');
        if(!user)return res.status(404).json({success:false,message:'User not found.'});
        if(user.withdrawalPinHash){if(!currentPassword)return res.status(400).json({success:false,message:'Current password needed.'}); if(!(await user.comparePassword(currentPassword)))return res.status(401).json({success:false,message:'Incorrect password.'});}
        const salt=await bcrypt.genSalt(10);user.withdrawalPinHash=await bcrypt.hash(newPin,salt); await user.save();
        res.status(200).json({success:true,message:'Withdrawal PIN updated.'});
    } catch(e){next(e);}
});
app.get('/api/investment-plans', authenticate, (req, res) => {
    console.log(`DEBUG [server.js ${new Date().toISOString()}]: GET /api/investment-plans | User: ${req.user?.email || 'N/A'}`);
    const frontendPlans=Object.values(INVESTMENT_PLANS).map(p=>({...p}));
    if(frontendPlans?.length) res.status(200).json({success:true,plans:frontendPlans});
    else { console.error("ERROR [server.js]: No plans defined for /api/investment-plans."); res.status(500).json({success:false,message:"Plans unavailable."});}
});

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
      planId,
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

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
