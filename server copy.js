// --- server.js (Your Full Backend - ADAPTED with PREFERRED CORS) ---
require('dotenv').config();

// ---- DOTENV DEBUG LOGS (Keep for now, remove or comment out for production) ----
console.log("----------------------------------------------------------");
console.log("DEBUG [dotenv]: process.env.NODE_ENV:", process.env.NODE_ENV);
console.log("DEBUG [dotenv]: process.env.PORT (from .env):", process.env.PORT);
console.log("DEBUG [dotenv]: process.env.JWT_SECRET (exists?):", process.env.JWT_SECRET ? 'Exists' : 'MISSING!');
console.log("DEBUG [dotenv]: process.env.MONGO_URI (exists?):", process.env.MONGO_URI ? 'Exists' : 'MISSING!');
console.log("DEBUG [dotenv]: process.env.EMAIL from .env:", process.env.EMAIL);
console.log("DEBUG [dotenv]: process.env.EMAIL_PASSWORD (exists?):", process.env.EMAIL_PASSWORD ? 'Exists (value hidden)' : 'MISSING!');
console.log("DEBUG [dotenv]: process.env.FRONTEND_PRIMARY_URL (for CORS/emails):", process.env.FRONTEND_PRIMARY_URL);
console.log("DEBUG [dotenv]: process.env.NETLIFY_DEPLOY_URL (for CORS):", process.env.NETLIFY_DEPLOY_URL);
console.log("----------------------------------------------------------");

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
const { body, validationResult, query, param } = require('express-validator');

const app = express();

// --- Configuration from Environment Variables ---
const PORT = process.env.PORT || 3001;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const APP_NAME = process.env.APP_NAME || 'RapidCrypto';
const EMAIL_ADDRESS = process.env.EMAIL;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;

const FRONTEND_URL_FOR_EMAILS = process.env.FRONTEND_PRIMARY_URL || `https://famous-scone-fcd9cb.netlify.app`;

// --- Critical Environment Variable Checks ---
if (!JWT_SECRET) { console.error('FATAL ERROR: JWT_SECRET not defined.'); process.exit(1); }
if (!MONGO_URI) { console.error('FATAL ERROR: MONGO_URI not defined.'); process.exit(1); }
if (!EMAIL_ADDRESS || !EMAIL_PASSWORD) { console.warn('⚠️ WARNING: Email credentials not fully loaded.'); }
else { console.log("✅ Email credentials seem loaded."); }
if (NODE_ENV === 'production' && !process.env.FRONTEND_PRIMARY_URL) {
    console.warn('⚠️ WARNING: FRONTEND_PRIMARY_URL is not set in environment. This is crucial for email links and CORS.');
}
if (NODE_ENV === 'production' && !process.env.NETLIFY_DEPLOY_URL) {
    console.warn('⚠️ WARNING: NETLIFY_DEPLOY_URL is not set in environment. This is needed for CORS.');
}

app.set('trust proxy', 1);
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

if (NODE_ENV === 'production' && allowedOrigins.length < 3) {
    console.warn("⚠️ WARNING: Production CORS origins might be incomplete. Expected at least Netlify deploy URL and primary domain.");
    console.warn("Current allowedOrigins (excluding localhost):", allowedOrigins.filter(o => !o.includes('localhost')));
}

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin && NODE_ENV !== 'production') {
             return callback(null, true);
        }
        if (allowedOrigins.indexOf(origin) !== -1) {
            return callback(null, true);
        } else {
            const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}. Allowed: ${allowedOrigins.join(', ')}`;
            console.error("CORS Error:", msg);
            return callback(new Error(msg), false);
        }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    credentials: true
};
app.use(cors(corsOptions));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());

mongoose.connect(MONGO_URI)
.then(() => console.log(`✅ MongoDB connected...`))
.catch(err => { console.error('❌ FATAL MongoDB connection error:', err.message); process.exit(1); });
mongoose.connection.on('error', err => console.error('MongoDB runtime error:', err));

const userSchema = new mongoose.Schema({ username: { type: String, trim: true, required: [true, 'Username required.'], index: true }, walletAddress: { type: String, trim: true }, email: { type: String, required: [true, 'Email required.'], unique: true, lowercase: true, trim: true, match: [/\S+@\S+\.\S+/, 'Valid email required.'], index: true }, password: { type: String, required: [true, 'Password required.'], minlength: [6, 'Password min 6.'] }, verified: { type: Boolean, default: false }, emailVerificationToken: { type: String, select: false }, emailVerificationTokenExpiry: { type: Date, select: false }, loginOtp: { type: String, select: false }, loginOtpExpiry: { type: Date, select: false }, withdrawalPinHash: { type: String, select: false }, resetToken: { type: String, select: false }, resetTokenExpiry: { type: Date, select: false }, assets: [{ name: String, symbol: String, amount: { type: Number, default: 0 } }], balance: { type: Number, default: 0.00, min: 0 } }, { timestamps: true });
userSchema.pre('save', async function(next) { if (this.isModified('password') && this.password) { try { const salt = await bcrypt.genSalt(10); this.password = await bcrypt.hash(this.password, salt); } catch (error) { return next(error); }} next(); });
userSchema.methods.comparePassword = async function(pw) { return (pw && this.password) ? bcrypt.compare(pw, this.password) : false; };
userSchema.methods.compareWithdrawalPin = async function(pin) { return (pin && this.withdrawalPinHash) ? bcrypt.compare(pin, this.withdrawalPinHash) : false; };
const User = mongoose.model('User', userSchema);

const investmentSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, planId: { type: String, required: true, index: true }, planName: { type: String, required: true }, initialAmount: { type: Number, required: true, min: [0.01, 'Amount > 0.01.'] }, currentValue: { type: Number, required: true, min: 0 }, profitRate: { type: Number, required: true }, interestPeriodMs: { type: Number, required: true }, lastInterestAccrualTime: { type: Date, default: Date.now }, startDate: { type: Date, default: Date.now }, maturityDate: { type: Date, required: true }, withdrawalUnlockTime: { type: Date, required: true }, status: { type: String, default: 'active', enum: ['active', 'matured', 'withdrawn_early', 'withdrawn_matured', 'cancelled'], index: true } }, { timestamps: true });
const Investment = mongoose.model('Investment', investmentSchema);

const TransactionSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, type: { type: String, required: true, enum: ['deposit_main_balance', 'withdrawal_main_balance', 'plan_investment', 'plan_withdrawal_return', 'interest_accrued_to_plan_value', 'fee', 'admin_credit', 'admin_debit'], index: true }, amount: { type: Number, required: true }, currency: { type: String, default: 'USD' }, description: { type: String, required: true }, status: { type: String, default: 'completed', enum: ['pending', 'completed', 'failed', 'cancelled'], index: true }, relatedInvestmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment', sparse: true, index: true }, referenceId: { type: String, sparse: true, index: true }, meta: { type: mongoose.Schema.Types.Mixed }, timestamp: { type: Date, default: Date.now, index: true } });
const Transaction = mongoose.model('Transaction', TransactionSchema);

const generateWalletAddress = () => `0x${crypto.randomBytes(20).toString('hex')}`;
const generateCryptoToken = (length = 32) => crypto.randomBytes(length).toString('hex');
const generateNumericOtp = (length = 6) => (length < 4 || length > 8) ? "000000" : crypto.randomInt(Math.pow(10, length - 1), Math.pow(10, length) - 1).toString();

const sendEmail = async ({ to, subject, html, text }) => {
    if (!EMAIL_ADDRESS || !EMAIL_PASSWORD) { console.error('ERROR [sendEmail]: Email service not configured.'); throw new Error('Email service configuration missing.');}
    const transporter = nodemailer.createTransport({ service: 'Gmail', auth: { user: EMAIL_ADDRESS, pass: EMAIL_PASSWORD }});
    const mailOptions = { from: `"${APP_NAME}" <${EMAIL_ADDRESS}>`, to, subject, html, text };
    try { await transporter.sendMail(mailOptions); console.log(`✅ Email sent to ${to}. Subject: "${subject}".`);
    } catch (e) { console.error(`❌ Nodemailer error for ${to}:`, e.message); if (e.code === 'EAUTH') throw new Error('Email auth failed.'); throw new Error('Error sending email.');}
};

const authenticate = async (req, res, next) => { const authHeader = req.headers.authorization; let token; if (authHeader && authHeader.startsWith('Bearer ')) { token = authHeader.split(' ')[1]; }
    if (!token) return res.status(401).json({ success: false, message: 'Auth Error: No token.' });
    try { const decoded = jwt.verify(token, JWT_SECRET);
        const currentUser = await User.findById(decoded.id).select('-password -emailVerificationToken -emailVerificationTokenExpiry -loginOtp -loginOtpExpiry -resetToken -resetTokenExpiry -withdrawalPinHash -__v');
        if (!currentUser) return res.status(401).json({ success: false, message: 'Auth Error: User not found.' });
        req.user = currentUser; next();
    } catch (e) {
        let sc=401, msg='Auth Error.', type=e.name;
        if (type==='TokenExpiredError') msg='Session expired.'; else if (type==='JsonWebTokenError') msg='Invalid token.';
        else { console.error('CRITICAL [authenticate]: Unexpected token error -', e); msg='Internal auth error.'; sc=500; }
        console.warn(`WARN [authenticate]: ${msg} (Type: ${type})`); return res.status(sc).json({success:false,message:msg,errorType:type});
    } };

const generalApiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: 'draft-7', legacyHeaders: false, message: { success: false, message: 'Too many requests.' }});
app.use('/api', generalApiLimiter);
const authActionLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { success: false, message: 'Too many auth attempts.' }, skipSuccessfulRequests: true });

const INVESTMENT_PLANS = {
    "silver":   { id: "silver",   name: "Silver Plan", minAmount: 1500,  maxAmount: 10000,  profitRatePercent: 2,  interestPeriodHours: 48, maturityPeriodDays: 14, withdrawalLockDays: 14 },
    "gold":     { id: "gold",     name: "Gold Plan",   minAmount: 2500,  maxAmount: 25000,  profitRatePercent: 5,  interestPeriodHours: 24, maturityPeriodDays: 14, withdrawalLockDays: 14 },
    "premium":  { id: "premium",  name: "Premium Plan",minAmount: 5000,  maxAmount: 50000,  profitRatePercent: 10, interestPeriodHours: 48, maturityPeriodDays: 14, withdrawalLockDays: 14 },
    "platinum": { id: "platinum", name: "Platinum Plan",minAmount: 10000, maxAmount: 100000, profitRatePercent: 20, interestPeriodHours: 12, maturityPeriodDays: 14, withdrawalLockDays: 14 }
};
function getPlanDurationsInMs(plan) { if (!plan || typeof plan.interestPeriodHours !== 'number' || typeof plan.maturityPeriodDays !== 'number' || typeof plan.withdrawalLockDays !== 'number') {
        console.error("ERROR [getPlanDurationsInMs]: Invalid plan config:", plan); throw new Error("Plan config issue.");
    } return { interestPeriodMs: plan.interestPeriodHours*3600000, maturityPeriodMs: plan.maturityPeriodDays*86400000, withdrawalLockPeriodMs: plan.withdrawalLockDays*86400000 };}

app.post('/api/register', authActionLimiter, [body('username').trim().isLength({min:3,max:30}).escape(), body('email').isEmail().normalizeEmail(), body('password').isLength({min:6,max:100})], async (req, res, next) => {
    const errors = validationResult(req); if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    try { const {username,email,password}=req.body; if(await User.findOne({email:email.toLowerCase()})) return res.status(400).json({success:false,message:'Email registered.'});
        const verificationToken=generateCryptoToken(); const user=await User.create({username,email:email.toLowerCase(),password,walletAddress:generateWalletAddress(),emailVerificationToken:verificationToken,emailVerificationTokenExpiry:Date.now()+(24*60*60*1000),balance:0,assets:[]});
        const verificationLink=`${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({to:user.email,subject:`Verify Your Email for ${APP_NAME}`,html:`<p>Hi ${user.username}, please verify your email by clicking <a href="${verificationLink}">here</a>.</p>`});
        res.status(201).json({success:true,message:'Registered! Verification email sent.'});
    } catch(e){ console.error("Error in /api/register: ", e); next(e);}
});
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

app.get('/api/investments', authenticate, async (req, res, next) => {
    try {
        const investments = await Investment.find({ userId: req.user._id }).sort({ startDate: -1 });
        res.status(200).json({
            success: true,
            investments
        });
    } catch (e) {
        console.error(`❌ ERROR [GET /api/investments]:`, e);
        next(new Error("Failed to retrieve investments."));
    }
});

app.post('/api/investments', authenticate, [
    body('planId').trim().notEmpty().escape(),
    body('amount').isFloat({ gt: 0 }).toFloat()
  ], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({
      success: false,
      message: errors.array({ onlyFirstError: true })[0].msg
    });
  
    const session = await mongoose.startSession();
    session.startTransaction();
  
    try {
      const { planId, amount } = req.body;
      const userId = req.user._id;
      const plan = INVESTMENT_PLANS[planId];
  
      if (!plan || plan.id !== planId) throw new Error('Invalid plan.');
      if (amount < plan.minAmount || amount > plan.maxAmount) {
        throw new Error(`Investment amount must be between $${plan.minAmount} and $${plan.maxAmount}.`);
      }
  
      const user = await User.findById(userId).session(session);
      if (!user) throw new Error('User not found.');
      if (user.balance < amount) throw new Error('Insufficient balance.');
  
      user.balance -= amount;
  
      const now = new Date();
      const durations = getPlanDurationsInMs(plan);
  
      const inv = new Investment({
        userId,
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
        userId,
        type: 'plan_investment',
        amount: -amount,
        description: `Invested $${amount.toFixed(2)} in ${plan.name}.`,
        relatedInvestmentId: inv._id,
        meta: { ip: req.ip }
      });
  
      await user.save({ session });
      await inv.save({ session });
      await trx.save({ session });
  
      await session.commitTransaction();
  
      res.status(201).json({
        success: true,
        message: `Successfully invested $${amount.toFixed(2)} in ${plan.name}.`,
        newBalance: user.balance,
        investment: inv
      });
    } catch (e) {
      await session.abortTransaction();
      console.error(`❌ ERROR [POST /api/investments]:`, e);
      if (e.message.includes("Insufficient balance") || e.message.includes("Invalid plan") || e.message.includes("Investment amount must be")) {
          return res.status(400).json({ success: false, message: e.message });
      }
      next(new Error("Investment failed due to a server error."));
    } finally {
      session.endSession();
    }
  });

app.post('/api/investments/:investmentId/withdraw', authenticate, [
    param('investmentId').isMongoId(),
    body('withdrawalPin').isNumeric().isLength({ min: 5, max: 5 })
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, message: errors.array({ onlyFirstError: true })[0].msg });
    }

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const { investmentId } = req.params;
        const { withdrawalPin } = req.body;
        const userId = req.user._id;

        const user = await User.findById(userId).select('+withdrawalPinHash').session(session);
        if (!user) {
            throw new Error('User not found.');
        }

        if (!user.withdrawalPinHash) {
            throw new Error('Withdrawal PIN not set. Please set it in your profile.');
        }
        const isPinMatch = await user.compareWithdrawalPin(withdrawalPin);
        if (!isPinMatch) {
            throw new Error('Incorrect withdrawal PIN.');
        }

        const investment = await Investment.findOne({ _id: investmentId, userId: userId }).session(session);
        if (!investment) {
            throw new Error('Investment not found or does not belong to you.');
        }

        if (investment.status !== 'active' && investment.status !== 'matured') {
            throw new Error(`Investment is not active or matured. Current status: ${investment.status}.`);
        }

        const now = new Date();
        if (now < investment.withdrawalUnlockTime) {
            throw new Error(`Investment not yet unlocked for withdrawal. Unlock date: ${investment.withdrawalUnlockTime.toLocaleDateString()}.`);
        }
        
        const amountToReturn = investment.currentValue;

        user.balance += amountToReturn;
        investment.status = 'withdrawn_matured';

        const trx = new Transaction({
            userId,
            type: 'plan_withdrawal_return',
            amount: amountToReturn,
            description: `Withdrawal of $${amountToReturn.toFixed(2)} from ${investment.planName} (ID: ${investment._id}).`,
            relatedInvestmentId: investment._id,
            meta: { ip: req.ip }
        });

        await user.save({ session });
        await investment.save({ session });
        await trx.save({ session });

        await session.commitTransaction();

        res.status(200).json({
            success: true,
            message: `Successfully withdrew $${amountToReturn.toFixed(2)}. Your new balance is $${user.balance.toFixed(2)}.`,
            newBalance: user.balance,
            updatedInvestment: investment
        });

    } catch (e) {
        await session.abortTransaction();
        console.error(`❌ ERROR [POST /api/investments/:investmentId/withdraw]:`, e);
        if (['User not found', 'Withdrawal PIN not set', 'Incorrect withdrawal PIN', 'Investment not found', 'Investment is not active', 'Investment not yet unlocked'].some(knownMsg => e.message.includes(knownMsg))) {
            return res.status(400).json({ success: false, message: e.message });
        }
        next(new Error("Withdrawal failed due to a server error."));
    } finally {
        session.endSession();
    }
});


app.all('/api/*', (req, res) => { console.warn(`WARN [Server]: 404 API: ${req.method} ${req.originalUrl}`); res.status(404).json({ success: false, message: `API endpoint not found.` }); });
app.use((err, req, res, next) => {
    console.error("❌ GLOBAL ERROR:", {path:req.path,name:err.name,msg:err.message,op:err.isOperational,stack:(NODE_ENV!=='production'&&!err.isOperational)?err.stack:undefined});
    if(res.headersSent) return next(err);
    let sc=err.statusCode||500; let msg=err.message||'Internal error.'; let eType=err.name||'ServerError';
    if(err.name==='ValidationError'){sc=400;msg=`Validation failed: ${Object.values(err.errors).map(el=>el.message).join('. ')}`;eType='ValidationError';}
    else if(err.name==='CastError'&&err.kind==='ObjectId'){sc=400;msg='Invalid ID.';eType='CastError';}
    else if(err.name==='MongoServerError'&&err.code===11000){sc=409;const f=Object.keys(err.keyValue)[0];msg=`${f.charAt(0).toUpperCase()+f.slice(1)} exists.`;eType='DuplicateKeyError';}
    if(NODE_ENV === 'production'&&sc === 500&&!err.isOperational)msg='Unexpected server error.';
    res.status(sc).json({success:false,message:msg,errorType:eType});
});

const serverInstance = app.listen(PORT, () => {
    console.log(`✅ Server ${NODE_ENV} on port ${PORT}`);
    console.log(`   MongoDB URI (prefix): ${MONGO_URI ? MONGO_URI.substring(0,20) + '...' : 'NOT SET'}`);
    console.log(`   Frontend URL for Emails: ${FRONTEND_URL_FOR_EMAILS}`);
    console.log(`   Allowed CORS Origins: ${allowedOrigins.join(', ')}`);
});
const gracefulShutdown = (signal) => { console.log(`\n${signal} received. Shutting down...`); serverInstance.close(() => { console.log('✅ HTTP server closed.'); mongoose.connection.close(false).then(() => { console.log('✅ MongoDB closed.'); process.exit(0); }).catch(err => { console.error("Error closing MongoDB:", err); process.exit(1); }); }); setTimeout(() => { console.error('❌ Graceful shutdown timeout.'); process.exit(1); }, 10000); };
['SIGINT', 'SIGTERM', 'SIGQUIT'].forEach(signal => process.on(signal, () => gracefulShutdown(signal)));
process.on('unhandledRejection', (reason, promise) => { console.error('❌ UNHANDLED REJECTION:', { reason: reason instanceof Error ? { msg: reason.message, stack: reason.stack } : reason }); });
process.on('uncaughtException', (error, origin) => { console.error('❌ UNCAUGHT EXCEPTION:', { err: { msg: error.message, stack: error.stack }, origin }); gracefulShutdown('uncaughtException'); setTimeout(() => process.exit(1), 7000); });