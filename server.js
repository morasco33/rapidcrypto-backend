// --- server.js (Your Full Backend - ADAPTED with PREFERRED CORS & ADMIN FEATURES) ---
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
    'https://famous-scone-fcd9cb.netlify.app', // Your Netlify deploy preview/actual
    'https://rapidcrypto.org',                 // Your primary domain
    'https://www.rapidcrypto.org',             // Your www primary domain
    process.env.NETLIFY_DEPLOY_URL,
    process.env.FRONTEND_PRIMARY_URL,
    process.env.FRONTEND_WWW_URL
].filter(Boolean);

if (NODE_ENV === 'production' && allowedOrigins.filter(o => !o.includes('localhost')).length < 2) { // Adjusted check
    console.warn("⚠️ WARNING: Production CORS origins might be incomplete. Expected at least Netlify deploy URL and primary domain.");
    console.warn("Current allowedOrigins (excluding localhost):", allowedOrigins.filter(o => !o.includes('localhost')));
}


const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests) OR if origin is in allowedOrigins
        // In development, you might be more lenient with !origin.
        // For production, if !origin is not expected, you might want to block it.
        if (!origin && NODE_ENV !== 'production') { // More permissive for local dev tools like Postman
             return callback(null, true);
        }
        if (allowedOrigins.indexOf(origin) !== -1 || (NODE_ENV !== 'production' && !origin) ) { // also allow no origin in dev
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

// --- Schemas & Models ---
const userSchema = new mongoose.Schema({
    username: { type: String, trim: true, required: [true, 'Username required.'], index: true },
    walletAddress: { type: String, trim: true },
    email: { type: String, required: [true, 'Email required.'], unique: true, lowercase: true, trim: true, match: [/\S+@\S+\.\S+/, 'Valid email required.'], index: true },
    password: { type: String, required: [true, 'Password required.'], minlength: [6, 'Password min 6.'] },
    verified: { type: Boolean, default: false }, // Email verified
    adminApproved: { type: Boolean, default: false }, // Approved by an Admin
    isAdmin: { type: Boolean, default: false }, // Is this user an Admin
    emailVerificationToken: { type: String, select: false },
    emailVerificationTokenExpiry: { type: Date, select: false },
    loginOtp: { type: String, select: false },
    loginOtpExpiry: { type: Date, select: false },
    withdrawalPinHash: { type: String, select: false },
    resetToken: { type: String, select: false },
    resetTokenExpiry: { type: Date, select: false },
    assets: [{ name: String, symbol: String, amount: { type: Number, default: 0 } }],
    balance: { type: Number, default: 0.00, min: 0 }
}, { timestamps: true });

userSchema.pre('save', async function(next) { if (this.isModified('password') && this.password) { try { const salt = await bcrypt.genSalt(10); this.password = await bcrypt.hash(this.password, salt); } catch (error) { return next(error); }} next(); });
userSchema.methods.comparePassword = async function(pw) { return (pw && this.password) ? bcrypt.compare(pw, this.password) : false; };
userSchema.methods.compareWithdrawalPin = async function(pin) { return (pin && this.withdrawalPinHash) ? bcrypt.compare(pin, this.withdrawalPinHash) : false; };
const User = mongoose.model('User', userSchema);

const investmentSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, planId: { type: String, required: true, index: true }, planName: { type: String, required: true }, initialAmount: { type: Number, required: true, min: [0.01, 'Amount > 0.01.'] }, currentValue: { type: Number, required: true, min: 0 }, profitRate: { type: Number, required: true }, interestPeriodMs: { type: Number, required: true }, lastInterestAccrualTime: { type: Date, default: Date.now }, startDate: { type: Date, default: Date.now }, maturityDate: { type: Date, required: true }, withdrawalUnlockTime: { type: Date, required: true }, status: { type: String, default: 'active', enum: ['active', 'matured', 'withdrawn_early', 'withdrawn_matured', 'cancelled'], index: true } }, { timestamps: true });
const Investment = mongoose.model('Investment', investmentSchema);

const TransactionSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true }, type: { type: String, required: true, enum: ['deposit_main_balance', 'withdrawal_main_balance', 'plan_investment', 'plan_withdrawal_return', 'interest_accrued_to_plan_value', 'fee', 'admin_credit', 'admin_debit'], index: true }, amount: { type: Number, required: true }, currency: { type: String, default: 'USD' }, description: { type: String, required: true }, status: { type: String, default: 'completed', enum: ['pending', 'completed', 'failed', 'cancelled'], index: true }, relatedInvestmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment', sparse: true, index: true }, referenceId: { type: String, sparse: true, index: true }, meta: { type: mongoose.Schema.Types.Mixed }, timestamp: { type: Date, default: Date.now, index: true } });
const Transaction = mongoose.model('Transaction', TransactionSchema);

// --- Helper Functions ---
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

// --- Authentication Middleware ---
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    let token;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }
    if (!token) {
        return res.status(401).json({ success: false, message: 'Auth Error: No token provided.' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Fetch user, including isAdmin and adminApproved status, excluding sensitive fields for general use
        const currentUser = await User.findById(decoded.id)
            .select('-password -emailVerificationToken -emailVerificationTokenExpiry -loginOtp -loginOtpExpiry -resetToken -resetTokenExpiry -withdrawalPinHash -__v');

        if (!currentUser) {
            return res.status(401).json({ success: false, message: 'Auth Error: User not found for token.' });
        }
        req.user = currentUser; // Attach full user object (with isAdmin, adminApproved)
        next();
    } catch (e) {
        let sc = 401, msg = 'Auth Error.', type = e.name;
        if (type === 'TokenExpiredError') msg = 'Session expired. Please log in again.';
        else if (type === 'JsonWebTokenError') msg = 'Invalid token. Please log in again.';
        else { console.error('CRITICAL [authenticate]: Unexpected token error -', e); msg = 'Internal authentication error.'; sc = 500; }
        console.warn(`WARN [authenticate]: ${msg} (Type: ${type}) for token: ${token ? token.substring(0, 10) + '...' : 'N/A'}`);
        return res.status(sc).json({ success: false, message: msg, errorType: type });
    }
};

// --- Admin Authentication Middleware ---
const adminAuthenticate = async (req, res, next) => {
    authenticate(req, res, () => { // Leverage existing authenticate middleware
        if (!req.user) { // Should have been caught by authenticate, but good failsafe
            return res.status(401).json({ success: false, message: 'Admin Auth: Authentication failed.' });
        }
        if (!req.user.isAdmin) {
            return res.status(403).json({ success: false, message: 'Forbidden: Admin privileges required.' });
        }
        console.log(`ADMIN ACCESS GRANTED: User ${req.user.email} (ID: ${req.user._id}) accessing ${req.method} ${req.originalUrl}`);
        next(); // User is authenticated and is an admin
    });
};


// --- Rate Limiters ---
const generalApiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: 'draft-7', legacyHeaders: false, message: { success: false, message: 'Too many requests from this IP, please try again after 15 minutes.' }});
app.use('/api', generalApiLimiter); // Apply to all /api routes
const authActionLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { success: false, message: 'Too many authentication attempts from this IP, please try again after an hour.' }, skipSuccessfulRequests: true });
// Apply authActionLimiter specifically to sensitive auth routes like login, register, password resets etc.

// --- Investment Plan Definitions ---
const INVESTMENT_PLANS = {
    "silver":   { id: "silver",   name: "Silver Plan", minAmount: 1500,  maxAmount: 10000,  profitRatePercent: 2,  interestPeriodHours: 48, maturityPeriodDays: 14, withdrawalLockDays: 14 },
    "gold":     { id: "gold",     name: "Gold Plan",   minAmount: 2500,  maxAmount: 25000,  profitRatePercent: 5,  interestPeriodHours: 24, maturityPeriodDays: 14, withdrawalLockDays: 14 },
    "premium":  { id: "premium",  name: "Premium Plan",minAmount: 5000,  maxAmount: 50000,  profitRatePercent: 10, interestPeriodHours: 48, maturityPeriodDays: 14, withdrawalLockDays: 14 },
    "platinum": { id: "platinum", name: "Platinum Plan",minAmount: 10000, maxAmount: 100000, profitRatePercent: 20, interestPeriodHours: 12, maturityPeriodDays: 14, withdrawalLockDays: 14 }
};
function getPlanDurationsInMs(plan) { if (!plan || typeof plan.interestPeriodHours !== 'number' || typeof plan.maturityPeriodDays !== 'number' || typeof plan.withdrawalLockDays !== 'number') {
        console.error("ERROR [getPlanDurationsInMs]: Invalid plan config:", plan); throw new Error("Plan config issue.");
    } return { interestPeriodMs: plan.interestPeriodHours*3600000, maturityPeriodMs: plan.maturityPeriodDays*86400000, withdrawalLockPeriodMs: plan.withdrawalLockDays*86400000 };}

// --- API Routes ---

// REGISTRATION
app.post('/api/register', authActionLimiter, [
    body('username').trim().isLength({min:3,max:30}).withMessage('Username must be 3-30 characters.').escape(),
    body('email').isEmail().withMessage('Invalid email address.').normalizeEmail(),
    body('password').isLength({min:6,max:100}).withMessage('Password must be at least 6 characters.')
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    try {
        const {username,email,password}=req.body;
        if(await User.findOne({email:email.toLowerCase()})) {
            return res.status(400).json({success:false,message:'An account with this email already exists.'});
        }
        const verificationToken=generateCryptoToken();
        const user=await User.create({
            username,
            email:email.toLowerCase(),
            password,
            walletAddress:generateWalletAddress(),
            emailVerificationToken:verificationToken,
            emailVerificationTokenExpiry:Date.now()+(24*60*60*1000), // 24 hours
            balance:0,
            assets:[],
            verified: false, // Starts as not verified
            adminApproved: false // Starts as not admin approved
        });
        const verificationLink=`${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({
            to:user.email,
            subject:`Verify Your Email for ${APP_NAME}`,
            html:`<p>Hi ${user.username},</p><p>Welcome to ${APP_NAME}! Please verify your email address by clicking the link below:</p><p><a href="${verificationLink}">Verify Email</a></p><p>This link will expire in 24 hours.</p><p>If you did not create this account, please ignore this email.</p>`
        });
        res.status(201).json({success:true,message:'Registration successful! Please check your email to verify your account.'});
    } catch(e){
        console.error("Error in /api/register: ", e);
        next(e); // Pass to global error handler
    }
});

// EMAIL VERIFICATION
app.get('/api/verify-email', [
    query('email').isEmail().normalizeEmail(),
    query('token').isHexadecimal().isLength({min:64,max:64})
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:"Invalid verification parameters."});
    try {
        const {email,token}=req.query;
        const user=await User.findOne({
            email: email.toLowerCase(),
            emailVerificationToken:token,
            emailVerificationTokenExpiry:{$gt:Date.now()}
        });
        if(!user) return res.status(400).json({success:false,message:'Verification link is invalid or has expired.'});

        user.verified=true;
        user.emailVerificationToken=undefined;
        user.emailVerificationTokenExpiry=undefined;
        // user.adminApproved will remain false until an admin approves
        await user.save({validateBeforeSave:false});
        res.status(200).json({success:true,message:'Email verified successfully! Your account may require admin approval before you can log in.'});
    } catch(e){ next(e); }
});

// RESEND VERIFICATION EMAIL
app.post('/api/resend-verification-email', authActionLimiter, [
    body('email').isEmail().withMessage('Valid email required.').normalizeEmail()
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg });
    try {
        const {email}=req.body;
        const user=await User.findOne({email: email.toLowerCase()});

        if(!user) { // Don't reveal if user exists for security, but handle it
            return res.status(200).json({success:true,message:'If an account with that email exists and is unverified, a new verification link has been sent.'});
        }
        if(user.verified) {
            return res.status(200).json({success:true,message:'This email address has already been verified.'});
        }

        user.emailVerificationToken=generateCryptoToken();
        user.emailVerificationTokenExpiry=Date.now()+(24*60*60*1000);
        await user.save({validateBeforeSave:false});

        const verificationLink=`${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${user.emailVerificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({
            to:user.email,
            subject:`Resent: Verify Your Email for ${APP_NAME}`,
            html:`<p>Hi ${user.username},</p><p>Here is a new link to verify your email address:</p><p><a href="${verificationLink}">Verify Email</a></p><p>This link will expire in 24 hours.</p>`
        });
        res.status(200).json({success:true,message:'A new verification link has been sent to your email address.'});
    } catch(e){ next(e); }
});

// LOGIN
app.post('/api/login', authActionLimiter, [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required.')
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    try {
        const {email,password}=req.body;
        const user=await User.findOne({email:email.toLowerCase()}).select('+password'); // Include password for comparison

        if(!user||!(await user.comparePassword(password))) {
            return res.status(401).json({success:false,message:'Invalid email or password.'});
        }
        if(!user.verified) {
            return res.status(403).json({success:false,message:'Email not verified. Please check your inbox for a verification link.', needsVerification:true, email: user.email});
        }
        // If admin approval is required for non-admin users:
        if (!user.isAdmin && !user.adminApproved) {
            return res.status(403).json({ success: false, message: 'Your account is verified but pending admin approval. Please wait or contact support.' });
        }
        // For admin users, adminApproved might not be relevant if they self-approve or are set manually
        // But if an admin also needs adminApproved=true to login, add that check here.
        // For now, if user.isAdmin is true, they bypass the adminApproved check for login.

        const token=jwt.sign({id:user._id},JWT_SECRET,{expiresIn:'1h'}); // Standard token
        
        // Return only non-sensitive user info
        const userResponse={
            _id:user._id,
            username:user.username,
            email:user.email,
            walletAddress:user.walletAddress,
            balance:user.balance,
            verified:user.verified,
            adminApproved: user.adminApproved,
            isAdmin: user.isAdmin,
            assets:user.assets
        };
        res.status(200).json({success:true,token,user:userResponse,message:'Login successful!'});
    } catch(e){ next(e); }
});

// USER PROFILE
app.get('/api/profile', authenticate, (req, res) => {
    // req.user is already populated by 'authenticate' middleware with selected fields
    res.status(200).json({success:true,user:req.user});
});

// SET/UPDATE WITHDRAWAL PIN
app.post('/api/user/set-withdrawal-pin', authenticate, [
    body('newPin').isNumeric().isLength({min:5,max:5}).withMessage('PIN must be 5 digits.'),
    body('confirmNewPin').custom((value, { req }) => {
        if (value !== req.body.newPin) { throw new Error('PINs do not match.'); }
        return true;
    }),
    body('currentPassword').optional().isString().notEmpty().withMessage('Current password is required if PIN is already set.')
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg });

    try {
        const {currentPassword,newPin}=req.body;
        // Fetch user with password and pin hash for comparison
        const user = await User.findById(req.user._id).select('+password +withdrawalPinHash');
        if(!user) return res.status(404).json({success:false,message:'User not found.'});

        // If PIN is already set, current password is required to change it
        if(user.withdrawalPinHash){
            if(!currentPassword) return res.status(400).json({success:false,message:'Current password is required to change an existing PIN.'});
            if(!(await user.comparePassword(currentPassword))) return res.status(401).json({success:false,message:'Incorrect current password.'});
        }
        const salt=await bcrypt.genSalt(10);
        user.withdrawalPinHash=await bcrypt.hash(newPin,salt);
        await user.save();
        res.status(200).json({success:true,message:'Withdrawal PIN updated successfully.'});
    } catch(e){next(e);}
});

// INVESTMENT PLANS
app.get('/api/investment-plans', authenticate, (req, res) => {
    console.log(`DEBUG [server.js ${new Date().toISOString()}]: GET /api/investment-plans | User: ${req.user?.email || 'N/A'}`);
    const frontendPlans=Object.values(INVESTMENT_PLANS).map(p=>({...p})); // Shallow copy
    if(frontendPlans?.length) res.status(200).json({success:true,plans:frontendPlans});
    else { console.error("ERROR [server.js]: No plans defined for /api/investment-plans."); res.status(500).json({success:false,message:"Investment plans are currently unavailable."});}
});

// GET USER INVESTMENTS
app.get('/api/investments', authenticate, async (req, res, next) => {
    try {
        const investments = await Investment.find({ userId: req.user._id }).sort({ startDate: -1 });
        res.status(200).json({ success: true, investments });
    } catch (e) {
        console.error(`❌ ERROR [GET /api/investments]:`, e);
        next(new Error("Failed to retrieve investments."));
    }
});

// CREATE INVESTMENT
app.post('/api/investments', authenticate, [
    body('planId').trim().notEmpty().withMessage('Plan ID is required.').escape(),
    body('amount').isFloat({ gt: 0 }).withMessage('Investment amount must be greater than 0.').toFloat()
  ], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array({ onlyFirstError: true })[0].msg });

    const session = await mongoose.startSession();
    session.startTransaction();
    try {
      const { planId, amount } = req.body;
      const userId = req.user._id;
      const plan = INVESTMENT_PLANS[planId];

      if (!plan || plan.id !== planId) return res.status(400).json({ success: false, message: 'Invalid investment plan selected.' });
      if (amount < plan.minAmount || amount > plan.maxAmount) {
        return res.status(400).json({ success: false, message: `Investment amount for ${plan.name} must be between $${plan.minAmount} and $${plan.maxAmount}.` });
      }

      const user = await User.findById(userId).session(session);
      if (!user) return res.status(404).json({ success: false, message: 'User not found.'}); // Should not happen if authenticated
      if (user.balance < amount) return res.status(400).json({ success: false, message: 'Insufficient account balance.' });

      user.balance -= amount;

      const now = new Date();
      const durations = getPlanDurationsInMs(plan);

      const inv = new Investment({
        userId, planId: plan.id, planName: plan.name, initialAmount: amount, currentValue: amount,
        profitRate: plan.profitRatePercent, interestPeriodMs: durations.interestPeriodMs,
        lastInterestAccrualTime: now, startDate: now,
        maturityDate: new Date(now.getTime() + durations.maturityPeriodMs),
        withdrawalUnlockTime: new Date(now.getTime() + durations.withdrawalLockPeriodMs),
        status: 'active'
      });

      const trx = new Transaction({
        userId, type: 'plan_investment', amount: -amount,
        description: `Invested $${amount.toFixed(2)} in ${plan.name}.`,
        relatedInvestmentId: inv._id, meta: { ip: req.ip }
      });

      await user.save({ session });
      await inv.save({ session });
      await trx.save({ session });
      await session.commitTransaction();

      res.status(201).json({
        success: true, message: `Successfully invested $${amount.toFixed(2)} in ${plan.name}.`,
        newBalance: user.balance, investment: inv
      });
    } catch (e) {
      await session.abortTransaction();
      console.error(`❌ ERROR [POST /api/investments]:`, e);
      // Avoid sending generic "Investment failed..." if specific error was already sent
      if (!res.headersSent) {
          next(new Error("Investment failed due to a server error. Please try again."));
      }
    } finally {
      session.endSession();
    }
  });

// WITHDRAW FROM INVESTMENT
app.post('/api/investments/:investmentId/withdraw', authenticate, [
    param('investmentId').isMongoId().withMessage('Invalid investment ID format.'),
    body('withdrawalPin').isNumeric().isLength({ min: 5, max: 5 }).withMessage('Withdrawal PIN must be 5 digits.')
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array({ onlyFirstError: true })[0].msg });

    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { investmentId } = req.params;
        const { withdrawalPin } = req.body;
        const userId = req.user._id;

        const user = await User.findById(userId).select('+withdrawalPinHash +password').session(session); // Fetch password for PIN check if needed
        if (!user) return res.status(404).json({ success: false, message: 'User not found.'});

        if (!user.withdrawalPinHash) return res.status(400).json({ success: false, message: 'Withdrawal PIN not set. Please set your PIN in profile settings.'});
        if (!(await user.compareWithdrawalPin(withdrawalPin))) return res.status(401).json({ success: false, message: 'Incorrect withdrawal PIN.'});

        const investment = await Investment.findOne({ _id: investmentId, userId: userId }).session(session);
        if (!investment) return res.status(404).json({ success: false, message: 'Investment not found or does not belong to you.'});

        if (investment.status !== 'active' && investment.status !== 'matured') {
            return res.status(400).json({ success: false, message: `Investment is not in a withdrawable state. Current status: ${investment.status}.`});
        }
        const now = new Date();
        if (now < investment.withdrawalUnlockTime) {
            return res.status(400).json({ success: false, message: `Investment not yet unlocked for withdrawal. Unlock date: ${investment.withdrawalUnlockTime.toLocaleDateString()}.`});
        }

        const amountToReturn = investment.currentValue; // Assuming currentValue is updated by a separate process/job
        user.balance += amountToReturn;
        investment.status = 'withdrawn_matured'; // Or other appropriate status

        const trx = new Transaction({
            userId, type: 'plan_withdrawal_return', amount: amountToReturn,
            description: `Withdrawal of $${amountToReturn.toFixed(2)} from ${investment.planName} (ID: ${investment._id}).`,
            relatedInvestmentId: investment._id, meta: { ip: req.ip }
        });

        await user.save({ session });
        await investment.save({ session });
        await trx.save({ session });
        await session.commitTransaction();

        res.status(200).json({
            success: true, message: `Successfully withdrew $${amountToReturn.toFixed(2)} from investment. Your new balance is $${user.balance.toFixed(2)}.`,
            newBalance: user.balance, updatedInvestment: investment
        });
    } catch (e) {
        await session.abortTransaction();
        console.error(`❌ ERROR [POST /api/investments/:investmentId/withdraw]:`, e);
        if (!res.headersSent) {
            next(new Error("Withdrawal failed due to a server error."));
        }
    } finally {
        session.endSession();
    }
});


// --- ADMIN ROUTES ---
// All routes below are protected by adminAuthenticate

// GET users pending admin approval
app.get('/api/admin/pending-users', adminAuthenticate, async (req, res, next) => {
    try {
        const pendingUsers = await User.find({ verified: true, adminApproved: false })
            .select('username email _id adminApproved verified createdAt');
        res.status(200).json({ success: true, users: pendingUsers });
    } catch (e) {
        console.error("Error in /api/admin/pending-users: ", e);
        next(e);
    }
});

// POST to approve a user
app.post('/api/admin/approve-user/:userId', adminAuthenticate, [
    param('userId').isMongoId().withMessage('Invalid user ID.')
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array({onlyFirstError:true})[0].msg });

    try {
        const userToApprove = await User.findById(req.params.userId);
        if (!userToApprove) return res.status(404).json({ success: false, message: 'User not found.' });
        if (!userToApprove.verified) return res.status(400).json({ success: false, message: 'User must verify their email before admin approval.' });
        if (userToApprove.adminApproved) return res.status(400).json({ success: false, message: 'User is already approved.' });
        
        userToApprove.adminApproved = true;
        await userToApprove.save({ validateBeforeSave: false }); // Avoid re-running password hash if not changed
        
        // Optionally send an email to the user
        await sendEmail({
            to: userToApprove.email,
            subject: `Your ${APP_NAME} Account Approved!`,
            html: `<p>Hi ${userToApprove.username},</p><p>Good news! Your account on ${APP_NAME} has been approved by an administrator. You can now log in and access all features.</p><p>Login here: <a href="${FRONTEND_URL_FOR_EMAILS}/login.html">${FRONTEND_URL_FOR_EMAILS}/login.html</a></p>`
        });

        res.status(200).json({ success: true, message: `User ${userToApprove.username} approved successfully.` });
    } catch (e) {
        console.error("Error in /api/admin/approve-user: ", e);
        next(e);
    }
});

// GET user by email (for admin search)
app.get('/api/admin/user-by-email', adminAuthenticate, [
    query('email').isEmail().withMessage('Valid email required.').normalizeEmail()
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array({onlyFirstError:true})[0].msg });

    try {
        const user = await User.findOne({ email: req.query.email.toLowerCase() })
            .select('-password -emailVerificationToken -emailVerificationTokenExpiry -loginOtp -loginOtpExpiry -resetToken -resetTokenExpiry -withdrawalPinHash'); // Exclude sensitive fields
        if (!user) return res.status(404).json({ success: false, message: 'User not found with that email.' });
        
        res.status(200).json({ success: true, user });
    } catch (e) {
        console.error("Error in /api/admin/user-by-email: ", e);
        next(e);
    }
});

// POST to update user details by admin (e.g., balance, status)
app.post('/api/admin/update-user/:userId', adminAuthenticate, [
    param('userId').isMongoId().withMessage('Invalid user ID.'),
    body('balance').optional().isFloat({ min: 0 }).withMessage('Balance must be a non-negative number.').toFloat(),
    body('username').optional().trim().isLength({min:3, max:30}).withMessage('Username must be 3-30 chars.').escape(),
    body('isAdmin').optional().isBoolean().withMessage('isAdmin must be true or false.').toBoolean(),
    body('verified').optional().isBoolean().withMessage('verified must be true or false.').toBoolean(),
    body('adminApproved').optional().isBoolean().withMessage('adminApproved must be true or false.').toBoolean()
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array({onlyFirstError:true}) });

    try {
        const userToUpdate = await User.findById(req.params.userId);
        if (!userToUpdate) return res.status(404).json({ success: false, message: 'User not found.' });

        const updatedFields = {};
        if (req.body.balance !== undefined) { userToUpdate.balance = req.body.balance; updatedFields.balance = req.body.balance; }
        if (req.body.username !== undefined) { userToUpdate.username = req.body.username; updatedFields.username = req.body.username; }
        if (req.body.isAdmin !== undefined) { userToUpdate.isAdmin = req.body.isAdmin; updatedFields.isAdmin = req.body.isAdmin; }
        if (req.body.verified !== undefined) { userToUpdate.verified = req.body.verified; updatedFields.verified = req.body.verified; }
        if (req.body.adminApproved !== undefined) { userToUpdate.adminApproved = req.body.adminApproved; updatedFields.adminApproved = req.body.adminApproved; }
        
        if (Object.keys(updatedFields).length === 0) {
            return res.status(400).json({ success: false, message: 'No valid fields provided for update.' });
        }

        await userToUpdate.save({ validateBeforeSave: true }); // Run validations for new username etc.
        
        console.log(`ADMIN ACTION: User ${req.user.email} updated user ${userToUpdate.email}. Changes: ${JSON.stringify(updatedFields)}`);

        // Return user without sensitive data
        const returnUser = userToUpdate.toObject();
        delete returnUser.password; delete returnUser.emailVerificationToken; delete returnUser.emailVerificationTokenExpiry;
        delete returnUser.loginOtp; delete returnUser.loginOtpExpiry; delete returnUser.resetToken; delete returnUser.resetTokenExpiry;
        delete returnUser.withdrawalPinHash;

        res.status(200).json({ success: true, message: 'User updated successfully.', user: returnUser });
    } catch (e) {
        console.error("Error in /api/admin/update-user: ", e);
        next(e);
    }
});

// POST to resend verification email for a user (by Admin)
app.post('/api/admin/resend-verification/:userId', adminAuthenticate, [
    param('userId').isMongoId().withMessage('Invalid user ID.')
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array({onlyFirstError:true})[0].msg });

    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
        if (user.verified) return res.status(400).json({ success: false, message: 'This user is already email-verified.' });

        user.emailVerificationToken = generateCryptoToken();
        user.emailVerificationTokenExpiry = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
        await user.save({ validateBeforeSave: false });

        const verificationLink = `${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${user.emailVerificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({
            to: user.email,
            subject: `ACTION REQUIRED: Verify Your Email for ${APP_NAME} (Admin Resend)`,
            html: `<p>Hi ${user.username},</p><p>An administrator has requested to resend your email verification link for your account at ${APP_NAME}.</p><p>Please verify your email by clicking the link below:</p><p><a href="${verificationLink}">Verify Email Address</a></p><p>This link will expire in 24 hours.</p>`
        });
        res.status(200).json({ success: true, message: 'Verification email has been resent to the user.' });
    } catch (e) {
        console.error("Error in /api/admin/resend-verification: ", e);
        next(e);
    }
});
// --- END ADMIN ROUTES ---


// --- Catch-all & Error Handling ---
app.all('/api/*', (req, res) => {
    console.warn(`WARN [Server]: 404 API Route Not Found: ${req.method} ${req.originalUrl} from IP ${req.ip}`);
    res.status(404).json({ success: false, message: `The API endpoint ${req.originalUrl} was not found on this server.` });
});

app.use((err, req, res, next) => {
    console.error("❌ GLOBAL ERROR HANDLER:", {
        path: req.path,
        name: err.name,
        message: err.message,
        isOperational: err.isOperational, // Add this if you use custom AppError class
        stack: (NODE_ENV !== 'production' && !err.isOperational) ? err.stack : undefined
    });

    if (res.headersSent) {
        return next(err); // Delegate to default Express error handler if headers already sent
    }

    let statusCode = err.statusCode || 500;
    let message = err.message || 'An unexpected internal server error occurred.';
    let errorType = err.name || 'ServerError';

    if (err.name === 'ValidationError') { // Mongoose validation error
        statusCode = 400;
        message = `Validation Failed: ${Object.values(err.errors).map(el => el.message).join('. ')}`;
        errorType = 'ValidationError';
    } else if (err.name === 'CastError' && err.kind === 'ObjectId') {
        statusCode = 400;
        message = 'Invalid ID format provided.';
        errorType = 'CastError';
    } else if (err.name === 'MongoServerError' && err.code === 11000) { // Duplicate key
        statusCode = 409; // Conflict
        const field = Object.keys(err.keyValue)[0];
        message = `An account with this ${field} already exists.`;
        errorType = 'DuplicateKeyError';
    } else if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        statusCode = 401; // Unauthorized for token issues not caught by authenticate middleware itself
        message = err.name === 'TokenExpiredError' ? 'Session has expired. Please log in again.' : 'Invalid session token. Please log in again.';
        errorType = err.name;
    }


    // For production, hide detailed error messages for 500 errors unless they are operational
    if (NODE_ENV === 'production' && statusCode === 500 && !err.isOperational) {
        message = 'An unexpected server error occurred. Please try again later.';
    }

    res.status(statusCode).json({
        success: false,
        message: message,
        errorType: errorType
        // stack: NODE_ENV === 'development' ? err.stack : undefined // Optionally include stack in dev
    });
});

// --- Start Server & Graceful Shutdown ---
const serverInstance = app.listen(PORT, () => {
    console.log(`✅ Server running in ${NODE_ENV} mode on port ${PORT}`);
    console.log(`   MongoDB URI (prefix): ${MONGO_URI ? MONGO_URI.substring(0,MONGO_URI.indexOf('@') > 0 ? MONGO_URI.indexOf('@') : 20) + '...' : 'NOT SET'}`);
    console.log(`   Frontend URL for Emails: ${FRONTEND_URL_FOR_EMAILS}`);
    console.log(`   Allowed CORS Origins: ${allowedOrigins.join(', ')}`);
});

const gracefulShutdown = (signal) => {
    console.log(`\n${signal} received. Initiating graceful shutdown...`);
    serverInstance.close(() => {
        console.log('✅ HTTP server closed.');
        mongoose.connection.close(false).then(() => {
            console.log('✅ MongoDB connection closed.');
            process.exit(0);
        }).catch(err => {
            console.error("❌ Error closing MongoDB connection during shutdown:", err);
            process.exit(1);
        });
    });
    // Force shutdown if graceful shutdown fails after timeout
    setTimeout(() => {
        console.error('❌ Graceful shutdown timeout. Forcing exit.');
        process.exit(1);
    }, 10000); // 10 seconds
};
['SIGINT', 'SIGTERM', 'SIGQUIT'].forEach(signal => process.on(signal, () => gracefulShutdown(signal)));

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ UNHANDLED REJECTION at:', promise, 'reason:', reason instanceof Error ? { message: reason.message, stack: reason.stack } : reason);
    // Optionally, throw error to trigger uncaughtException handler for consistent shutdown
    // throw reason;
});
process.on('uncaughtException', (error, origin) => {
    console.error('❌ UNCAUGHT EXCEPTION:', { error: { message: error.message, stack: error.stack }, origin: origin });
    // It's critical to shut down on uncaught exceptions as the application is in an unknown state
    gracefulShutdown('uncaughtException');
    // Ensure process exits after shutdown attempt, even if graceful fails
    setTimeout(() => process.exit(1), 7000);
});