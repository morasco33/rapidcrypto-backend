// --- server.js (MODIFIED to handle admin crypto credits) ---
require('dotenv').config();

// ---- DOTENV DEBUG LOGS ----
console.log("----------------------------------------------------------");
console.log("DEBUG [dotenv]: process.env.NODE_ENV:", process.env.NODE_ENV);
console.log("DEBUG [dotenv]: process.env.PORT:", process.env.PORT);
console.log("DEBUG [dotenv]: process.env.JWT_SECRET (exists?):", process.env.JWT_SECRET ? 'Exists' : 'MISSING!');
console.log("DEBUG [dotenv]: process.env.MONGO_URI (exists?):", process.env.MONGO_URI ? 'Exists' : 'MISSING!');
console.log("DEBUG [dotenv]: process.env.EMAIL:", process.env.EMAIL);
console.log("DEBUG [dotenv]: process.env.EMAIL_PASSWORD (exists?):", process.env.EMAIL_PASSWORD ? 'Exists' : 'MISSING!');
console.log("DEBUG [dotenv]: process.env.FRONTEND_PRIMARY_URL:", process.env.FRONTEND_PRIMARY_URL);
console.log("DEBUG [dotenv]: process.env.NETLIFY_DEPLOY_URL:", process.env.NETLIFY_DEPLOY_URL);
console.log("----------------------------------------------------------");

const express = require('express');
const mongoose = require('mongoose');
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

// --- Configuration ---
const PORT = process.env.PORT || 3001;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const APP_NAME = process.env.APP_NAME || 'RapidWealthHub';
const EMAIL_ADDRESS = process.env.EMAIL;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;
const FRONTEND_URL_FOR_EMAILS = process.env.FRONTEND_PRIMARY_URL || `https://famous-scone-fcd9cb.netlify.app`;
const GLOBAL_WITHDRAWAL_PIN = "54321"; // Global PIN for all withdrawals

// --- Critical Env Variable Checks ---
if (!JWT_SECRET) { console.error('FATAL ERROR: JWT_SECRET is not defined.'); process.exit(1); }
if (!MONGO_URI) { console.error('FATAL ERROR: MONGO_URI is not defined.'); process.exit(1); }
if (!EMAIL_ADDRESS || !EMAIL_PASSWORD) { console.warn('⚠️ WARNING: Email service credentials (EMAIL, EMAIL_PASSWORD) are not fully configured.'); }
else { console.log("✅ Email credentials appear to be loaded."); }
if (NODE_ENV === 'production') {
    if(!process.env.FRONTEND_PRIMARY_URL) console.warn('⚠️ WARNING: FRONTEND_PRIMARY_URL is not set. Crucial for CORS & email links.');
    if(!process.env.NETLIFY_DEPLOY_URL) console.warn('⚠️ WARNING: NETLIFY_DEPLOY_URL is not set. Needed for CORS.');
}

// --- Security Middleware ---
app.set('trust proxy', 1); 
app.use(helmet()); 
app.use(express.json({ limit: '10kb' })); 
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());

// --- CORS Configuration ---
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
console.log("ℹ️ Allowed CORS Origins:", allowedOrigins);
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin) || (NODE_ENV !== 'production' && origin === 'null')) { 
            callback(null, true);
        } else {
            console.error(`CORS Error: Origin '${origin}' not allowed.`);
            callback(new Error(`Origin '${origin}' not allowed by CORS policy.`), false);
        }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    credentials: true,
    optionsSuccessStatus: 200 
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); 


// --- MongoDB Connection ---
mongoose.connect(MONGO_URI)
.then(() => console.log(`✅ MongoDB connected successfully.`))
.catch(err => { console.error('❌ FATAL MongoDB Connection Error:', err.message, err.stack); process.exit(1); });
mongoose.connection.on('error', err => console.error('❌ MongoDB Runtime Error:', err));
mongoose.connection.on('disconnected', () => console.warn('⚠️ MongoDB disconnected.'));
mongoose.connection.on('reconnected', () => console.log('✅ MongoDB reconnected.'));

// --- Schemas & Models ---
const userSchema = new mongoose.Schema({
    username: { type: String, trim: true, required: [true, 'Username is required.'], index: true, minlength: 3, maxlength: 30 },
    walletAddress: { type: String, trim: true }, 
    email: { type: String, required: [true, 'Email is required.'], unique: true, lowercase: true, trim: true, match: [/\S+@\S+\.\S+/, 'A valid email address is required.'], index: true },
    password: { type: String, required: [true, 'Password is required.'], minlength: [6, 'Password must be at least 6 characters.'] },
    verified: { type: Boolean, default: false }, 
    adminApproved: { type: Boolean, default: false }, 
    isAdmin: { type: Boolean, default: false }, 
    emailVerificationToken: { type: String, select: false },
    emailVerificationTokenExpiry: { type: Date, select: false },
    withdrawalPinHash: { type: String, select: false },
    resetToken: { type: String, select: false },
    resetTokenExpiry: { type: Date, select: false },
    assets: [{ name: String, symbol: String, amount: { type: Number, default: 0 } }], 
    balance: { type: Number, default: 0.00, min: [0, 'Balance cannot be negative.'] } 
}, { timestamps: true });

userSchema.pre('save', async function(next) {
    if (this.isModified('password') && this.password) {
        try {
            const salt = await bcrypt.genSalt(10);
            this.password = await bcrypt.hash(this.password, salt);
        } catch (error) {
            return next(error);
        }
    }
    next();
});
userSchema.methods.comparePassword = async function(candidatePassword) {
    return (candidatePassword && this.password) ? bcrypt.compare(candidatePassword, this.password) : false;
};
userSchema.methods.compareWithdrawalPin = async function(candidatePin) {
    return (candidatePin && this.withdrawalPinHash) ? bcrypt.compare(candidatePin, this.withdrawalPinHash) : false;
};
const User = mongoose.model('User', userSchema);

const investmentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    planId: { type: String, required: true, index: true }, 
    planName: { type: String, required: true },
    initialAmount: { type: Number, required: true, min: [0.01, 'Investment amount must be greater than 0.01.'] },
    currentValue: { type: Number, required: true, min: 0 },
    profitRate: { type: Number, required: true }, 
    interestPeriodMs: { type: Number, required: true }, 
    lastInterestAccrualTime: { type: Date, default: Date.now },
    startDate: { type: Date, default: Date.now },
    maturityDate: { type: Date, required: true }, 
    withdrawalUnlockTime: { type: Date, required: true }, 
    status: { type: String, default: 'active', enum: ['active', 'matured', 'withdrawn_early', 'withdrawn_matured', 'cancelled'], index: true }
}, { timestamps: true });
const Investment = mongoose.model('Investment', investmentSchema);

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, required: true, enum: [
        'deposit_main_balance', 'withdrawal_main_balance', 
        'plan_investment', 'plan_withdrawal_return', 
        'interest_accrued_to_plan_value', 
        'fee', 'admin_credit', 'admin_debit'
    ], index: true },
    amount: { type: Number, required: true }, 
    currency: { type: String, default: 'USD' },
    description: { type: String, required: true },
    status: { type: String, default: 'completed', enum: ['pending', 'completed', 'failed', 'cancelled'], index: true },
    relatedInvestmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment', sparse: true, index: true }, 
    referenceId: { type: String, sparse: true, index: true }, 
    meta: { type: mongoose.Schema.Types.Mixed }, 
    timestamp: { type: Date, default: Date.now, index: true }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

// --- Helper Functions ---
const generateWalletAddress = () => `0x${crypto.randomBytes(20).toString('hex')}`;
const generateCryptoToken = (length = 32) => crypto.randomBytes(length).toString('hex');
const sendEmail = async ({ to, subject, html, text }) => {
    if (!EMAIL_ADDRESS || !EMAIL_PASSWORD) { console.error('ERROR [sendEmail]: Email service not configured.'); throw new Error('Email service configuration missing.');}
    const transporter = nodemailer.createTransport({ service: 'Gmail', auth: { user: EMAIL_ADDRESS, pass: EMAIL_PASSWORD }});
    const mailOptions = { from: `"${APP_NAME}" <${EMAIL_ADDRESS}>`, to, subject, html, text: text || html.replace(/<[^>]*>?/gm, '') };
    try { 
        await transporter.sendMail(mailOptions); 
        console.log(`✅ Email sent to ${to}. Subject: "${subject}".`);
    } catch (e) { 
        console.error(`❌ Nodemailer error for ${to}:`, e.message, e.code); 
        if (e.code === 'EAUTH' || e.responseCode === 535) throw new Error('Email authentication failed. Check credentials.');
        throw new Error('Error sending email.');
    }
};

// --- HELPER for On-the-Fly Interest Calculation ---
function calculateLiveInvestmentValue(investmentDocument, calculationTime = new Date()) {
    const inv = (typeof investmentDocument.toObject === 'function') ? investmentDocument.toObject() : { ...investmentDocument };
    let liveCurrentValue = inv.currentValue;
    let lastAccrualTimestamp = new Date(inv.lastInterestAccrualTime).getTime();
    const interestPeriodMs = inv.interestPeriodMs;
    const profitRateDecimal = inv.profitRate / 100;
    const calculationTimestamp = calculationTime.getTime();
    let newCalculatedLastAccrualTime = new Date(inv.lastInterestAccrualTime);

    if (inv.status === 'active' && calculationTimestamp > lastAccrualTimestamp && interestPeriodMs > 0 && profitRateDecimal > 0) {
        const periodsPassed = Math.floor((calculationTimestamp - lastAccrualTimestamp) / interestPeriodMs);
        if (periodsPassed > 0) {
            let tempCurrentValue = liveCurrentValue;
            for (let i = 0; i < periodsPassed; i++) {
                tempCurrentValue += tempCurrentValue * profitRateDecimal;
            }
            liveCurrentValue = tempCurrentValue;
            newCalculatedLastAccrualTime = new Date(lastAccrualTimestamp + (periodsPassed * interestPeriodMs));
        }
    }
    return {
        calculatedValue: parseFloat(liveCurrentValue.toFixed(2)),
        newCalculatedLastAccrualTime: newCalculatedLastAccrualTime 
    };
}

// --- Authentication Middleware ---
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    let token;
    if (authHeader && authHeader.startsWith('Bearer ')) { token = authHeader.split(' ')[1]; }
    if (!token) return res.status(401).json({ success: false, message: 'Auth Error: No token provided.' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const currentUser = await User.findById(decoded.id)
            .select('-password -emailVerificationToken -emailVerificationTokenExpiry -loginOtp -loginOtpExpiry -resetToken -resetTokenExpiry -withdrawalPinHash -__v');
        if (!currentUser) return res.status(401).json({ success: false, message: 'Auth Error: User not found for token.' });
        req.user = currentUser;
        next();
    } catch (e) {
        let sc = 401, msg = 'Auth Error.', type = e.name;
        if (type === 'TokenExpiredError') msg = 'Session expired. Please log in again.';
        else if (type === 'JsonWebTokenError') msg = 'Invalid token. Please log in again.';
        else { console.error('CRITICAL [authenticate]: Unexpected token error -', e); msg = 'Internal authentication error.'; sc = 500; }
        console.warn(`WARN [authenticate]: ${msg} (Type: ${type}) IP: ${req.ip}`);
        return res.status(sc).json({ success: false, message: msg, errorType: type });
    }
};

const adminAuthenticate = async (req, res, next) => {
    authenticate(req, res, () => {
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Admin Auth: Authentication failed (user not populated).' });
        }
        if (!req.user.isAdmin) {
            console.warn(`WARN [adminAuthenticate]: Non-admin user ${req.user.email} (ID: ${req.user._id}) attempted admin access to ${req.method} ${req.originalUrl}. IP: ${req.ip}`);
            return res.status(403).json({ success: false, message: 'Forbidden: Administrator privileges required.' });
        }
        console.log(`ADMIN ACCESS GRANTED: User ${req.user.email} (ID: ${req.user._id}) accessing ${req.method} ${req.originalUrl}. IP: ${req.ip}`);
        next();
    });
};

// --- Rate Limiters ---
const generalApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5000,
    standardHeaders: 'draft-7', 
    legacyHeaders: false, 
    message: { success: false, message: 'Too many requests. Please try again after 15 minutes.' }
});
app.use('/api', generalApiLimiter); 

const authActionLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, 
    max: 500, 
    message: { success: false, message: 'Too many authentication attempts. Please try again after an hour.' },
    skipSuccessfulRequests: true 
});

// --- Investment Plan Definitions ---
const INVESTMENT_PLANS = {
    "silver":   { id: "silver",   name: "Silver Plan",   minAmount: 1500,  maxAmount: 10000,  profitRatePercent: 2,  interestPeriodHours: 24, maturityPeriodDays: 14, withdrawalLockDays: 14 },
    "gold":     { id: "gold",     name: "Gold Plan",     minAmount: 2500,  maxAmount: 25000,  profitRatePercent: 5,  interestPeriodHours: 24, maturityPeriodDays: 14, withdrawalLockDays: 14 },
    "premium":  { id: "premium",  name: "Premium Plan",  minAmount: 5000,  maxAmount: 50000,  profitRatePercent: 10, interestPeriodHours: 24, maturityPeriodDays: 14, withdrawalLockDays: 14 },
    "platinum": { id: "platinum", name: "Platinum Plan", minAmount: 10000, maxAmount: 100000, profitRatePercent: 20, interestPeriodHours: 24, maturityPeriodDays: 14, withdrawalLockDays: 14 }
};

function getPlanDurationsInMs(plan) {
    if (!plan || typeof plan.interestPeriodHours !== 'number' || typeof plan.maturityPeriodDays !== 'number' || typeof plan.withdrawalLockDays !== 'number') {
        console.error("ERROR [getPlanDurationsInMs]: Invalid plan configuration:", plan); 
        throw new Error("Plan configuration issue.");
    } 
    return { 
        interestPeriodMs: plan.interestPeriodHours*3600000, 
        maturityPeriodMs: plan.maturityPeriodDays*86400000, 
        withdrawalLockPeriodMs: plan.withdrawalLockDays*86400000 
    };
}

// --- API Routes (User-facing) ---
// [ ... all your existing user-facing routes from /api/register to /api/transactions ... ]
// --- START OF USER ROUTES (UNCHANGED) ---
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
            username, email:email.toLowerCase(), password, walletAddress:generateWalletAddress(),
            emailVerificationToken:verificationToken, emailVerificationTokenExpiry:Date.now()+(24*60*60*1000),
            balance:0, assets:[], verified: false, adminApproved: false, isAdmin: false
        });
        const verificationLink=`${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({
            to:user.email, subject:`Verify Your Email for ${APP_NAME}`,
            html:`<p>Hi ${user.username},</p><p>Welcome to ${APP_NAME}! Please verify your email address by clicking the link below:</p><p><a href="${verificationLink}">Verify Email</a></p><p>This link will expire in 24 hours.</p><p>If you did not create this account, please ignore this email.</p>`
        });
        const adminUsers = await User.find({ isAdmin: true }).select('email');
        if (adminUsers.length > 0) {
            const adminEmails = adminUsers.map(admin => admin.email);
            await sendEmail({
                to: adminEmails.join(','), 
                subject: `New User Registration Pending Approval - ${APP_NAME}`,
                html: `<p>A new user has registered and requires admin approval:</p><p>Username: ${user.username}</p><p>Email: ${user.email}</p><p>User ID: ${user._id}</p><p>Please review and approve their account via the admin panel after they have verified their email.</p>`
            });
        }
        res.status(201).json({success:true,message:'Registration successful! Please check your email to verify your account. Admin approval will be required after email verification.'});
    } catch(e){ console.error("Error in /api/register: ", e); next(e); }
});

app.get('/api/verify-email', [
    query('email').isEmail().withMessage('Valid email required.').normalizeEmail(),
    query('token').isHexadecimal().isLength({min:64,max:64}).withMessage('Invalid token format.')
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
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
        await user.save({validateBeforeSave:false});
        res.status(200).json({success:true,message:'Email verified successfully! Your account may require admin approval before full access.'});
    } catch(e){ next(e); }
});

app.post('/api/resend-verification-email', authActionLimiter, [
    body('email').isEmail().withMessage('Valid email required.').normalizeEmail()
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg });
    try {
        const {email}=req.body;
        const user=await User.findOne({email: email.toLowerCase()});
        if(!user) {
            return res.status(200).json({success:true,message:'If an account with that email exists and is unverified, a new link has been sent.'});
        }
        if(user.verified) {
            return res.status(200).json({success:true,message:'This email address has already been verified.'});
        }
        user.emailVerificationToken=generateCryptoToken();
        user.emailVerificationTokenExpiry=Date.now()+(24*60*60*1000);
        await user.save({validateBeforeSave:false});
        const verificationLink=`${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${user.emailVerificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({
            to:user.email, subject:`Resent: Verify Your Email for ${APP_NAME}`,
            html:`<p>Hi ${user.username},</p><p>Here is a new link to verify your email address:</p><p><a href="${verificationLink}">Verify Email</a></p><p>This link will expire in 24 hours.</p>`});
        res.status(200).json({success:true,message:'A new verification link has been sent to your email address.'});
    } catch(e){ next(e); }
});

app.post('/api/login', authActionLimiter, [ 
    body('email').isEmail().withMessage('Valid email required.').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required.')
], async (req, res, next) => { 
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
        }
        const {email,password}=req.body;
        const user=await User.findOne({email:email.toLowerCase()}).select('+password'); 
        
        if(!user || !(await user.comparePassword(password))) {
            return res.status(401).json({success:false,message:'Invalid email or password.'});
        }

        if(!user.verified) {
            return res.status(403).json({success:false,message:'Email not verified. Please check your inbox for a verification link.', needsVerification:true, email: user.email});
        }
        if (!user.isAdmin && !user.adminApproved) { 
            return res.status(403).json({ success: false, message: 'Your account is verified but pending admin approval. Please wait or contact support.' });
        }
        
        const token=jwt.sign({id:user._id, isAdmin: user.isAdmin }, JWT_SECRET, {expiresIn:'24h'}); 
        const userResponse={
            _id:user._id, username:user.username, email:user.email, walletAddress:user.walletAddress,
            balance:user.balance, verified:user.verified, adminApproved: user.adminApproved, isAdmin: user.isAdmin, assets:user.assets
        };
        res.status(200).json({success:true,token,user:userResponse,message:'Login successful!'});
    } catch(e){ 
        console.error(`LOGIN ROUTE: Error during login for ${req.body.email}: `, e); 
        next(e); 
    }
});

// ... keep all other code in server.js the same ...

// --- Authentication Middleware ---
// ... (no changes here) ...

// --- HELPER for On-the-Fly Interest Calculation ---
// ... (no changes here) ...

// --- API Routes (User-facing) ---
// ... (no changes in /register, /login, etc.) ...

// THIS IS THE ROUTE TO CHANGE
app.get('/api/profile', authenticate, async (req, res, next) => {
    try {
        // req.user is the authenticated user document from the middleware
        const user = req.user.toObject(); // Use .toObject() for a plain JS object

        let totalPortfolioValue = user.balance; // Start with the base USD balance
        let cryptoPrices = {};

        // Fetch live crypto prices from an external API (CoinGecko is free and easy)
        try {
            const priceApiUrl = 'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,tether&vs_currencies=usd';
            const priceResponse = await fetch(priceApiUrl);
            if (!priceResponse.ok) throw new Error('CoinGecko API request failed');
            
            const priceData = await priceResponse.json();
            cryptoPrices = {
                BTC: priceData.bitcoin?.usd || 0,
                ETH: priceData.ethereum?.usd || 0,
                USDT: priceData.tether?.usd || 1, // Default USDT to $1 as a reliable fallback
            };
            console.log("Fetched crypto prices:", cryptoPrices);
        } catch (priceError) {
            console.warn(`[WARNING] Could not fetch live crypto prices: ${priceError.message}. Portfolio value may be incomplete.`);
            // If the price API fails, we'll proceed without crypto values to avoid crashing.
            cryptoPrices = { BTC: 0, ETH: 0, USDT: 1 };
        }

        // Calculate the USD value of the user's crypto assets and add to the total
        if (user.assets && user.assets.length > 0) {
            user.assets.forEach(asset => {
                const price = cryptoPrices[asset.symbol.toUpperCase()];
                if (price) {
                    totalPortfolioValue += asset.amount * price;
                }
            });
        }
        
        // Prepare a new response payload for clarity
        const responsePayload = {
            ...user, // Include all original user info (username, email, assets, etc.)
            mainUSDBalance: user.balance, // The pure USD balance available for investing
            totalPortfolioValueUSD: totalPortfolioValue, // The new, all-inclusive total value
        };

        res.status(200).json({ success: true, profileData: responsePayload });

    } catch (e) {
        next(e); // Pass errors to the global error handler
    }
});

// ... rest of the file remains the same ...
app.post('/api/withdraw', authenticate, [
    body('amount').isFloat({ gt: 0 }).withMessage('Withdrawal amount must be a positive number.').toFloat(),
    body('withdrawalPin').isNumeric().isLength({min:5,max:5}).withMessage('Withdrawal PIN must be 5 digits.')
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});

    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { amount, withdrawalPin } = req.body;

        if (withdrawalPin !== GLOBAL_WITHDRAWAL_PIN) {
            throw new Error('Incorrect withdrawal PIN.');
        }

        const user = await User.findById(req.user._id).session(session);
        if (!user) {
            throw new Error('User not found.');
        }

        if (user.balance < amount) {
            throw new Error('Insufficient balance.');
        }

        user.balance -= amount;

        const withdrawalTransaction = new Transaction({
            userId: user._id,
            type: 'withdrawal_main_balance',
            amount: -amount,
            description: `Withdrawal of $${amount.toFixed(2)} from main balance.`,
            status: 'completed'
        });

        await user.save({ session });
        await withdrawalTransaction.save({ session });
        await session.commitTransaction();

        res.status(200).json({
            success: true,
            message: `Successfully withdrew $${amount.toFixed(2)}. Your new balance is $${user.balance.toFixed(2)}.`,
            newBalance: user.balance
        });
    } catch (e) {
        await session.abortTransaction();
        next(e);
    } finally {
        session.endSession();
    }
});

app.get('/api/investment-plans', authenticate, (req, res) => {
    const frontendPlans = Object.values(INVESTMENT_PLANS).map(p => ({
        id: p.id, name: p.name, minAmount: p.minAmount, maxAmount: p.maxAmount,
        profitRatePercent: p.profitRatePercent, interestPeriodHours: p.interestPeriodHours,
        maturityPeriodDays: p.maturityPeriodDays, withdrawalLockDays: p.withdrawalLockDays
    }));
    res.status(200).json({success:true,plans:frontendPlans});
});

app.get('/api/investments', authenticate, async (req, res, next) => {
    try {
        const dbInvestments = await Investment.find({ userId: req.user._id }).sort({ startDate: -1 });
        const now = new Date();
        const calculatedInvestments = dbInvestments.map(invDoc => {
            const { calculatedValue } = calculateLiveInvestmentValue(invDoc, now);
            return { ...invDoc.toObject(), currentValue: calculatedValue };
        });
        res.status(200).json({ success: true, investments: calculatedInvestments });
    } catch (e) {
        next(e);
    }
});

app.post('/api/investments', authenticate, [
    body('planId').trim().notEmpty().withMessage('Plan ID is required.').escape(),
    body('amount').isFloat({gt:0}).withMessage('Investment amount must be a positive number.').toFloat()
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const {planId,amount}=req.body;
        const userId=req.user._id;
        const plan = INVESTMENT_PLANS[planId];
        if(!plan) throw new Error('Invalid investment plan selected.');
        if(amount < plan.minAmount || amount > plan.maxAmount) {
            throw new Error(`Amount for ${plan.name} must be between $${plan.minAmount} and $${plan.maxAmount}.`);
        }
        const user = await User.findById(userId).session(session);
        if(!user) throw new Error('User not found.'); 
        if(user.balance < amount) throw new Error('Insufficient account balance.');
        user.balance -= amount;
        const now = new Date(); 
        const durations = getPlanDurationsInMs(plan);
        const newInvestment = new Investment({
            userId, planId: plan.id, planName: plan.name, initialAmount: amount, currentValue: amount,
            profitRate: plan.profitRatePercent, interestPeriodMs: durations.interestPeriodMs,
            startDate: now,
            maturityDate: new Date(now.getTime() + durations.maturityPeriodMs),
            withdrawalUnlockTime: new Date(now.getTime() + durations.withdrawalLockPeriodMs),
        });
        const investmentTransaction = new Transaction({
            userId, type: 'plan_investment', amount: -amount, 
            description: `Invested $${amount.toFixed(2)} in ${plan.name}.`,
            relatedInvestmentId: newInvestment._id
        });
        await user.save({session});
        await newInvestment.save({session});
        await investmentTransaction.save({session});
        await session.commitTransaction();
        res.status(201).json({
            success:true, message:`Successfully invested $${amount.toFixed(2)} in ${plan.name}.`,
            newBalance: user.balance, investment: newInvestment.toObject()
        });
    } catch(e){
        await session.abortTransaction();
        next(e);
    } finally{
        session.endSession();
    }
});

app.post('/api/investments/:investmentId/withdraw', authenticate, [
    param('investmentId').isMongoId().withMessage('Invalid investment ID.'),
    body('withdrawalPin').isNumeric().isLength({min:5,max:5}).withMessage('Withdrawal PIN must be 5 digits.')
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const {investmentId}=req.params;
        const {withdrawalPin}=req.body;
        const userId=req.user._id;
        const currentTime = new Date(); 
        const user = await User.findById(userId).session(session); 
        if(!user) throw new Error('User authentication issue.');
        if (withdrawalPin !== GLOBAL_WITHDRAWAL_PIN) throw new Error('Incorrect withdrawal PIN.');
        const investment = await Investment.findOne({_id: investmentId, userId: userId}).session(session);
        if(!investment) throw new Error('Investment not found or does not belong to you.');
        if(currentTime < new Date(investment.withdrawalUnlockTime)) {
            throw new Error(`Withdrawal is locked until ${new Date(investment.withdrawalUnlockTime).toLocaleString()}.`);
        }
        if(!['active','matured'].includes(investment.status)) {
            throw new Error(`Investment is not in a withdrawable state (current status: ${investment.status}).`);
        }
        const { calculatedValue } = calculateLiveInvestmentValue(investment, currentTime);
        let amountToReturn = calculatedValue; 
        user.balance += amountToReturn;
        const withdrawalTransaction = new Transaction({
            userId, type: 'plan_withdrawal_return', amount: amountToReturn,
            description: `Withdrew $${amountToReturn.toFixed(2)} from ${investment.planName}.`,
            relatedInvestmentId: investment._id
        });
        investment.status = 'withdrawn_matured';
        investment.currentValue = 0; 
        await user.save({session});
        await investment.save({session}); 
        await withdrawalTransaction.save({session});
        await session.commitTransaction();
        res.status(200).json({
            success:true, message:`Successfully withdrew $${amountToReturn.toFixed(2)} from investment.`,
            newBalance:user.balance
        });
    } catch(e){
        await session.abortTransaction();
        next(e);
    } finally{
        session.endSession();
    }
});

app.get('/api/transactions', authenticate, async (req, res, next) => {
    try {
        const transactions = await Transaction.find({ userId: req.user._id })
            .sort({ timestamp: -1 }) 
            .limit(200); 
        res.status(200).json({ success: true, transactions: transactions });
    } catch (e) {
        next(e);
    }
});
// --- END OF USER ROUTES (UNCHANGED) ---

// --- ADMIN ROUTES ---
app.get('/api/admin/pending-users', adminAuthenticate, async (req, res, next) => {
    try {
        const pendingUsers = await User.find({ verified: true, adminApproved: false })
            .select('username email _id adminApproved verified createdAt');
        res.status(200).json({ success: true, users: pendingUsers });
    } catch (e) { next(e); }
});

app.post('/api/admin/approve-user/:userId', adminAuthenticate, [
    param('userId').isMongoId()
], async (req, res, next) => {
    try {
        const userToApprove = await User.findById(req.params.userId);
        if (!userToApprove) return res.status(404).json({ success: false, message: 'User not found.' });
        userToApprove.adminApproved = true;
        await userToApprove.save({ validateBeforeSave: false });
        res.status(200).json({ success: true, message: `User ${userToApprove.username} approved successfully.` });
    } catch (e) { next(e); }
});

app.get('/api/admin/user-by-email', adminAuthenticate, [
    query('email').isEmail().normalizeEmail()
], async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.query.email.toLowerCase() })
            .select('-password -emailVerificationToken -emailVerificationTokenExpiry');
        if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
        res.status(200).json({ success: true, user });
    } catch (e) { next(e); }
});

// ========================== CORRECTED AND FINAL ADMIN UPDATE ROUTE ==========================
app.post('/api/admin/update-user/:userId', adminAuthenticate, [
    param('userId').isMongoId().withMessage('Invalid user ID.'),
    body('balance').optional().isFloat({ min: 0 }).withMessage('Balance must be a non-negative number.').toFloat(),
    body('username').optional().trim().isLength({min:3, max:30}).withMessage('Username must be 3-30 characters long.').escape(),
    body('isAdmin').optional().isBoolean().withMessage('isAdmin must be a boolean (true or false).').toBoolean(),
    body('verified').optional().isBoolean().withMessage('verified must be a boolean.').toBoolean(),
    body('adminApproved').optional().isBoolean().withMessage('adminApproved must be a boolean.').toBoolean(),
    body('assetCredits').optional().isObject().withMessage('Asset credits must be an object.'),
    body('assetCredits.*').optional().isFloat({ min: 0 }).withMessage('Asset credit amount must be a non-negative number.').toFloat()
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array({onlyFirstError:true}) });
    
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const userToUpdate = await User.findById(req.params.userId).session(session);
        if (!userToUpdate) {
            await session.abortTransaction();
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const updatedFields = {};
        const allowedUpdates = ['balance', 'username', 'isAdmin', 'verified', 'adminApproved'];
        let changesMade = false;

        allowedUpdates.forEach(field => {
            if (req.body[field] !== undefined && userToUpdate[field] !== req.body[field]) {
                userToUpdate[field] = req.body[field];
                updatedFields[field] = req.body[field];
                changesMade = true;
            }
        });

        const { assetCredits } = req.body;
        const newTransactions = [];

        if (assetCredits && Object.keys(assetCredits).length > 0) {
            changesMade = true;
            updatedFields.assetCredits = {};

            for (const symbol in assetCredits) {
                const amountToAdd = assetCredits[symbol];
                if (amountToAdd > 0) {
                    const normalizedSymbol = symbol.toUpperCase();
                    updatedFields.assetCredits[normalizedSymbol] = amountToAdd;
                    const assetIndex = userToUpdate.assets.findIndex(a => a.symbol === normalizedSymbol);

                    if (assetIndex > -1) {
                        userToUpdate.assets[assetIndex].amount += amountToAdd;
                    } else {
                        userToUpdate.assets.push({ name: normalizedSymbol, symbol: normalizedSymbol, amount: amountToAdd });
                    }

                    const adminCreditTrx = new Transaction({
                        userId: userToUpdate._id,
                        type: 'admin_credit',
                        amount: amountToAdd,
                        currency: normalizedSymbol,
                        description: `Admin credit of ${amountToAdd} ${normalizedSymbol} by ${req.user.email}.`,
                    });
                    newTransactions.push(adminCreditTrx);
                }
            }
        }
        
        if (!changesMade) {
            await session.abortTransaction();
            return res.status(400).json({ success: false, message: 'No changes provided.' });
        }
        
        await userToUpdate.save({ session });
        if (newTransactions.length > 0) {
            await Transaction.insertMany(newTransactions, { session });
        }

        await session.commitTransaction();
        
        console.log(`ADMIN ACTION: Admin ${req.user.email} updated user ${userToUpdate.email}. Changes: ${JSON.stringify(updatedFields)}`);
        
        const returnUser = userToUpdate.toObject(); 
        delete returnUser.password; 
        delete returnUser.emailVerificationToken;
        delete returnUser.resetToken;
        
        res.status(200).json({ success: true, message: 'User details updated successfully.', user: returnUser });

    } catch (e) { 
        await session.abortTransaction();
        console.error("Error in /api/admin/update-user: ", e); 
        next(e); 
    } finally {
        session.endSession();
    }
});
// ======================================================================================

app.post('/api/admin/resend-verification/:userId', adminAuthenticate, [
    param('userId').isMongoId()
], async (req, res, next) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
        if (user.verified) return res.status(400).json({ success: false, message: 'This user is already email-verified.' });
        user.emailVerificationToken = generateCryptoToken();
        user.emailVerificationTokenExpiry = Date.now() + (24 * 60 * 60 * 1000);
        await user.save({ validateBeforeSave: false });
        const verificationLink = `${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${user.emailVerificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({
            to: user.email, subject: `ACTION REQUIRED: Verify Your Email for ${APP_NAME} (Admin Resend)`,
            html: `<p>Hi ${user.username},</p><p>An administrator has requested to resend your email verification link for your account at ${APP_NAME}.</p><p>Please verify your email by clicking the link below:</p><p><a href="${verificationLink}">Verify Email Address</a></p><p>This link will expire in 24 hours.</p>`});
        res.status(200).json({ success: true, message: 'Verification email has been resent to the user.' });
    } catch (e) { next(e); }
});


// --- Catch-all & Error Handling ---
app.all('/api/*', (req, res) => {
    res.status(404).json({ success: false, message: `The API endpoint ${req.originalUrl} was not found.` });
});

app.use((err, req, res, next) => {
    console.error("GLOBAL ERROR HANDLER:", err.message, err.stack);
    if (res.headersSent) { return next(err); }
    res.status(err.statusCode || 500).json({ 
        success: false, 
        message: err.message || 'An unexpected internal server error occurred.'
    });
});

// --- Start Server ---
const serverInstance = app.listen(PORT, () => {
    console.log(`\n✅ Server running in ${NODE_ENV} mode on port ${PORT}`);
});

process.on('unhandledRejection', (err, promise) => {
  console.error(`Unhandled Rejection: ${err.message}`);
  serverInstance.close(() => process.exit(1));
});