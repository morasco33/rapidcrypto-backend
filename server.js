// --- server.js (Full Version with Admin Features & Refinements) ---
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
const APP_NAME = process.env.APP_NAME || 'RapidWealthHub'; // Changed from RapidCrypto for consistency
const EMAIL_ADDRESS = process.env.EMAIL;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;
const FRONTEND_URL_FOR_EMAILS = process.env.FRONTEND_PRIMARY_URL || `https://famous-scone-fcd9cb.netlify.app`; // Your Netlify frontend

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
app.set('trust proxy', 1); // Essential if behind a reverse proxy (like Render, Heroku) for rate limiting and IP stuff
app.use(helmet()); 
app.use(express.json({ limit: '10kb' })); 
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());

// --- CORS Configuration ---
const allowedOrigins = [
    'http://localhost:5500', // Common local dev port
    'http://127.0.0.1:5500',
    'https://famous-scone-fcd9cb.netlify.app', // Your Netlify site
    'https://rapidcrypto.org', // Your custom domain
    'https://www.rapidcrypto.org', // WWW version
    process.env.NETLIFY_DEPLOY_URL,
    process.env.FRONTEND_PRIMARY_URL,
    process.env.FRONTEND_WWW_URL 
].filter(Boolean); // Removes undefined/null if env vars aren't set

console.log("ℹ️ Allowed CORS Origins:", allowedOrigins);

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin) || (NODE_ENV !== 'production' && origin === 'null')) { // 'null' for local file:// testing in dev
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
// Explicitly handle preflight requests for all routes
// This is sometimes necessary for certain clients or complex requests.
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
    walletAddress: { type: String, trim: true }, // Auto-generated
    email: { type: String, required: [true, 'Email is required.'], unique: true, lowercase: true, trim: true, match: [/\S+@\S+\.\S+/, 'A valid email address is required.'], index: true },
    password: { type: String, required: [true, 'Password is required.'], minlength: [6, 'Password must be at least 6 characters.'] },
    verified: { type: Boolean, default: false }, // Email verified
    adminApproved: { type: Boolean, default: false }, // Approved by an admin to use the platform
    isAdmin: { type: Boolean, default: false }, // Is an administrator
    emailVerificationToken: { type: String, select: false },
    emailVerificationTokenExpiry: { type: Date, select: false },
    // loginOtp: { type: String, select: false }, // OTP login not fully implemented, keep if planned
    // loginOtpExpiry: { type: Date, select: false },
    withdrawalPinHash: { type: String, select: false },
    resetToken: { type: String, select: false },
    resetTokenExpiry: { type: Date, select: false },
    assets: [{ name: String, symbol: String, amount: { type: Number, default: 0 } }], // Example if tracking specific crypto assets
    balance: { type: Number, default: 0.00, min: [0, 'Balance cannot be negative.'] } // Main USD balance
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
    planId: { type: String, required: true, index: true }, // e.g., "silver", "gold"
    planName: { type: String, required: true },
    initialAmount: { type: Number, required: true, min: [0.01, 'Investment amount must be greater than 0.01.'] },
    currentValue: { type: Number, required: true, min: 0 },
    profitRate: { type: Number, required: true }, // The percentage rate (e.g., 2 for 2%)
    interestPeriodMs: { type: Number, required: true }, // How often interest is calculated/accrued
    lastInterestAccrualTime: { type: Date, default: Date.now },
    startDate: { type: Date, default: Date.now },
    maturityDate: { type: Date, required: true }, // When the investment fully matures
    withdrawalUnlockTime: { type: Date, required: true }, // When funds can be withdrawn (might be same as maturity or earlier/later)
    status: { type: String, default: 'active', enum: ['active', 'matured', 'withdrawn_early', 'withdrawn_matured', 'cancelled'], index: true }
}, { timestamps: true });
const Investment = mongoose.model('Investment', investmentSchema);

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, required: true, enum: [
        'deposit_main_balance', 'withdrawal_main_balance', // For main account balance
        'plan_investment', 'plan_withdrawal_return', // Related to investment plans
        'interest_accrued_to_plan_value', // Internal tracking for plan value increase
        'fee', 'admin_credit', 'admin_debit' // Other types
    ], index: true },
    amount: { type: Number, required: true }, // Can be positive (credit) or negative (debit)
    currency: { type: String, default: 'USD' },
    description: { type: String, required: true },
    status: { type: String, default: 'completed', enum: ['pending', 'completed', 'failed', 'cancelled'], index: true },
    relatedInvestmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment', sparse: true, index: true }, // Link to investment if applicable
    referenceId: { type: String, sparse: true, index: true }, // For external transaction IDs
    meta: { type: mongoose.Schema.Types.Mixed }, // For additional data (e.g., IP address, device info)
    timestamp: { type: Date, default: Date.now, index: true }
});
const Transaction = mongoose.model('Transaction', TransactionSchema);

// --- Helper Functions ---
const generateWalletAddress = () => `0x${crypto.randomBytes(20).toString('hex')}`;
const generateCryptoToken = (length = 32) => crypto.randomBytes(length).toString('hex');

const sendEmail = async ({ to, subject, html, text }) => { /* ... (Keep your sendEmail function as it was) ... */ 
    if (!EMAIL_ADDRESS || !EMAIL_PASSWORD) { console.error('ERROR [sendEmail]: Email service not configured.'); throw new Error('Email service configuration missing.');}
    const transporter = nodemailer.createTransport({ service: 'Gmail', auth: { user: EMAIL_ADDRESS, pass: EMAIL_PASSWORD }});
    const mailOptions = { from: `"${APP_NAME}" <${EMAIL_ADDRESS}>`, to, subject, html, text: text || html.replace(/<[^>]*>?/gm, '') }; // Basic text fallback
    try { 
        await transporter.sendMail(mailOptions); 
        console.log(`✅ Email sent to ${to}. Subject: "${subject}".`);
    } catch (e) { 
        console.error(`❌ Nodemailer error for ${to}:`, e.message, e.code); 
        if (e.code === 'EAUTH' || e.responseCode === 535) throw new Error('Email authentication failed. Check credentials.'); // More specific
        throw new Error('Error sending email.');
    }
};

// --- Authentication Middleware ---
const authenticate = async (req, res, next) => { /* ... (Keep your authenticate function as it was) ... */ 
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

const adminAuthenticate = async (req, res, next) => { /* ... (Keep your adminAuthenticate function as it was) ... */
    authenticate(req, res, () => { // Call authenticate first
        if (!req.user) {
            // This case should ideally be caught by authenticate itself, but as a safeguard:
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
const generalApiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: NODE_ENV === 'development' ? 1000 : 200, standardHeaders: 'draft-7', legacyHeaders: false, message: { success: false, message: 'Too many requests. Please try again later.' }});
app.use('/api', generalApiLimiter);
const authActionLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: NODE_ENV === 'development' ? 100 : 10, message: { success: false, message: 'Too many authentication attempts. Please try again later.' }, skipSuccessfulRequests: true });


// --- Investment Plan Definitions ---
// !!! IMPORTANT: Define your INVESTMENT_PLANS object here !!!
const INVESTMENT_PLANS = {
    "silver":   { id: "silver",   name: "Silver Plan", minAmount: 1500,  maxAmount: 10000,  profitRatePercent: 2,  interestPeriodHours: 48, maturityPeriodDays: 2, withdrawalLockDays: 2 },
    "gold":     { id: "gold",     name: "Gold Plan",   minAmount: 2500,  maxAmount: 25000,  profitRatePercent: 5,  interestPeriodHours: 24, maturityPeriodDays: 2, withdrawalLockDays: 2 },
    "premium":  { id: "premium",  name: "Premium Plan",minAmount: 5000,  maxAmount: 50000,  profitRatePercent: 10, interestPeriodHours: 48, maturityPeriodDays: 2, withdrawalLockDays: 2 },
    "platinum": { id: "platinum", name: "Platinum Plan",minAmount: 10000, maxAmount: 100000, profitRatePercent: 20, interestPeriodHours: 12, maturityPeriodDays: 2, withdrawalLockDays: 2 }
};

// !!! IMPORTANT: Define your getPlanDurationsInMs function here !!!
function getPlanDurationsInMs(plan) {
    if (!plan || typeof plan.interestPeriodHours !== 'number' || typeof plan.maturityPeriodDays !== 'number' || typeof plan.withdrawalLockDays !== 'number') {
        console.error("ERROR [getPlanDurationsInMs]: Invalid plan configuration object received:", plan);
        throw new Error("Plan configuration processing issue. Check plan definitions.");
    }
    return {
        interestPeriodMs: plan.interestPeriodHours * 3600000,      // hours to ms
        maturityPeriodMs: plan.maturityPeriodDays * 86400000,      // days to ms
        withdrawalLockPeriodMs: plan.withdrawalLockDays * 86400000 // days to ms
    };
}


// --- API Routes (User-facing) ---
app.post('/api/register', authActionLimiter, [
    body('username').trim().isLength({min:3,max:30}).withMessage('Username must be 3-30 characters.').escape(),
    body('email').isEmail().withMessage('Invalid email address.').normalizeEmail(),
    body('password').isLength({min:6,max:100}).withMessage('Password must be at least 6 characters.')
], async (req, res, next) => { /* ... (Keep your /api/register route) ... */ 
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
            balance:0, assets:[], verified: false, adminApproved: false, isAdmin: false // Default isAdmin to false
        });
        const verificationLink=`${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({
            to:user.email, subject:`Verify Your Email for ${APP_NAME}`,
            html:`<p>Hi ${user.username},</p><p>Welcome to ${APP_NAME}! Please verify your email address by clicking the link below:</p><p><a href="${verificationLink}">Verify Email</a></p><p>This link will expire in 24 hours.</p><p>If you did not create this account, please ignore this email.</p>`
        });
        // Notify admin about new registration for approval
        const adminUsers = await User.find({ isAdmin: true }).select('email');
        if (adminUsers.length > 0) {
            const adminEmails = adminUsers.map(admin => admin.email);
            await sendEmail({
                to: adminEmails.join(','), // Send to all admins
                subject: `New User Registration Pending Approval - ${APP_NAME}`,
                html: `<p>A new user has registered and requires admin approval:</p>
                       <p>Username: ${user.username}</p>
                       <p>Email: ${user.email}</p>
                       <p>Please review and approve their account via the admin panel.</p>
                       <p>User ID: ${user._id}</p>`
            });
        }
        res.status(201).json({success:true,message:'Registration successful! Please check your email to verify your account. Admin approval will be required after email verification.'});
    } catch(e){ console.error("Error in /api/register: ", e); next(e); }
});

app.get('/api/verify-email', [
    query('email').isEmail().withMessage('Valid email required.').normalizeEmail(),
    query('token').isHexadecimal().isLength({min:64,max:64}).withMessage('Invalid token format.')
], async (req, res, next) => { /* ... (Keep your /api/verify-email route) ... */
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
], async (req, res, next) => { /* ... (Keep your /api/resend-verification-email route) ... */
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
], async (req, res, next) => { /* ... (Keep your /api/login route with adminApproved check) ... */
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    try {
        const {email,password}=req.body;
        const user=await User.findOne({email:email.toLowerCase()}).select('+password'); // Ensure password is selected
        if(!user||!(await user.comparePassword(password))) {
            return res.status(401).json({success:false,message:'Invalid email or password.'});
        }
        if(!user.verified) {
            return res.status(403).json({success:false,message:'Email not verified. Please check your inbox for a verification link.', needsVerification:true, email: user.email});
        }
        if (!user.isAdmin && !user.adminApproved) { // Non-admins must be approved
            return res.status(403).json({ success: false, message: 'Your account is verified but pending admin approval. Please wait or contact support.' });
        }
        // Admins can log in even if adminApproved is false (they approve themselves or are pre-approved)
        
        const token=jwt.sign({id:user._id, isAdmin: user.isAdmin }, JWT_SECRET, {expiresIn:'24h'}); // Longer expiry, include isAdmin
        const userResponse={
            _id:user._id, username:user.username, email:user.email, walletAddress:user.walletAddress,
            balance:user.balance, verified:user.verified, adminApproved: user.adminApproved, isAdmin: user.isAdmin, assets:user.assets
        };
        res.status(200).json({success:true,token,user:userResponse,message:'Login successful!'});
    } catch(e){ console.error("Error in /api/login: ", e); next(e); }
});

app.get('/api/profile', authenticate, (req, res) => {
    // req.user is populated by 'authenticate' middleware
    res.status(200).json({success:true,user:req.user});
});

app.post('/api/user/set-withdrawal-pin', authenticate, [
    body('newPin').isNumeric().isLength({min:5,max:5}).withMessage('PIN must be 5 digits.'),
    body('confirmNewPin').custom((value, { req }) => {
        if (value !== req.body.newPin) throw new Error('New PINs do not match.');
        return true;
    }),
    body('currentPassword').optional().isString().notEmpty().withMessage('Current password is required if PIN is already set.')
], async (req, res, next) => { /* ... (Keep your /api/user/set-withdrawal-pin route) ... */
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    try {
        const {currentPassword,newPin}=req.body;
        const user=await User.findById(req.user._id).select('+password +withdrawalPinHash');
        if(!user)return res.status(404).json({success:false,message:'User not found.'}); // Should not happen if authenticate works

        // If user already has a PIN, current password is required to change it
        if(user.withdrawalPinHash){
            if(!currentPassword) return res.status(400).json({success:false,message:'Current password is required to change existing PIN.'});
            if(!(await user.comparePassword(currentPassword))) return res.status(401).json({success:false,message:'Incorrect current password.'});
        }
        const salt=await bcrypt.genSalt(10);
        user.withdrawalPinHash=await bcrypt.hash(newPin,salt);
        await user.save();
        res.status(200).json({success:true,message:'Withdrawal PIN updated successfully.'});
    } catch(e){console.error("Error in set-withdrawal-pin:", e); next(e);}
});

app.get('/api/investment-plans', authenticate, (req, res) => {
    // console.log(`DEBUG [server.js]: GET /api/investment-plans | User: ${req.user?.email || 'N/A'}`);
    const frontendPlans = Object.values(INVESTMENT_PLANS).map(p => ({
        id: p.id,
        name: p.name,
        minAmount: p.minAmount,
        maxAmount: p.maxAmount,
        profitRatePercent: p.profitRatePercent,
        interestPeriodHours: p.interestPeriodHours,
        maturityPeriodDays: p.maturityPeriodDays,
        withdrawalLockDays: p.withdrawalLockDays
        // DO NOT send sensitive calculation details like *Ms versions to frontend if not needed
    }));
    if(frontendPlans?.length) {
        res.status(200).json({success:true,plans:frontendPlans});
    } else {
        console.error("ERROR [server.js]: No investment plans defined or failed to map for /api/investment-plans.");
        res.status(500).json({success:false,message:"Investment plans are currently unavailable."});
    }
});

// GET all investments for the logged-in user
app.get('/api/investments', authenticate, async (req, res, next) => {
    try {
        const investments = await Investment.find({ userId: req.user._id }).sort({ startDate: -1 });
        res.status(200).json({ success: true, investments: investments });
    } catch (e) {
        console.error(`ERROR [GET /api/investments] User: ${req.user?._id} - `, e);
        next(e); // Pass to global error handler
    }
});

app.post('/api/investments', authenticate, [
    body('planId').trim().notEmpty().withMessage('Plan ID is required.').escape(),
    body('amount').isFloat({gt:0}).withMessage('Investment amount must be a positive number.').toFloat()
], async (req, res, next) => { /* ... (Keep your /api/investments POST route) ... */
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});

    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const {planId,amount}=req.body;
        const userId=req.user._id;
        const plan = INVESTMENT_PLANS[planId];

        if(!plan) return res.status(400).json({success:false, message: 'Invalid investment plan selected.'});
        if(amount < plan.minAmount || amount > plan.maxAmount) {
            return res.status(400).json({success:false, message: `Amount for ${plan.name} must be between $${plan.minAmount} and $${plan.maxAmount}.`});
        }

        const user = await User.findById(userId).session(session);
        if(!user) return res.status(404).json({success:false, message:'User not found.'}); // Should be caught by authenticate
        if(user.balance < amount) return res.status(400).json({success:false, message: 'Insufficient account balance.'});

        user.balance -= amount;
        const now = new Date();
        const durations = getPlanDurationsInMs(plan);

        const newInvestment = new Investment({
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

        const investmentTransaction = new Transaction({
            userId,
            type: 'plan_investment',
            amount: -amount, // Debiting main balance
            description: `Invested $${amount.toFixed(2)} in ${plan.name}.`,
            relatedInvestmentId: newInvestment._id,
            meta: { ip: req.ip }
        });

        await user.save({session});
        await newInvestment.save({session});
        await investmentTransaction.save({session});
        await session.commitTransaction();

        res.status(201).json({
            success:true,
            message:`Successfully invested $${amount.toFixed(2)} in ${plan.name}.`,
            newBalance: user.balance,
            investment: newInvestment
        });
    } catch(e){
        await session.abortTransaction();
        console.error(`ERROR [POST /api/investments] User: ${req.user?.email} - `,e);
        // Provide a more generic error to the client for unexpected issues
        next(new Error("Investment failed due to an unexpected error. Please try again."));
    } finally{
        session.endSession();
    }
});

app.post('/api/investments/:investmentId/withdraw', authenticate, [
    param('investmentId').isMongoId().withMessage('Invalid investment ID.'),
    body('withdrawalPin').isNumeric().isLength({min:5,max:5}).withMessage('Withdrawal PIN must be 5 digits.')
], async (req, res, next) => { /* ... (Keep your /api/investments/:investmentId/withdraw route) ... */
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});

    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const {investmentId}=req.params;
        const {withdrawalPin}=req.body;
        const userId=req.user._id;

        const user = await User.findById(userId).select('+withdrawalPinHash +balance').session(session);
        if(!user || !user.withdrawalPinHash || !(await user.compareWithdrawalPin(withdrawalPin))) {
            return res.status(401).json({success:false, message:'Invalid withdrawal PIN or user authentication issue.'});
        }

        const investment = await Investment.findOne({_id: investmentId, userId: userId}).session(session);
        if(!investment) return res.status(404).json({success:false, message: 'Investment not found or does not belong to you.'});

        const currentTime = new Date();
        if(currentTime < new Date(investment.withdrawalUnlockTime)) {
            return res.status(403).json({success:false, message:`Withdrawal is locked until ${new Date(investment.withdrawalUnlockTime).toLocaleString()}.`});
        }
        
        // Update status if it's active and past maturity
        if(investment.status === 'active' && currentTime >= new Date(investment.maturityDate)) {
            investment.status = 'matured';
        }

        if(!['active','matured'].includes(investment.status)) {
            return res.status(400).json({success:false, message:`Investment is not in a withdrawable state (current status: ${investment.status}).`});
        }
        
        let amountToReturn = investment.currentValue; // Start with current value

        // Optional: Final interest calculation if needed, though typically done by a cron job or background process.
        // For simplicity here, we assume currentValue is up-to-date or final interest is part of a separate process.
        // If you need to calculate interest up to the withdrawal moment:
        // const timeSinceLastAccrual = currentTime.getTime() - new Date(investment.lastInterestAccrualTime).getTime();
        // const accrualPeriods = Math.floor(timeSinceLastAccrual / investment.interestPeriodMs);
        // if (accrualPeriods > 0 && investment.profitRate > 0 && investment.status === 'active') {
        //     for (let i = 0; i < accrualPeriods; i++) {
        //         amountToReturn += amountToReturn * (investment.profitRate / 100);
        //     }
        //     investment.lastInterestAccrualTime = new Date(new Date(investment.lastInterestAccrualTime).getTime() + (accrualPeriods * investment.interestPeriodMs));
        // }
        // investment.currentValue = amountToReturn; // Update currentValue if calculated here

        user.balance += amountToReturn;

        const withdrawalTransaction = new Transaction({
            userId,
            type: 'plan_withdrawal_return',
            amount: +amountToReturn, // Crediting main balance
            description: `Withdrew $${amountToReturn.toFixed(2)} from ${investment.planName} (ID: ${investment._id}).`,
            relatedInvestmentId: investment._id,
            meta: { ip: req.ip }
        });

        investment.status = (investment.status === 'matured' || currentTime >= new Date(investment.maturityDate)) ? 'withdrawn_matured' : 'withdrawn_early';
        investment.currentValue = 0; // Set to 0 after withdrawal

        await user.save({session});
        await investment.save({session});
        await withdrawalTransaction.save({session});
        await session.commitTransaction();

        res.status(200).json({
            success:true,
            message:`Successfully withdrew $${amountToReturn.toFixed(2)} from investment.`,
            newBalance:user.balance,
            withdrawnInvestment:investment
        });
    } catch(e){
        await session.abortTransaction();
        console.error(`ERROR [POST /api/investments/:id/withdraw] User: ${req.user?.email} - `,e);
        next(new Error(e.message || "Withdrawal failed due to an unexpected error."));
    } finally{
        session.endSession();
    }
});


// --- ADMIN ROUTES ---
// (Your admin routes from previous message)
app.get('/api/admin/pending-users', adminAuthenticate, async (req, res, next) => {
    try {
        const pendingUsers = await User.find({ verified: true, adminApproved: false })
            .select('username email _id adminApproved verified createdAt'); // Select relevant fields
        res.status(200).json({ success: true, users: pendingUsers });
    } catch (e) { console.error("Error in /api/admin/pending-users: ", e); next(e); }
});

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
        await userToApprove.save({ validateBeforeSave: false }); // No other fields changed here
        
        await sendEmail({
            to: userToApprove.email, subject: `Your ${APP_NAME} Account has been Approved!`,
            html: `<p>Hi ${userToApprove.username},</p><p>Good news! Your account on ${APP_NAME} has been approved by an administrator. You can now log in and access all platform features.</p><p>Login here: <a href="${FRONTEND_URL_FOR_EMAILS}/login.html">${FRONTEND_URL_FOR_EMAILS}/login.html</a></p><p>Thank you for joining ${APP_NAME}!</p>`});
        
        res.status(200).json({ success: true, message: `User ${userToApprove.username} approved successfully.` });
    } catch (e) { console.error("Error in /api/admin/approve-user: ", e); next(e); }
});

app.get('/api/admin/user-by-email', adminAuthenticate, [
    query('email').isEmail().withMessage('A valid email address is required.').normalizeEmail()
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array({onlyFirstError:true})[0].msg });
    try {
        const user = await User.findOne({ email: req.query.email.toLowerCase() })
            .select('-password -emailVerificationToken -emailVerificationTokenExpiry -loginOtp -loginOtpExpiry -resetToken -resetTokenExpiry -withdrawalPinHash -__v'); // Exclude sensitive fields
        if (!user) return res.status(404).json({ success: false, message: 'User not found with that email address.' });
        res.status(200).json({ success: true, user });
    } catch (e) { console.error("Error in /api/admin/user-by-email: ", e); next(e); }
});

app.post('/api/admin/update-user/:userId', adminAuthenticate, [
    param('userId').isMongoId().withMessage('Invalid user ID.'),
    body('balance').optional().isFloat({ min: 0 }).withMessage('Balance must be a non-negative number.').toFloat(),
    body('username').optional().trim().isLength({min:3, max:30}).withMessage('Username must be 3-30 characters long.').escape(),
    body('isAdmin').optional().isBoolean().withMessage('isAdmin must be a boolean (true or false).').toBoolean(),
    body('verified').optional().isBoolean().withMessage('verified must be a boolean.').toBoolean(),
    body('adminApproved').optional().isBoolean().withMessage('adminApproved must be a boolean.').toBoolean()
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array({onlyFirstError:true}) });
    try {
        const userToUpdate = await User.findById(req.params.userId).select('+password'); // Select password if admin wants to change it (though not directly supported here)
        if (!userToUpdate) return res.status(404).json({ success: false, message: 'User not found.' });

        const updatedFields = {};
        const allowedUpdates = ['balance', 'username', 'isAdmin', 'verified', 'adminApproved'];
        let changesMade = false;

        allowedUpdates.forEach(field => {
            if (req.body[field] !== undefined && req.body[field] !== userToUpdate[field]) {
                userToUpdate[field] = req.body[field];
                updatedFields[field] = req.body[field];
                changesMade = true;
            }
        });

        if (!changesMade) {
            return res.status(400).json({ success: false, message: 'No changes provided or new values match current values.' });
        }
        
        await userToUpdate.save({ validateBeforeSave: true }); // Let Mongoose validations run
        console.log(`ADMIN ACTION: User ${req.user.email} updated user ${userToUpdate.email}. Changes: ${JSON.stringify(updatedFields)}`);
        
        const returnUser = userToUpdate.toObject(); 
        delete returnUser.password; 
        delete returnUser.emailVerificationToken;
        delete returnUser.resetToken;
        // etc. for other sensitive fields
        
        res.status(200).json({ success: true, message: 'User details updated successfully.', user: returnUser });
    } catch (e) { console.error("Error in /api/admin/update-user: ", e); next(e); }
});

app.post('/api/admin/resend-verification/:userId', adminAuthenticate, [
    param('userId').isMongoId().withMessage('Invalid user ID.')
], async (req, res, next) => { /* ... (Keep your /api/admin/resend-verification route) ... */
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array({onlyFirstError:true})[0].msg });
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
    } catch (e) { console.error("Error in /api/admin/resend-verification: ", e); next(e); }
});


// --- Catch-all & Error Handling ---
// Catch-all for /api routes not found
app.all('/api/*', (req, res) => {
    console.warn(`WARN [Server]: 404 Not Found for API route: ${req.method} ${req.originalUrl} from IP: ${req.ip}`);
    res.status(404).json({ success: false, message: `The API endpoint ${req.originalUrl} was not found on this server.` });
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error("❌ GLOBAL ERROR HANDLER:", {
        path: req.path,
        method: req.method,
        name: err.name,
        message: err.message,
        isOperational: err.isOperational, // Custom property for expected errors
        stack: NODE_ENV !== 'production' ? err.stack : undefined // Show stack only in dev
    });

    if (res.headersSent) {
        return next(err); // Delegate to default Express error handler if headers already sent
    }

    let statusCode = err.statusCode || 500;
    let message = err.isOperational ? err.message : 'An unexpected internal server error occurred.'; // Use operational message if available
    let errorType = err.name || 'ServerError';

    if (err.name === 'ValidationError') { // Mongoose validation error
        statusCode = 400;
        message = `Validation Failed: ${Object.values(err.errors).map(el => el.message).join('. ')}`;
        errorType = 'ValidationError';
    } else if (err.name === 'CastError' && err.kind === 'ObjectId') {
        statusCode = 400;
        message = 'Invalid ID format provided. Please check the ID and try again.';
        errorType = 'CastError';
    } else if (err.name === 'MongoServerError' && err.code === 11000) { // Duplicate key
        statusCode = 409; // Conflict
        const field = Object.keys(err.keyValue)[0];
        message = `An account with this ${field} already exists. Please use a different ${field}.`;
        errorType = 'DuplicateKeyError';
    } else if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        statusCode = 401; // Unauthorized
        message = err.name === 'TokenExpiredError' ? 'Your session has expired. Please log in again.' : 'Invalid session token. Please log in again.';
        errorType = err.name;
    }
    
    // For production, hide generic 500 error messages if not operational
    if (NODE_ENV === 'production' && statusCode === 500 && !err.isOperational) {
        message = 'An unexpected server error occurred. Our team has been notified. Please try again later.';
    }

    res.status(statusCode).json({
        success: false,
        message: message,
        errorType: errorType,
        ...(NODE_ENV !== 'production' && !err.isOperational && { errorDetails: err.message }) // Include original message in dev for non-op 500s
    });
});

// --- Start Server & Graceful Shutdown ---
const serverInstance = app.listen(PORT, () => {
    console.log(`\n✅ Server running in ${NODE_ENV} mode on port ${PORT}`);
    const mongoDisplayUri = MONGO_URI 
        ? (MONGO_URI.includes('@') ? MONGO_URI.substring(0, MONGO_URI.indexOf('@')).split('/').pop() + '@...' : MONGO_URI.substring(0, 20) + '...')
        : 'NOT SET';
    console.log(`   MongoDB URI (host part): ${mongoDisplayUri}`);
    console.log(`   Frontend URL for Emails: ${FRONTEND_URL_FOR_EMAILS}`);
    console.log(`   Allowed CORS Origins: ${allowedOrigins.length > 0 ? allowedOrigins.join(', ') : 'None explicitly set (check logic)'}`);
    if(NODE_ENV === 'development') console.log(`   Open in browser: http://localhost:${PORT}`);
});

const gracefulShutdown = (signal) => {
    console.log(`\n${signal} received. Shutting down gracefully...`);
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
    // Force shutdown if graceful period exceeds
    setTimeout(() => {
        console.error('❌ Graceful shutdown timed out. Forcing exit.');
        process.exit(1);
    }, 10000); // 10 seconds
};
['SIGINT', 'SIGTERM', 'SIGQUIT'].forEach(signal => process.on(signal, () => gracefulShutdown(signal)));

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ UNHANDLED REJECTION at:', promise, 'reason:', reason);
    // Optionally, you might want to crash the process for unhandled rejections
    // For now, just log it. In a robust system, you'd consider if this warrants a shutdown.
    // throw reason; // This would trigger uncaughtException
});
process.on('uncaughtException', (error, origin) => {
    console.error('❌ UNCAUGHT EXCEPTION:', { error: { message: error.message, stack: error.stack }, origin });
    // It's generally recommended to exit after an uncaught exception,
    // as the application state might be inconsistent.
    gracefulShutdown('uncaughtException'); // Attempt graceful shutdown
    setTimeout(() => process.exit(1), 7000); // Give time for shutdown, then force exit
});