// --- server.js (Your Full Backend - ADAPTED with PREFERRED CORS & ADMIN FEATURES - CORS FIX) ---
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

app.set('trust proxy', 1); // For rate limiting behind a reverse proxy
app.use(helmet()); // Basic security headers

// --- CORS Configuration ---
const allowedOrigins = [
    'http://localhost:5500',                // For local Live Server testing
    'http://127.0.0.1:5500',              // Alternative for local Live Server
    'https://famous-scone-fcd9cb.netlify.app', // Your Netlify deploy preview/actual
    'https://rapidcrypto.org',                 // Your primary domain
    'https://www.rapidcrypto.org',             // Your www primary domain
    process.env.NETLIFY_DEPLOY_URL,       // From .env, e.g., Netlify's specific deploy URL
    process.env.FRONTEND_PRIMARY_URL,     // From .env, e.g., https://rapidcrypto.org
    process.env.FRONTEND_WWW_URL          // From .env, e.g., https://www.rapidcrypto.org
].filter(Boolean); // Removes any undefined/null entries if env vars are not set

if (NODE_ENV === 'production' && allowedOrigins.filter(o => !o.includes('localhost')).length < 2) {
    console.warn("⚠️ WARNING: Production CORS origins might be incomplete. Expected at least Netlify deploy URL and primary domain.");
    console.warn("Current allowedOrigins (excluding localhost):", allowedOrigins.filter(o => !o.includes('localhost')));
}

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, or local file://)
        // OR if origin is in the allowedOrigins list
        // OR if origin is the literal string 'null' (often from local file system or sandboxed iframes)
        if (!origin || allowedOrigins.includes(origin) || origin === 'null') {
            callback(null, true);
        } else {
            const msg = `CORS policy: Origin '${origin}' not allowed. Allowed: ${allowedOrigins.join(', ')}`;
            console.error("CORS Error:", msg);
            callback(new Error(msg), false);
        }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"], // Allowed methods
    credentials: true, // Important for cookies, authorization headers
    optionsSuccessStatus: 200 // For compatibility with older browsers/clients
};
app.use(cors(corsOptions)); // Apply CORS middleware
app.options('*', cors(corsOptions)); // IMPORTANT: Enable pre-flight requests for all routes

// --- Core Middleware ---
app.use(express.json({ limit: '10kb' })); // Parse JSON bodies
app.use(express.urlencoded({ extended: true, limit: '10kb' })); // Parse URL-encoded bodies
app.use(mongoSanitize()); // Sanitize MongoDB query selectors

// --- MongoDB Connection ---
mongoose.connect(MONGO_URI)
.then(() => console.log(`✅ MongoDB connected...`))
.catch(err => { console.error('❌ FATAL MongoDB connection error:', err.message); process.exit(1); });
mongoose.connection.on('error', err => console.error('MongoDB runtime error:', err));

// --- Schemas & Models (Includes isAdmin, adminApproved) ---
const userSchema = new mongoose.Schema({
    username: { type: String, trim: true, required: [true, 'Username required.'], index: true },
    walletAddress: { type: String, trim: true },
    email: { type: String, required: [true, 'Email required.'], unique: true, lowercase: true, trim: true, match: [/\S+@\S+\.\S+/, 'Valid email required.'], index: true },
    password: { type: String, required: [true, 'Password required.'], minlength: [6, 'Password min 6.'] },
    verified: { type: Boolean, default: false },
    adminApproved: { type: Boolean, default: false },
    isAdmin: { type: Boolean, default: false },
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
// const generateNumericOtp = (length = 6) => (length < 4 || length > 8) ? "000000" : crypto.randomInt(Math.pow(10, length - 1), Math.pow(10, length) - 1).toString(); // If you use this

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
    if (authHeader && authHeader.startsWith('Bearer ')) { token = authHeader.split(' ')[1]; }
    if (!token) return res.status(401).json({ success: false, message: 'Auth Error: No token provided.' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const currentUser = await User.findById(decoded.id)
            .select('-password -emailVerificationToken -emailVerificationTokenExpiry -loginOtp -loginOtpExpiry -resetToken -resetTokenExpiry -withdrawalPinHash -__v'); // __v is mongoose version key
        if (!currentUser) return res.status(401).json({ success: false, message: 'Auth Error: User not found for token.' });
        req.user = currentUser;
        next();
    } catch (e) {
        let sc = 401, msg = 'Auth Error.', type = e.name;
        if (type === 'TokenExpiredError') msg = 'Session expired. Please log in again.';
        else if (type === 'JsonWebTokenError') msg = 'Invalid token. Please log in again.';
        else { console.error('CRITICAL [authenticate]: Unexpected token error -', e); msg = 'Internal authentication error.'; sc = 500; }
        console.warn(`WARN [authenticate]: ${msg} (Type: ${type})`);
        return res.status(sc).json({ success: false, message: msg, errorType: type });
    }
};

// --- Admin Authentication Middleware ---
const adminAuthenticate = async (req, res, next) => {
    authenticate(req, res, () => {
        if (!req.user) return res.status(401).json({ success: false, message: 'Admin Auth: Authentication failed.' });
        if (!req.user.isAdmin) return res.status(403).json({ success: false, message: 'Forbidden: Admin privileges required.' });
        console.log(`ADMIN ACCESS GRANTED: User ${req.user.email} (ID: ${req.user._id}) accessing ${req.method} ${req.originalUrl}`);
        next();
    });
};

// --- Rate Limiters ---
const generalApiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: 'draft-7', legacyHeaders: false, message: { success: false, message: 'Too many requests from this IP, please try again after 15 minutes.' }});
app.use('/api', generalApiLimiter);
const authActionLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { success: false, message: 'Too many authentication attempts from this IP, please try again after an hour.' }, skipSuccessfulRequests: true });

// --- Investment Plan Definitions ---
const INVESTMENT_PLANS = { /* ... (your plans) ... */ };
function getPlanDurationsInMs(plan) { /* ... (your function) ... */ }
// Ensure INVESTMENT_PLANS and getPlanDurationsInMs are defined as before

// --- API Routes (User-facing) ---
// (Your existing routes: /api/register, /api/verify-email, /api/resend-verification-email, /api/login, /api/profile, etc.)
// Make sure to apply authActionLimiter to register, login, resend-verification, password reset routes

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
            balance:0, assets:[], verified: false, adminApproved: false
        });
        const verificationLink=`${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({
            to:user.email, subject:`Verify Your Email for ${APP_NAME}`,
            html:`<p>Hi ${user.username},</p><p>Welcome to ${APP_NAME}! Please verify your email address by clicking the link below:</p><p><a href="${verificationLink}">Verify Email</a></p><p>This link will expire in 24 hours.</p><p>If you did not create this account, please ignore this email.</p>`
        });
        res.status(201).json({success:true,message:'Registration successful! Please check your email to verify your account.'});
    } catch(e){ console.error("Error in /api/register: ", e); next(e); }
});

app.get('/api/verify-email', [ /* ... validation ... */ ], async (req, res, next) => {
    // ... your verify-email logic ...
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
        await user.save({validateBeforeSave:false});
        res.status(200).json({success:true,message:'Email verified successfully! Your account may require admin approval before you can log in.'});
    } catch(e){ next(e); }
});

app.post('/api/resend-verification-email', authActionLimiter, [ /* ... validation ... */ ], async (req, res, next) => {
    // ... your resend-verification-email logic ...
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg });
    try {
        const {email}=req.body;
        const user=await User.findOne({email: email.toLowerCase()});

        if(!user) {
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
            to:user.email, subject:`Resent: Verify Your Email for ${APP_NAME}`,
            html:`<p>Hi ${user.username},</p><p>Here is a new link to verify your email address:</p><p><a href="${verificationLink}">Verify Email</a></p><p>This link will expire in 24 hours.</p>`});
        res.status(200).json({success:true,message:'A new verification link has been sent to your email address.'});
    } catch(e){ next(e); }
});

app.post('/api/login', authActionLimiter, [ /* ... validation ... */ ], async (req, res, next) => {
    // ... (your login logic, including adminApproved check if desired) ...
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    try {
        const {email,password}=req.body;
        const user=await User.findOne({email:email.toLowerCase()}).select('+password');
        if(!user||!(await user.comparePassword(password))) {
            return res.status(401).json({success:false,message:'Invalid email or password.'});
        }
        if(!user.verified) {
            return res.status(403).json({success:false,message:'Email not verified. Please check your inbox for a verification link.', needsVerification:true, email: user.email});
        }
        if (!user.isAdmin && !user.adminApproved) { // Strict check for non-admins
            return res.status(403).json({ success: false, message: 'Your account is verified but pending admin approval. Please wait or contact support.' });
        }
        const token=jwt.sign({id:user._id},JWT_SECRET,{expiresIn:'1h'});
        const userResponse={
            _id:user._id, username:user.username, email:user.email, walletAddress:user.walletAddress,
            balance:user.balance, verified:user.verified, adminApproved: user.adminApproved, isAdmin: user.isAdmin, assets:user.assets
        };
        res.status(200).json({success:true,token,user:userResponse,message:'Login successful!'});
    } catch(e){ next(e); }
});

app.get('/api/profile', authenticate, (req, res) => { /* ... */ res.status(200).json({success:true,user:req.user});});
app.post('/api/user/set-withdrawal-pin', authenticate, [ /* ... validation ... */ ], async (req, res, next) => { /* ... */ });
app.get('/api/investment-plans', authenticate, (req, res) => { /* ... */ });
app.get('/api/investments', authenticate, async (req, res, next) => { /* ... */ });
app.post('/api/investments', authenticate, [ /* ... validation ... */ ], async (req, res, next) => { /* ... */ });
app.post('/api/investments/:investmentId/withdraw', authenticate, [ /* ... validation ... */ ], async (req, res, next) => { /* ... */ });


// --- ADMIN ROUTES ---
// (Copy the Admin Routes from the previous correct server.js version here)
// GET users pending admin approval
app.get('/api/admin/pending-users', adminAuthenticate, async (req, res, next) => {
    try {
        const pendingUsers = await User.find({ verified: true, adminApproved: false })
            .select('username email _id adminApproved verified createdAt');
        res.status(200).json({ success: true, users: pendingUsers });
    } catch (e) { console.error("Error in /api/admin/pending-users: ", e); next(e); }
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
        await userToApprove.save({ validateBeforeSave: false });
        await sendEmail({
            to: userToApprove.email, subject: `Your ${APP_NAME} Account Approved!`,
            html: `<p>Hi ${userToApprove.username},</p><p>Good news! Your account on ${APP_NAME} has been approved by an administrator. You can now log in and access all features.</p><p>Login here: <a href="${FRONTEND_URL_FOR_EMAILS}/login.html">${FRONTEND_URL_FOR_EMAILS}/login.html</a></p>`});
        res.status(200).json({ success: true, message: `User ${userToApprove.username} approved successfully.` });
    } catch (e) { console.error("Error in /api/admin/approve-user: ", e); next(e); }
});

// GET user by email (for admin search)
app.get('/api/admin/user-by-email', adminAuthenticate, [
    query('email').isEmail().withMessage('Valid email required.').normalizeEmail()
], async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array({onlyFirstError:true})[0].msg });
    try {
        const user = await User.findOne({ email: req.query.email.toLowerCase() })
            .select('-password -emailVerificationToken -emailVerificationTokenExpiry -loginOtp -loginOtpExpiry -resetToken -resetTokenExpiry -withdrawalPinHash');
        if (!user) return res.status(404).json({ success: false, message: 'User not found with that email.' });
        res.status(200).json({ success: true, user });
    } catch (e) { console.error("Error in /api/admin/user-by-email: ", e); next(e); }
});

// POST to update user details by admin
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
        await userToUpdate.save({ validateBeforeSave: true });
        console.log(`ADMIN ACTION: User ${req.user.email} updated user ${userToUpdate.email}. Changes: ${JSON.stringify(updatedFields)}`);
        const returnUser = userToUpdate.toObject(); // Clean for response
        delete returnUser.password; /* delete other sensitive fields */
        res.status(200).json({ success: true, message: 'User updated successfully.', user: returnUser });
    } catch (e) { console.error("Error in /api/admin/update-user: ", e); next(e); }
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
        user.emailVerificationTokenExpiry = Date.now() + (24 * 60 * 60 * 1000);
        await user.save({ validateBeforeSave: false });
        const verificationLink = `${FRONTEND_URL_FOR_EMAILS}/verify-email.html?token=${user.emailVerificationToken}&email=${encodeURIComponent(user.email)}`;
        await sendEmail({
            to: user.email, subject: `ACTION REQUIRED: Verify Your Email for ${APP_NAME} (Admin Resend)`,
            html: `<p>Hi ${user.username},</p><p>An administrator has requested to resend your email verification link for your account at ${APP_NAME}.</p><p>Please verify your email by clicking the link below:</p><p><a href="${verificationLink}">Verify Email Address</a></p><p>This link will expire in 24 hours.</p>`});
        res.status(200).json({ success: true, message: 'Verification email has been resent to the user.' });
    } catch (e) { console.error("Error in /api/admin/resend-verification: ", e); next(e); }
});
// --- END ADMIN ROUTES ---


// --- Catch-all & Error Handling ---
app.all('/api/*', (req, res) => { /* ... */ res.status(404).json({ success: false, message: `The API endpoint ${req.originalUrl} was not found on this server.` }); });
app.use((err, req, res, next) => { /* ... (your global error handler) ... */
    console.error("❌ GLOBAL ERROR HANDLER:", { path: req.path, name: err.name, message: err.message, isOperational: err.isOperational, stack: (NODE_ENV !=='production' && !err.isOperational) ? err.stack : undefined });
    if (res.headersSent) return next(err);
    let statusCode = err.statusCode || 500; let message = err.message || 'An unexpected internal server error occurred.'; let errorType = err.name || 'ServerError';
    if (err.name === 'ValidationError') { statusCode = 400; message = `Validation Failed: ${Object.values(err.errors).map(el => el.message).join('. ')}`; errorType = 'ValidationError';}
    else if (err.name === 'CastError' && err.kind === 'ObjectId') { statusCode = 400; message = 'Invalid ID format provided.'; errorType = 'CastError';}
    else if (err.name === 'MongoServerError' && err.code === 11000) { statusCode = 409; const field = Object.keys(err.keyValue)[0]; message = `An account with this ${field} already exists.`; errorType = 'DuplicateKeyError';}
    else if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') { statusCode = 401; message = err.name === 'TokenExpiredError' ? 'Session has expired. Please log in again.' : 'Invalid session token. Please log in again.'; errorType = err.name;}
    if (NODE_ENV === 'production' && statusCode === 500 && !err.isOperational) { message = 'An unexpected server error occurred. Please try again later.';}
    res.status(statusCode).json({ success: false, message: message, errorType: errorType });
});

// --- Start Server & Graceful Shutdown ---
const serverInstance = app.listen(PORT, () => { /* ... (console logs) ... */
    console.log(`✅ Server running in ${NODE_ENV} mode on port ${PORT}`);
    console.log(`   MongoDB URI (prefix): ${MONGO_URI ? MONGO_URI.substring(0,MONGO_URI.indexOf('@') > 0 ? MONGO_URI.indexOf('@') : 20) + '...' : 'NOT SET'}`);
    console.log(`   Frontend URL for Emails: ${FRONTEND_URL_FOR_EMAILS}`);
    console.log(`   Allowed CORS Origins: ${allowedOrigins.join(', ')}`);
});
const gracefulShutdown = (signal) => { /* ... */ }; // As before
['SIGINT', 'SIGTERM', 'SIGQUIT'].forEach(signal => process.on(signal, () => gracefulShutdown(signal)));
process.on('unhandledRejection', (reason, promise) => { /* ... */ });
process.on('uncaughtException', (error, origin) => { /* ... */ });