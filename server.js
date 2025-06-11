// --- server.js (Based on YOUR "server copy 2.js" with MINIMAL Targeted Modifications) ---
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
const NODE_ENV = process.env.NODE_ENV || 'development'; // Preserved from your file
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const APP_NAME = process.env.APP_NAME || 'RapidWealthHub'; 
const EMAIL_ADDRESS = process.env.EMAIL;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;
const FRONTEND_URL_FOR_EMAILS = process.env.FRONTEND_PRIMARY_URL || `https://famous-scone-fcd9cb.netlify.app`;
const GLOBAL_WITHDRAWAL_PIN = "54321"; // ✨ ADDED: Global PIN

// --- Critical Env Variable Checks --- (Preserved from your file)
if (!JWT_SECRET) { console.error('FATAL ERROR: JWT_SECRET is not defined.'); process.exit(1); }
if (!MONGO_URI) { console.error('FATAL ERROR: MONGO_URI is not defined.'); process.exit(1); }
if (!EMAIL_ADDRESS || !EMAIL_PASSWORD) { console.warn('⚠️ WARNING: Email service credentials (EMAIL, EMAIL_PASSWORD) are not fully configured.'); }
else { console.log("✅ Email credentials appear to be loaded."); }
if (NODE_ENV === 'production') {
    if(!process.env.FRONTEND_PRIMARY_URL) console.warn('⚠️ WARNING: FRONTEND_PRIMARY_URL is not set. Crucial for CORS & email links.');
    if(!process.env.NETLIFY_DEPLOY_URL) console.warn('⚠️ WARNING: NETLIFY_DEPLOY_URL is not set. Needed for CORS.');
}

// --- Security Middleware --- (Preserved from your file)
app.set('trust proxy', 1); 
app.use(helmet()); 
app.use(express.json({ limit: '10kb' })); 
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());

// --- CORS Configuration --- (Preserved from your file)
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

// --- MongoDB Connection --- (Preserved from your file)
mongoose.connect(MONGO_URI)
.then(() => console.log(`✅ MongoDB connected successfully.`))
.catch(err => { console.error('❌ FATAL MongoDB Connection Error:', err.message, err.stack); process.exit(1); });
mongoose.connection.on('error', err => console.error('❌ MongoDB Runtime Error:', err));
mongoose.connection.on('disconnected', () => console.warn('⚠️ MongoDB disconnected.'));
mongoose.connection.on('reconnected', () => console.log('✅ MongoDB reconnected.'));

// --- Schemas & Models --- (Preserved from your file)
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
userSchema.pre('save', async function(next) { /* Preserved */ 
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
userSchema.methods.comparePassword = async function(candidatePassword) { /* Preserved */ 
    return (candidatePassword && this.password) ? bcrypt.compare(candidatePassword, this.password) : false;
};
userSchema.methods.compareWithdrawalPin = async function(candidatePin) { /* Preserved */ 
    return (candidatePin && this.withdrawalPinHash) ? bcrypt.compare(candidatePin, this.withdrawalPinHash) : false;
};
const User = mongoose.model('User', userSchema);

const investmentSchema = new mongoose.Schema({ /* Preserved - ensure lastInterestAccrualTime exists */ 
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

const TransactionSchema = new mongoose.Schema({ /* Preserved */ 
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

// --- Helper Functions --- (Preserved from your file)
const generateWalletAddress = () => `0x${crypto.randomBytes(20).toString('hex')}`;
const generateCryptoToken = (length = 32) => crypto.randomBytes(length).toString('hex');
const sendEmail = async ({ to, subject, html, text }) => { /* Preserved */ };

// --- ✨ HELPER for On-the-Fly Interest Calculation (NEW) ---
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

// --- Authentication Middleware --- (Preserved from your file)
const authenticate = async (req, res, next) => { /* Preserved */ };
const adminAuthenticate = async (req, res, next) => { /* Preserved */ };

// --- ✨ Rate Limiters (MODIFIED for Testing - High Limits) ---
const TEMP_MAX_GENERAL = 5000; 
const TEMP_MAX_AUTH = 500;    
console.log(`RATE LIMITER CONFIG: General Max = ${TEMP_MAX_GENERAL}, Auth Max = ${TEMP_MAX_AUTH} (High for testing)`);

const generalApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: TEMP_MAX_GENERAL, // MODIFIED
    standardHeaders: 'draft-7', 
    legacyHeaders: false, 
    message: { success: false, message: 'Too many requests. Please try again after 15 minutes.' }
});
app.use('/api', generalApiLimiter); 

const authActionLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, 
    max: TEMP_MAX_AUTH, // MODIFIED
    message: { success: false, message: 'Too many authentication attempts. Please try again after an hour.' },
    skipSuccessfulRequests: true 
});

// --- Investment Plan Definitions --- (Preserved from your file)
const INVESTMENT_PLANS = {
    "silver":   { id: "silver",   name: "Silver Plan", minAmount: 1500,  maxAmount: 10000,  profitRatePercent: 2,  interestPeriodHours: 48, maturityPeriodDays: 2, withdrawalLockDays: 2 },
    "gold":     { id: "gold",     name: "Gold Plan",   minAmount: 2500,  maxAmount: 25000,  profitRatePercent: 5,  interestPeriodHours: 24, maturityPeriodDays: 2, withdrawalLockDays: 2 },
    "premium":  { id: "premium",  name: "Premium Plan",minAmount: 5000,  maxAmount: 50000,  profitRatePercent: 10, interestPeriodHours: 48, maturityPeriodDays: 2, withdrawalLockDays: 2 },
    "platinum": { id: "platinum", name: "Platinum Plan",minAmount: 10000, maxAmount: 100000, profitRatePercent: 20, interestPeriodHours: 12, maturityPeriodDays: 2, withdrawalLockDays: 2 }
};
function getPlanDurationsInMs(plan) { /* Preserved */ 
    if (!plan || typeof plan.interestPeriodHours !== 'number' || typeof plan.maturityPeriodDays !== 'number' || typeof plan.withdrawalLockDays !== 'number') {
        console.error("ERROR [getPlanDurationsInMs]: Invalid plan configuration object received:", plan);
        throw new Error("Plan configuration processing issue. Check plan definitions.");
    }
    return {
        interestPeriodMs: plan.interestPeriodHours * 3600000,      
        maturityPeriodMs: plan.maturityPeriodDays * 86400000,      
        withdrawalLockPeriodMs: plan.withdrawalLockDays * 86400000 
    };
}

// --- API Routes (User-facing) ---

// Register Route (Preserved from your file)
app.post('/api/register', authActionLimiter, [
    body('username').trim().isLength({min:3,max:30}).withMessage('Username must be 3-30 characters.').escape(),
    body('email').isEmail().withMessage('Invalid email address.').normalizeEmail(),
    body('password').isLength({min:6,max:100}).withMessage('Password must be at least 6 characters.')
], async (req, res, next) => { /* Preserved */ });

// Verify Email Route (Preserved from your file)
app.get('/api/verify-email', [
    query('email').isEmail().withMessage('Valid email required.').normalizeEmail(),
    query('token').isHexadecimal().isLength({min:64,max:64}).withMessage('Invalid token format.')
], async (req, res, next) => { /* Preserved */ });

// Resend Verification Email Route (Preserved from your file)
app.post('/api/resend-verification-email', authActionLimiter, [
    body('email').isEmail().withMessage('Valid email required.').normalizeEmail()
], async (req, res, next) => { /* Preserved */ });

// Login Route (Preserved from your file, including its debug logs)
app.post('/api/login', authActionLimiter, [
    body('email').isEmail().withMessage('Valid email required.').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required.')
], async (req, res, next) => { 
    console.log(`LOGIN ROUTE: Attempting login for email: ${req.body.email}, IP: ${req.ip}`);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log("LOGIN ROUTE: Validation errors.", errors.array());
        return res.status(400).json({success:false,message:errors.array({onlyFirstError:true})[0].msg});
    }
    try {
        const {email,password}=req.body;
        console.log("LOGIN ROUTE: Finding user...");
        const user=await User.findOne({email:email.toLowerCase()}).select('+password'); 
        
        if(!user) {
            console.log(`LOGIN ROUTE: User not found for email: ${email.toLowerCase()}`);
            return res.status(401).json({success:false,message:'Invalid email or password.'});
        }
        console.log("LOGIN ROUTE: User found, comparing password...");
        const isMatch = await user.comparePassword(password);
        if(!isMatch) {
            console.log(`LOGIN ROUTE: Password mismatch for email: ${email.toLowerCase()}`);
            return res.status(401).json({success:false,message:'Invalid email or password.'});
        }

        console.log("LOGIN ROUTE: Password matched. Checking verification and approval...");
        if(!user.verified) {
            console.log(`LOGIN ROUTE: Email not verified for: ${email.toLowerCase()}`);
            return res.status(403).json({success:false,message:'Email not verified. Please check your inbox for a verification link.', needsVerification:true, email: user.email});
        }
        if (!user.isAdmin && !user.adminApproved) { 
            console.log(`LOGIN ROUTE: Account not admin approved for: ${email.toLowerCase()}`);
            return res.status(403).json({ success: false, message: 'Your account is verified but pending admin approval. Please wait or contact support.' });
        }
        
        console.log("LOGIN ROUTE: Generating token...");
        const token=jwt.sign({id:user._id, isAdmin: user.isAdmin }, JWT_SECRET, {expiresIn:'24h'}); 
        const userResponse={
            _id:user._id, username:user.username, email:user.email, walletAddress:user.walletAddress,
            balance:user.balance, verified:user.verified, adminApproved: user.adminApproved, isAdmin: user.isAdmin, assets:user.assets
        };
        console.log(`LOGIN ROUTE: Login successful for ${email.toLowerCase()}. Sending response.`);
        res.status(200).json({success:true,token,user:userResponse,message:'Login successful!'});
    } catch(e){ 
        console.error(`LOGIN ROUTE: Error during login for ${req.body.email}: `, e); 
        next(e); 
    }
});

// Profile Route (Preserved from your file)
app.get('/api/profile', authenticate, (req, res) => {
    res.status(200).json({success:true,user:req.user});
});

// Set Withdrawal PIN Route (Preserved from your file)
app.post('/api/user/set-withdrawal-pin', authenticate, [
    body('newPin').isNumeric().isLength({min:5,max:5}).withMessage('PIN must be 5 digits.'),
    body('confirmNewPin').custom((value, { req }) => {
        if (value !== req.body.newPin) throw new Error('New PINs do not match.');
        return true;
    }),
    body('currentPassword').optional().isString().notEmpty().withMessage('Current password is required if PIN is already set.')
], async (req, res, next) => { /* Preserved */ });

// Investment Plans Route (Preserved from your file)
app.get('/api/investment-plans', authenticate, (req, res) => { /* Preserved */ });

// --- ✨ MODIFIED GET /api/investments Route ---
app.get('/api/investments', authenticate, async (req, res, next) => {
    try {
        console.log(`GET /api/investments: User ${req.user.email} fetching investments.`); // DEBUG LOG
        const dbInvestments = await Investment.find({ userId: req.user._id }).sort({ startDate: -1 });
        const now = new Date();
        const calculatedInvestments = dbInvestments.map(invDoc => {
            const { calculatedValue } = calculateLiveInvestmentValue(invDoc, now);
            return { ...invDoc.toObject(), currentValue: calculatedValue };
        });
        console.log(`GET /api/investments: Found and calculated ${calculatedInvestments.length} investments for user ${req.user.email}.`); // DEBUG LOG
        res.status(200).json({ success: true, investments: calculatedInvestments });
    } catch (e) {
        console.error(`ERROR [GET /api/investments] User: ${req.user?._id} - `, e);
        next(e);
    }
});

// --- ✨ MODIFIED POST /api/investments Route ---
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
        if(!plan) return res.status(400).json({success:false, message: 'Invalid investment plan selected.'});
        if(amount < plan.minAmount || amount > plan.maxAmount) {
            return res.status(400).json({success:false, message: `Amount for ${plan.name} must be between $${plan.minAmount} and $${plan.maxAmount}.`});
        }
        const user = await User.findById(userId).session(session);
        if(!user) return res.status(404).json({success:false, message:'User not found.'}); 
        if(user.balance < amount) return res.status(400).json({success:false, message: 'Insufficient account balance.'});
        user.balance -= amount;
        const now = new Date(); 
        const durations = getPlanDurationsInMs(plan);
        const newInvestment = new Investment({
            userId, planId: plan.id, planName: plan.name, initialAmount: amount, currentValue: amount,
            profitRate: plan.profitRatePercent, interestPeriodMs: durations.interestPeriodMs,
            lastInterestAccrualTime: now, // ✨ Ensures correct start for interest calculation
            startDate: now,
            maturityDate: new Date(now.getTime() + durations.maturityPeriodMs),
            withdrawalUnlockTime: new Date(now.getTime() + durations.withdrawalLockPeriodMs),
            status: 'active'
        });
        const investmentTransaction = new Transaction({
            userId, type: 'plan_investment', amount: -amount, 
            description: `Invested $${amount.toFixed(2)} in ${plan.name}.`,
            relatedInvestmentId: newInvestment._id, meta: { ip: req.ip }
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
        console.error(`ERROR [POST /api/investments] User: ${req.user?.email} - `,e);
        next(new Error("Investment failed due to an unexpected error. Please try again."));
    } finally{
        session.endSession();
    }
});

// --- ✨ MODIFIED /api/investments/:investmentId/withdraw Route ---
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
        const user = await User.findById(userId).select('+balance').session(session); 
        if(!user) {
            return res.status(401).json({success:false, message:'User authentication issue.'});
        }
        // ✨ MODIFIED: Use GLOBAL_WITHDRAWAL_PIN
        if (withdrawalPin !== GLOBAL_WITHDRAWAL_PIN) { 
            return res.status(401).json({success:false, message:'Incorrect withdrawal PIN. Please try again or contact admin if you forgot the PIN.'});
        }
        const investment = await Investment.findOne({_id: investmentId, userId: userId}).session(session);
        if(!investment) return res.status(404).json({success:false, message: 'Investment not found or does not belong to you.'});
        if(currentTime < new Date(investment.withdrawalUnlockTime)) {
            return res.status(403).json({success:false, message:`Withdrawal is locked until ${new Date(investment.withdrawalUnlockTime).toLocaleString()}.`});
        }
        
        // ✨ Calculate final value and new last accrual time
        const { calculatedValue, newCalculatedLastAccrualTime } = calculateLiveInvestmentValue(investment, currentTime);
        const finalInterestAccrued = calculatedValue - investment.currentValue; 
        
        // ✨ Update investment document before other checks
        investment.currentValue = calculatedValue; 
        investment.lastInterestAccrualTime = newCalculatedLastAccrualTime;

        if(investment.status === 'active' && currentTime >= new Date(investment.maturityDate)) {
            investment.status = 'matured';
        }
        if(!['active','matured'].includes(investment.status)) {
            return res.status(400).json({success:false, message:`Investment is not in a withdrawable state (current status: ${investment.status}).`});
        }
        
        let amountToReturn = investment.currentValue; // This is now the freshly calculated value
        user.balance += amountToReturn;

        if (finalInterestAccrued > 0.005) { 
            const interestTrx = new Transaction({
                userId, type: 'interest_accrued_to_plan_value',
                amount: parseFloat(finalInterestAccrued.toFixed(2)),
                description: `Final interest for ${investment.planName} (ID: ${investment._id}) on withdrawal.`,
                relatedInvestmentId: investment._id, status: 'completed', meta: { ip: req.ip }
            });
            await interestTrx.save({session});
        }
        const withdrawalTransaction = new Transaction({
            userId, type: 'plan_withdrawal_return', amount: +amountToReturn,
            description: `Withdrew $${amountToReturn.toFixed(2)} from ${investment.planName} (ID: ${investment._id}).`,
            relatedInvestmentId: investment._id, meta: { ip: req.ip }
        });
        investment.status = (investment.status === 'matured' || currentTime >= new Date(investment.maturityDate)) ? 'withdrawn_matured' : 'withdrawn_early';
        investment.currentValue = 0; 
        await user.save({session});
        await investment.save({session}); 
        await withdrawalTransaction.save({session});
        await session.commitTransaction();
        res.status(200).json({
            success:true, message:`Successfully withdrew $${amountToReturn.toFixed(2)} from investment.`,
            newBalance:user.balance, withdrawnInvestment:investment.toObject() 
        });
    } catch(e){
        await session.abortTransaction();
        console.error(`ERROR [POST /api/investments/:id/withdraw] User: ${req.user?.email} - `,e);
        next(new Error(e.message || "Withdrawal failed due to an unexpected error."));
    } finally{
        session.endSession();
    }
});

// --- ✨ NEW: GET User Transactions Route ---
app.get('/api/transactions', authenticate, async (req, res, next) => {
    try {
        const transactions = await Transaction.find({ userId: req.user._id })
            .sort({ timestamp: -1 }) 
            .limit(50); 
        res.status(200).json({ success: true, transactions: transactions });
    } catch (e) {
        console.error(`ERROR [GET /api/transactions] User: ${req.user?._id} - `, e);
        next(e);
    }
});

// --- ADMIN ROUTES --- (Preserved from your file)
app.get('/api/admin/pending-users', adminAuthenticate, async (req, res, next) => { /* Preserved */ });
app.post('/api/admin/approve-user/:userId', adminAuthenticate, [ /* Preserved */ ], async (req, res, next) => { /* Preserved */ });
app.get('/api/admin/user-by-email', adminAuthenticate, [ /* Preserved */ ], async (req, res, next) => { /* Preserved */ });
app.post('/api/admin/update-user/:userId', adminAuthenticate, [ /* Preserved */ ], async (req, res, next) => { /* Preserved */ });
app.post('/api/admin/resend-verification/:userId', adminAuthenticate, [ /* Preserved */ ], async (req, res, next) => { /* Preserved */ });

// --- Catch-all & Error Handling --- (Preserved from your file)
app.all('/api/*', (req, res) => { /* Preserved */ });
app.use((err, req, res, next) => { /* Preserved */ });

// --- Start Server & Graceful Shutdown --- (Preserved from your file)
const serverInstance = app.listen(PORT, () => { /* Preserved */ });
const gracefulShutdown = (signal) => { /* Preserved */ };
['SIGINT', 'SIGTERM', 'SIGQUIT'].forEach(signal => process.on(signal, () => gracefulShutdown(signal)));
process.on('unhandledRejection', (reason, promise) => { /* Preserved */ });
process.on('uncaughtException', (error, origin) => { /* Preserved */ });