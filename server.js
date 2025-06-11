// --- server.js (Full Version with On-the-Fly Interest Calculation) ---
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
const GLOBAL_WITHDRAWAL_PIN = "54321"; 

// --- Critical Env Variable Checks ---
if (!JWT_SECRET) { console.error('FATAL ERROR: JWT_SECRET is not defined.'); process.exit(1); }
if (!MONGO_URI) { console.error('FATAL ERROR: MONGO_URI is not defined.'); process.exit(1); }
if (!EMAIL_ADDRESS || !EMAIL_PASSWORD) { console.warn('⚠️ WARNING: Email service credentials are not fully configured.'); }
else { console.log("✅ Email credentials appear to be loaded."); }
// ... (other env checks from previous versions)

// --- Security Middleware ---
app.set('trust proxy', 1); 
app.use(helmet()); 
app.use(express.json({ limit: '10kb' })); 
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());

// --- CORS Configuration ---
const allowedOrigins = [ /* ... (your allowed origins array from previous server.js) ... */ 
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
const corsOptions = { /* ... (your corsOptions object from previous server.js) ... */ 
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
mongoose.connect(MONGO_URI) /* ... (as before) ... */
.then(() => console.log(`✅ MongoDB connected successfully.`))
.catch(err => { console.error('❌ FATAL MongoDB Connection Error:', err.message, err.stack); process.exit(1); });
mongoose.connection.on('error', err => console.error('❌ MongoDB Runtime Error:', err));
// ... (other mongoose connection event listeners)

// --- Schemas & Models ---
const userSchema = new mongoose.Schema({ /* ... (as before) ... */ 
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
userSchema.pre('save', async function(next) { /* ... (bcrypt password) ... */ 
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
userSchema.methods.comparePassword = async function(candidatePassword) { /* ... */ 
    return (candidatePassword && this.password) ? bcrypt.compare(candidatePassword, this.password) : false;
};
userSchema.methods.compareWithdrawalPin = async function(candidatePin) { /* ... */ 
    return (candidatePin && this.withdrawalPinHash) ? bcrypt.compare(candidatePin, this.withdrawalPinHash) : false;
};
const User = mongoose.model('User', userSchema);

const investmentSchema = new mongoose.Schema({ /* ... (as before, ensure lastInterestAccrualTime is present) ... */ 
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    planId: { type: String, required: true, index: true }, 
    planName: { type: String, required: true },
    initialAmount: { type: Number, required: true, min: [0.01, 'Investment amount must be greater than 0.01.'] },
    currentValue: { type: Number, required: true, min: 0 },
    profitRate: { type: Number, required: true }, 
    interestPeriodMs: { type: Number, required: true }, 
    lastInterestAccrualTime: { type: Date, default: Date.now }, // Crucial for interest calculation
    startDate: { type: Date, default: Date.now },
    maturityDate: { type: Date, required: true }, 
    withdrawalUnlockTime: { type: Date, required: true }, 
    status: { type: String, default: 'active', enum: ['active', 'matured', 'withdrawn_early', 'withdrawn_matured', 'cancelled'], index: true }
}, { timestamps: true });
const Investment = mongoose.model('Investment', investmentSchema);

const TransactionSchema = new mongoose.Schema({ /* ... (as before) ... */ 
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, required: true, enum: [
        'deposit_main_balance', 'withdrawal_main_balance', 
        'plan_investment', 'plan_withdrawal_return', 
        'interest_accrued_to_plan_value', // This type will be used for interest logging
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
const sendEmail = async ({ to, subject, html, text }) => { /* ... (as before) ... */ 
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

// --- ✨ NEW HELPER for On-the-Fly Interest Calculation ---
function calculateLiveInvestmentValue(investmentDocument, calculationTime = new Date()) {
    // Make sure investmentDocument is a Mongoose document or a plain object with the necessary fields
    const inv = (typeof investmentDocument.toObject === 'function') ? investmentDocument.toObject() : { ...investmentDocument };

    let liveCurrentValue = inv.currentValue; // Start with the last known DB value
    let lastAccrualTimestamp = new Date(inv.lastInterestAccrualTime).getTime();
    const interestPeriodMs = inv.interestPeriodMs;
    const profitRateDecimal = inv.profitRate / 100; // e.g., 5% -> 0.05
    const calculationTimestamp = calculationTime.getTime();

    let newLastAccrualTimeForDbUpdate = new Date(inv.lastInterestAccrualTime); // Keep track for DB update if needed

    if (inv.status === 'active' && calculationTimestamp > lastAccrualTimestamp && interestPeriodMs > 0 && profitRateDecimal > 0) {
        const periodsPassed = Math.floor((calculationTimestamp - lastAccrualTimestamp) / interestPeriodMs);

        if (periodsPassed > 0) {
            let tempCurrentValue = liveCurrentValue; // Use a temp var for iterative calculation
            for (let i = 0; i < periodsPassed; i++) {
                tempCurrentValue += tempCurrentValue * profitRateDecimal;
            }
            liveCurrentValue = tempCurrentValue; // Assign final calculated value
            newLastAccrualTimeForDbUpdate = new Date(lastAccrualTimestamp + (periodsPassed * interestPeriodMs));
        }
    }
    return {
        calculatedValue: parseFloat(liveCurrentValue.toFixed(2)), // Ensure 2 decimal places
        newCalculatedLastAccrualTime: newLastAccrualTimeForDbUpdate 
    };
}


// --- Authentication Middleware ---
const authenticate = async (req, res, next) => { /* ... (as before) ... */ };
const adminAuthenticate = async (req, res, next) => { /* ... (as before) ... */ };

// --- Rate Limiters ---
const generalApiLimiter = rateLimit({ /* ... (as before) ... */ });
app.use('/api', generalApiLimiter);
const authActionLimiter = rateLimit({ /* ... (as before) ... */ });

// --- Investment Plan Definitions ---
// !!! FILL THIS WITH YOUR ACTUAL INVESTMENT_PLANS OBJECT !!!
const INVESTMENT_PLANS = {
    "silver":   { id: "silver",   name: "Silver Plan", minAmount: 1500,  maxAmount: 10000,  profitRatePercent: 2,  interestPeriodHours: 48, maturityPeriodDays: 2, withdrawalLockDays: 2 },
    "gold":     { id: "gold",     name: "Gold Plan",   minAmount: 2500,  maxAmount: 25000,  profitRatePercent: 5,  interestPeriodHours: 24, maturityPeriodDays: 2, withdrawalLockDays: 2 },
    "premium":  { id: "premium",  name: "Premium Plan",minAmount: 5000,  maxAmount: 50000,  profitRatePercent: 10, interestPeriodHours: 48, maturityPeriodDays: 2, withdrawalLockDays: 2 },
    "platinum": { id: "platinum", name: "Platinum Plan",minAmount: 10000, maxAmount: 100000, profitRatePercent: 20, interestPeriodHours: 12, maturityPeriodDays: 2, withdrawalLockDays: 2 }
};
// !!! FILL THIS WITH YOUR ACTUAL getPlanDurationsInMs FUNCTION !!!
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
app.post('/api/register', authActionLimiter, [ /* ... */ ], async (req, res, next) => { /* ... (as before) ... */ });
app.get('/api/verify-email', [ /* ... */ ], async (req, res, next) => { /* ... (as before) ... */ });
app.post('/api/resend-verification-email', authActionLimiter, [ /* ... */ ], async (req, res, next) => { /* ... (as before) ... */ });
app.post('/api/login', authActionLimiter, [ /* ... */ ], async (req, res, next) => { /* ... (as before) ... */ });
app.get('/api/profile', authenticate, (req, res) => { /* ... (as before) ... */ });
app.post('/api/user/set-withdrawal-pin', authenticate, [ /* ... */ ], async (req, res, next) => { /* ... (as before) ... */ });
app.get('/api/investment-plans', authenticate, (req, res) => { /* ... (as before) ... */ });

// --- ✨ MODIFIED GET /api/investments Route ---
app.get('/api/investments', authenticate, async (req, res, next) => {
    try {
        const dbInvestments = await Investment.find({ userId: req.user._id }).sort({ startDate: -1 });
        const now = new Date();

        const calculatedInvestments = dbInvestments.map(invDoc => {
            const { calculatedValue } = calculateLiveInvestmentValue(invDoc, now);
            return {
                ...invDoc.toObject(), // Convert Mongoose doc to plain object
                currentValue: calculatedValue, // Override currentValue with the calculated one for display
            };
        });

        res.status(200).json({ success: true, investments: calculatedInvestments });
    } catch (e) {
        console.error(`ERROR [GET /api/investments] User: ${req.user?._id} - `, e);
        next(e);
    }
});

app.post('/api/investments', authenticate, [ /* ... validations ... */ ], async (req, res, next) => { /* ... (as before, ensure lastInterestAccrualTime is set to now on creation) ... */ 
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
        const now = new Date(); // CRITICAL: Use this 'now' for all date initializations
        const durations = getPlanDurationsInMs(plan);

        const newInvestment = new Investment({
            userId, planId: plan.id, planName: plan.name, initialAmount: amount, currentValue: amount,
            profitRate: plan.profitRatePercent, interestPeriodMs: durations.interestPeriodMs,
            lastInterestAccrualTime: now, // Set to current time on creation
            startDate: now,
            maturityDate: new Date(now.getTime() + durations.maturityPeriodMs),
            withdrawalUnlockTime: new Date(now.getTime() + durations.withdrawalLockPeriodMs),
            status: 'active'
        });

        const investmentTransaction = new Transaction({ /* ... */ });

        await user.save({session});
        await newInvestment.save({session});
        await investmentTransaction.save({session});
        await session.commitTransaction();

        res.status(201).json({ /* ... */ });
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

        if (withdrawalPin !== GLOBAL_WITHDRAWAL_PIN) { 
            return res.status(401).json({success:false, message:'Incorrect withdrawal PIN. Please try again or contact admin if you forgot the PIN.'});
        }

        const investment = await Investment.findOne({_id: investmentId, userId: userId}).session(session);
        if(!investment) return res.status(404).json({success:false, message: 'Investment not found or does not belong to you.'});

        if(currentTime < new Date(investment.withdrawalUnlockTime)) {
            return res.status(403).json({success:false, message:`Withdrawal is locked until ${new Date(investment.withdrawalUnlockTime).toLocaleString()}.`});
        }
        
        // ✨ Calculate final value and new last accrual time before any status changes
        const { calculatedValue, newCalculatedLastAccrualTime } = calculateLiveInvestmentValue(investment, currentTime);
        
        const finalInterestAccrued = calculatedValue - investment.currentValue; // Difference from DB stored value
        
        // Update the investment document with calculated values before further checks
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

        // Log transactions
        if (finalInterestAccrued > 0.005) { // Log only if meaningful interest was accrued just now
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
        investment.currentValue = 0; // Reset after withdrawal

        await user.save({session});
        await investment.save({session}); // Save updated investment (currentValue, lastAccrualTime, status)
        await withdrawalTransaction.save({session});
        await session.commitTransaction();

        res.status(200).json({
            success:true,
            message:`Successfully withdrew $${amountToReturn.toFixed(2)} from investment.`,
            newBalance:user.balance,
            withdrawnInvestment:investment.toObject() 
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
app.get('/api/admin/pending-users', adminAuthenticate, async (req, res, next) => { /* ... (as before) ... */ });
app.post('/api/admin/approve-user/:userId', adminAuthenticate, [ /* ... */ ], async (req, res, next) => { /* ... (as before) ... */ });
app.get('/api/admin/user-by-email', adminAuthenticate, [ /* ... */ ], async (req, res, next) => { /* ... (as before) ... */ });
app.post('/api/admin/update-user/:userId', adminAuthenticate, [ /* ... */ ], async (req, res, next) => { /* ... (as before) ... */ });
app.post('/api/admin/resend-verification/:userId', adminAuthenticate, [ /* ... */ ], async (req, res, next) => { /* ... (as before) ... */ });

// --- Catch-all & Error Handling ---
app.all('/api/*', (req, res) => { /* ... (as before) ... */ });
app.use((err, req, res, next) => { /* ... (as before - global error handler) ... */ });

// --- Start Server & Graceful Shutdown ---
const serverInstance = app.listen(PORT, () => { /* ... (as before - console logs) ... */ });
const gracefulShutdown = (signal) => { /* ... (as before) ... */ };
['SIGINT', 'SIGTERM', 'SIGQUIT'].forEach(signal => process.on(signal, () => gracefulShutdown(signal)));
process.on('unhandledRejection', (reason, promise) => { /* ... (as before) ... */ });
process.on('uncaughtException', (error, origin) => { /* ... (as before) ... */ });