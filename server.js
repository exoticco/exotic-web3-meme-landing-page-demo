// server.js - MOONMEME Backend API

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Web3 = require('web3');
const axios = require('axios');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

// ==================== CONFIGURATION ====================
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/moonmeme';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const WEB3_PROVIDER = process.env.WEB3_PROVIDER || 'https://mainnet.infura.io/v3/your-project-id';
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// ==================== MIDDLEWARE ====================
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// ==================== DATABASE CONNECTION ====================
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ Connected to MongoDB');
}).catch(err => {
    console.error('❌ MongoDB connection error:', err);
});

// ==================== MODELS ====================

// User Schema
const userSchema = new mongoose.Schema({
    walletAddress: { type: String, unique: true, required: true },
    email: { type: String, unique: true, sparse: true },
    username: { type: String, unique: true },
    password: { type: String }, // For email login
    nonce: { type: String, default: Math.floor(Math.random() * 1000000).toString() },
    
    // Token Holdings
    balance: { type: Number, default: 0 },
    stakedBalance: { type: Number, default: 0 },
    rewardsEarned: { type: Number, default: 0 },
    
    // Referrals
    referralCode: { type: String, unique: true },
    referredBy: { type: String },
    referrals: [{ type: String }],
    referralEarnings: { type: Number, default: 0 },
    
    // Stats
    totalTransactions: { type: Number, default: 0 },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

userSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

const User = mongoose.model('User', userSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
    walletAddress: { type: String, required: true },
    type: { type: String, enum: ['buy', 'sell', 'transfer', 'stake', 'unstake', 'claim_reward'], required: true },
    amount: { type: Number, required: true },
    hash: { type: String, required: true, unique: true },
    status: { type: String, enum: ['pending', 'confirmed', 'failed'], default: 'pending' },
    blockNumber: { type: Number },
    timestamp: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// Staking Schema
const stakingSchema = new mongoose.Schema({
    walletAddress: { type: String, required: true },
    amount: { type: Number, required: true },
    startDate: { type: Date, default: Date.now },
    endDate: { type: Date },
    apy: { type: Number, default: 20 }, // 20% APY
    rewards: { type: Number, default: 0 },
    status: { type: String, enum: ['active', 'completed', 'withdrawn'], default: 'active' }
});

const Staking = mongoose.model('Staking', stakingSchema);

// Newsletter Schema
const newsletterSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    subscribedAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true }
});

const Newsletter = mongoose.model('Newsletter', newsletterSchema);

// ==================== WEB3 SETUP ====================
const web3 = new Web3(new Web3.providers.HttpProvider(WEB3_PROVIDER));

// Contract ABI (simplified)
const contractABI = [
    // Add your actual contract ABI here
];

let contract;
try {
    contract = new web3.eth.Contract(contractABI, CONTRACT_ADDRESS);
    console.log('✅ Web3 contract initialized');
} catch (error) {
    console.error('❌ Web3 contract initialization error:', error);
}

// ==================== EMAIL SETUP ====================
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: ADMIN_EMAIL,
        pass: ADMIN_PASSWORD
    }
});

// ==================== MIDDLEWARE FUNCTIONS ====================

// Authentication middleware
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(403).json({ error: 'Invalid token' });
    }
};

// Admin middleware
const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ==================== API ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date() });
});

// ==================== AUTH ROUTES ====================

// Generate nonce for wallet signature
app.get('/api/auth/nonce/:wallet', async (req, res) => {
    try {
        const walletAddress = req.params.wallet.toLowerCase();
        let user = await User.findOne({ walletAddress });
        
        if (!user) {
            user = new User({
                walletAddress,
                referralCode: generateReferralCode()
            });
            await user.save();
        }
        
        res.json({ nonce: user.nonce });
    } catch (error) {
        console.error('Nonce error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify wallet signature
app.post('/api/auth/verify', async (req, res) => {
    try {
        const { walletAddress, signature } = req.body;
        
        const user = await User.findOne({ walletAddress: walletAddress.toLowerCase() });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Verify signature (implement your verification logic)
        const message = `Sign this message to login: ${user.nonce}`;
        const recoveredAddress = web3.eth.accounts.recover(message, signature);
        
        if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
            return res.status(401).json({ error: 'Invalid signature' });
        }
        
        // Update nonce
        user.nonce = Math.floor(Math.random() * 1000000).toString();
        user.lastLogin = new Date();
        await user.save();
        
        // Generate JWT
        const token = jwt.sign(
            { wallet: user.walletAddress, role: 'user' },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                wallet: user.walletAddress,
                username: user.username,
                email: user.email,
                balance: user.balance,
                stakedBalance: user.stakedBalance,
                referralCode: user.referralCode
            }
        });
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Email/Password Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, username, referralCode } = req.body;
        
        // Check if user exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ error: 'Email or username already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = new User({
            email,
            username,
            password: hashedPassword,
            referralCode: generateReferralCode(),
            referredBy: referralCode
        });
        
        await user.save();
        
        // Handle referral bonus
        if (referralCode) {
            const referrer = await User.findOne({ referralCode });
            if (referrer) {
                referrer.referrals.push(user._id);
                referrer.referralEarnings += 500; // 500 token bonus
                await referrer.save();
            }
        }
        
        // Generate JWT
        const token = jwt.sign(
            { wallet: user.walletAddress, role: 'user' },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.status(201).json({
            token,
            user: {
                email: user.email,
                username: user.username,
                balance: user.balance,
                referralCode: user.referralCode
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Email/Password Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await User.findOne({ email });
        if (!user || !user.password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        user.lastLogin = new Date();
        await user.save();
        
        const token = jwt.sign(
            { wallet: user.walletAddress, role: 'user' },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                email: user.email,
                username: user.username,
                balance: user.balance,
                referralCode: user.referralCode
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== USER ROUTES ====================

// Get user profile
app.get('/api/user/profile', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findOne({ walletAddress: req.user.wallet });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            wallet: user.walletAddress,
            username: user.username,
            email: user.email,
            balance: user.balance,
            stakedBalance: user.stakedBalance,
            rewardsEarned: user.rewardsEarned,
            referralCode: user.referralCode,
            referrals: user.referrals.length,
            referralEarnings: user.referralEarnings,
            totalTransactions: user.totalTransactions,
            createdAt: user.createdAt
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update user profile
app.put('/api/user/profile', authenticateJWT, async (req, res) => {
    try {
        const { username, email } = req.body;
        
        const user = await User.findOne({ walletAddress: req.user.wallet });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (username) user.username = username;
        if (email) user.email = email;
        
        await user.save();
        
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get user transactions
app.get('/api/user/transactions', authenticateJWT, async (req, res) => {
    try {
        const transactions = await Transaction.find({ walletAddress: req.user.wallet })
            .sort({ timestamp: -1 })
            .limit(50);
        
        res.json(transactions);
    } catch (error) {
        console.error('Transactions error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== TOKEN ROUTES ====================

// Get token info
app.get('/api/token/info', async (req, res) => {
    try {
        // In production, fetch from contract
        const tokenInfo = {
            name: 'MOONMEME',
            symbol: '$MOON',
            totalSupply: 1000000000,
            circulatingSupply: 750000000,
            marketCap: 10000000,
            price: 0.01,
            volume24h: 500000,
            holders: 50000,
            burned: 50000000
        };
        
        res.json(tokenInfo);
    } catch (error) {
        console.error('Token info error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get price chart data
app.get('/api/token/chart', async (req, res) => {
    try {
        const { period = '1d' } = req.query;
        
        // In production, fetch from DEX API
        const chartData = generateChartData(period);
        
        res.json(chartData);
    } catch (error) {
        console.error('Chart error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== STAKING ROUTES ====================

// Get staking info
app.get('/api/staking/info', async (req, res) => {
    try {
        const stakingInfo = {
            totalStaked: 250000000,
            totalStakers: 15000,
            apy: 20,
            minStake: 1000,
            lockPeriod: 30, // days
            rewardsPool: 50000000
        };
        
        res.json(stakingInfo);
    } catch (error) {
        console.error('Staking info error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get user staking positions
app.get('/api/staking/positions', authenticateJWT, async (req, res) => {
    try {
        const positions = await Staking.find({ 
            walletAddress: req.user.wallet,
            status: 'active'
        });
        
        res.json(positions);
    } catch (error) {
        console.error('Staking positions error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create stake
app.post('/api/staking/stake', authenticateJWT, async (req, res) => {
    try {
        const { amount } = req.body;
        
        const user = await User.findOne({ walletAddress: req.user.wallet });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (user.balance < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        // Create staking position
        const stake = new Staking({
            walletAddress: user.walletAddress,
            amount,
            apy: 20
        });
        
        await stake.save();
        
        // Update user balance
        user.balance -= amount;
        user.stakedBalance += amount;
        await user.save();
        
        // Record transaction
        const transaction = new Transaction({
            walletAddress: user.walletAddress,
            type: 'stake',
            amount,
            hash: `stake_${Date.now()}`,
            status: 'confirmed'
        });
        await transaction.save();
        
        res.json({ 
            message: 'Stake created successfully',
            stake
        });
    } catch (error) {
        console.error('Stake error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Claim rewards
app.post('/api/staking/claim', authenticateJWT, async (req, res) => {
    try {
        const { stakeId } = req.body;
        
        const stake = await Staking.findById(stakeId);
        if (!stake || stake.walletAddress !== req.user.wallet) {
            return res.status(404).json({ error: 'Stake not found' });
        }
        
        // Calculate rewards (simplified)
        const daysStaked = Math.floor((Date.now() - stake.startDate) / (1000 * 60 * 60 * 24));
        const rewards = stake.amount * (stake.apy / 100) * (daysStaked / 365);
        
        // Update user balance
        const user = await User.findOne({ walletAddress: req.user.wallet });
        user.balance += rewards;
        user.rewardsEarned += rewards;
        await user.save();
        
        // Update stake
        stake.rewards += rewards;
        await stake.save();
        
        res.json({ 
            message: 'Rewards claimed successfully',
            rewards
        });
    } catch (error) {
        console.error('Claim rewards error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== REFERRAL ROUTES ====================

// Get referral info
app.get('/api/referral/info', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findOne({ walletAddress: req.user.wallet });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const referralLink = `https://moonmeme.io?ref=${user.referralCode}`;
        
        // Get referral details
        const referrals = await User.find({ referredBy: user.referralCode })
            .select('username createdAt balance');
        
        res.json({
            referralCode: user.referralCode,
            referralLink,
            totalReferrals: user.referrals.length,
            referralEarnings: user.referralEarnings,
            referrals
        });
    } catch (error) {
        console.error('Referral info error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== NEWSLETTER ROUTES ====================

// Subscribe to newsletter
app.post('/api/newsletter/subscribe', async (req, res) => {
    try {
        const { email } = req.body;
        
        let subscription = await Newsletter.findOne({ email });
        
        if (subscription) {
            if (!subscription.isActive) {
                subscription.isActive = true;
                await subscription.save();
            }
            return res.json({ message: 'Already subscribed' });
        }
        
        subscription = new Newsletter({ email });
        await subscription.save();
        
        // Send welcome email
        await transporter.sendMail({
            from: ADMIN_EMAIL,
            to: email,
            subject: 'Welcome to MOONMEME Newsletter!',
            html: `
                <h1>Welcome to MOONMEME!</h1>
                <p>Thank you for subscribing to our newsletter. You'll receive updates about:</p>
                <ul>
                    <li>New listings and partnerships</li>
                    <li>Community events and airdrops</li>
                    <li>Product launches and updates</li>
                    <li>Exclusive promotions</li>
                </ul>
                <p>Stay tuned for exciting news!</p>
                <p>Join our community: <a href="https://t.me/moonmeme">Telegram</a></p>
            `
        });
        
        res.json({ message: 'Successfully subscribed' });
    } catch (error) {
        console.error('Newsletter error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Unsubscribe from newsletter
app.post('/api/newsletter/unsubscribe', async (req, res) => {
    try {
        const { email } = req.body;
        
        await Newsletter.findOneAndUpdate(
            { email },
            { isActive: false }
        );
        
        res.json({ message: 'Successfully unsubscribed' });
    } catch (error) {
        console.error('Unsubscribe error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== ADMIN ROUTES ====================

// Get dashboard stats (admin only)
app.get('/api/admin/stats', authenticateJWT, isAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalTransactions = await Transaction.countDocuments();
        const totalStaked = await Staking.aggregate([
            { $match: { status: 'active' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);
        
        const recentTransactions = await Transaction.find()
            .sort({ timestamp: -1 })
            .limit(20);
        
        const topHolders = await User.find()
            .sort({ balance: -1 })
            .limit(10)
            .select('walletAddress balance username');
        
        res.json({
            totalUsers,
            totalTransactions,
            totalStaked: totalStaked[0]?.total || 0,
            recentTransactions,
            topHolders
        });
    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateJWT, isAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        
        const users = await User.find()
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
        
        const total = await User.countDocuments();
        
        res.json({
            users,
            totalPages: Math.ceil(total / limit),
            currentPage: page
        });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== UTILITY FUNCTIONS ====================

function generateReferralCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

function generateChartData(period) {
    const points = 100;
    const data = [];
    let basePrice = 0.01;
    
    for (let i = 0; i < points; i++) {
        const timestamp = Date.now() - (points - i) * 3600000; // hourly
        const change = (Math.random() - 0.5) * 0.002;
        basePrice += change;
        
        data.push({
            timestamp,
            price: Math.max(0.005, basePrice)
        });
    }
    
    return data;
}

// ==================== CRON JOBS ====================

// Calculate staking rewards daily
cron.schedule('0 0 * * *', async () => {
    console.log('Running daily staking rewards calculation...');
    
    const stakes = await Staking.find({ status: 'active' });
    
    for (const stake of stakes) {
        const daysStaked = Math.floor((Date.now() - stake.startDate) / (1000 * 60 * 60 * 24));
        const dailyReward = stake.amount * (stake.apy / 100 / 365);
        
        stake.rewards += dailyReward;
        await stake.save();
    }
    
    console.log(`Updated rewards for ${stakes.length} stakes`);
});

// Update token price every minute
cron.schedule('* * * * *', async () => {
    try {
        // Fetch price from DEX API
        // const price = await fetchPriceFromDEX();
        // Save to database or cache
    } catch (error) {
        console.error('Price update error:', error);
    }
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Web3 Provider: ${WEB3_PROVIDER}`);
    console.log(`📧 Email configured: ${!!ADMIN_EMAIL}`);
});

module.exports = app;