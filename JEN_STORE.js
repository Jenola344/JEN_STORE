// server.js - JEN_STORE Backend API
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult, param } = require('express-validator');
const winston = require('winston');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
require('dotenv').config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3001',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(limiter);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/jenstore', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  walletAddress: { type: String, unique: true, sparse: true },
  firstName: String,
  lastName: String,
  phone: String,
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  preferences: {
    newsletter: { type: Boolean, default: false },
    notifications: { type: Boolean, default: true }
  },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  isActive: { type: Boolean, default: true }
});

// Order Schema
const orderSchema = new mongoose.Schema({
  orderId: { type: String, unique: true, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  walletAddress: String,
  items: [{
    productId: Number,
    productName: String,
    quantity: Number,
    price: String, // Store as string to handle big numbers
    totalAmount: String
  }],
  totalAmount: String,
  discountApplied: String,
  finalAmount: String,
  transactionHash: String,
  blockNumber: Number,
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'],
    default: 'pending'
  },
  paymentMethod: {
    type: String,
    enum: ['crypto', 'card', 'paypal'],
    default: 'crypto'
  },
  shippingAddress: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);

// Ethereum setup
const provider = new ethers.JsonRpcProvider(process.env.ETH_RPC_URL || 'http://localhost:8545');
const contractAddress = process.env.CONTRACT_ADDRESS || '0x1234567890123456789012345678901234567890';

// Smart Contract ABI (simplified for key functions)
const contractABI = [
  "function products(uint256) view returns (string name, string description, uint256 price, uint256 stock, bool active, uint256 totalSold)",
  "function productCount() view returns (uint256)",
  "function purchaseProduct(uint256 productId, uint256 quantity) payable",
  "function batchPurchase(uint256[] productIds, uint256[] quantities) payable",
  "function calculateTotalCost(uint256 productId, uint256 quantity) view returns (uint256)",
  "function getUserPurchases(address user) view returns (tuple(uint256 productId, address buyer, uint256 quantity, uint256 totalAmount, uint256 timestamp, bool refunded)[])",
  "function isLoyalCustomer(address user) view returns (bool)",
  "function getUserDiscount(address user) view returns (uint256)",
  "event ProductPurchased(uint256 indexed productId, address indexed buyer, uint256 quantity, uint256 totalAmount, uint256 timestamp)"
];

const contract = new ethers.Contract(contractAddress, contractABI, provider);

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Error handling middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// User Registration
app.post('/api/auth/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('firstName').optional().trim(),
  body('lastName').optional().trim()
], handleValidationErrors, async (req, res) => {
  try {
    const { email, password, firstName, lastName, walletAddress } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [
        { email },
        ...(walletAddress ? [{ walletAddress }] : [])
      ]
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      walletAddress
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    logger.info(`New user registered: ${email}`);
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        walletAddress: user.walletAddress
      }
    });

  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Login
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], handleValidationErrors, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email, isActive: true });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    logger.info(`User logged in: ${email}`);
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        walletAddress: user.walletAddress
      }
    });

  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const productCount = await contract.productCount();
    const products = [];

    for (let i = 0; i < productCount; i++) {
      const product = await contract.products(i);
      products.push({
        id: i,
        name: product.name,
        description: product.description,
        price: ethers.formatEther(product.price),
        stock: product.stock.toString(),
        active: product.active,
        totalSold: product.totalSold.toString()
      });
    }

    res.json({ products });
  } catch (error) {
    logger.error('Get products error:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Get single product
app.get('/api/products/:id', [
  param('id').isInt({ min: 0 })
], handleValidationErrors, async (req, res) => {
  try {
    const productId = parseInt(req.params.id);
    const product = await contract.products(productId);

    res.json({
      id: productId,
      name: product.name,
      description: product.description,
      price: ethers.formatEther(product.price),
      stock: product.stock.toString(),
      active: product.active,
      totalSold: product.totalSold.toString()
    });

  } catch (error) {
    logger.error('Get product error:', error);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// Calculate purchase cost
app.post('/api/products/calculate-cost', [
  body('productId').isInt({ min: 0 }),
  body('quantity').isInt({ min: 1 }),
  body('walletAddress').optional().isEthereumAddress()
], handleValidationErrors, async (req, res) => {
  try {
    const { productId, quantity, walletAddress } = req.body;

    // Get contract instance with wallet if provided
    let contractInstance = contract;
    if (walletAddress) {
      const wallet = new ethers.Wallet(process.env.PRIVATE_KEY || ethers.Wallet.createRandom().privateKey, provider);
      contractInstance = contract.connect(wallet);
    }

    const totalCost = await contractInstance.calculateTotalCost(productId, quantity);
    const isLoyal = walletAddress ? await contractInstance.isLoyalCustomer(walletAddress) : false;
    const discount = walletAddress ? await contractInstance.getUserDiscount(walletAddress) : 0;

    res.json({
      productId,
      quantity,
      totalCost: ethers.formatEther(totalCost),
      isLoyalCustomer: isLoyal,
      discountPercentage: discount.toString(),
      walletAddress
    });

  } catch (error) {
    logger.error('Calculate cost error:', error);
    res.status(500).json({ error: 'Failed to calculate cost' });
  }
});

// Create order (prepare purchase)
app.post('/api/orders', authenticateToken, [
  body('items').isArray({ min: 1 }),
  body('items.*.productId').isInt({ min: 0 }),
  body('items.*.quantity').isInt({ min: 1 }),
  body('walletAddress').isEthereumAddress(),
  body('shippingAddress').optional().isObject()
], handleValidationErrors, async (req, res) => {
  try {
    const { items, walletAddress, shippingAddress } = req.body;
    const userId = req.user.userId;

    // Generate unique order ID
    const orderId = `JEN-${Date.now()}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;

    // Calculate total cost and prepare order items
    let totalAmount = ethers.parseEther('0');
    const orderItems = [];

    for (const item of items) {
      const product = await contract.products(item.productId);
      const itemCost = await contract.calculateTotalCost(item.productId, item.quantity);
      
      orderItems.push({
        productId: item.productId,
        productName: product.name,
        quantity: item.quantity,
        price: ethers.formatEther(product.price),
        totalAmount: ethers.formatEther(itemCost)
      });
      
      totalAmount = totalAmount + itemCost;
    }

    // Check user discount
    const userDiscount = await contract.getUserDiscount(walletAddress);
    const discountAmount = (totalAmount * BigInt(userDiscount)) / BigInt(100);
    const finalAmount = totalAmount - discountAmount;

    // Create order in database
    const order = new Order({
      orderId,
      userId,
      walletAddress,
      items: orderItems,
      totalAmount: ethers.formatEther(totalAmount),
      discountApplied: ethers.formatEther(discountAmount),
      finalAmount: ethers.formatEther(finalAmount),
      shippingAddress,
      status: 'pending'
    });

    await order.save();

    logger.info(`Order created: ${orderId} for user: ${userId}`);
    res.status(201).json({
      message: 'Order created successfully',
      order: {
        orderId,
        items: orderItems,
        totalAmount: ethers.formatEther(totalAmount),
        discountApplied: ethers.formatEther(discountAmount),
        finalAmount: ethers.formatEther(finalAmount),
        status: 'pending'
      }
    });

  } catch (error) {
    logger.error('Create order error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Process blockchain transaction
app.post('/api/orders/:orderId/process', authenticateToken, [
  param('orderId').notEmpty(),
  body('transactionHash').matches(/^0x[a-fA-F0-9]{64}$/)
], handleValidationErrors, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { transactionHash } = req.body;
    const userId = req.user.userId;

    // Find order
    const order = await Order.findOne({ orderId, userId });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    if (order.status !== 'pending') {
      return res.status(400).json({ error: 'Order already processed' });
    }

    // Verify transaction on blockchain
    const transaction = await provider.getTransaction(transactionHash);
    if (!transaction) {
      return res.status(400).json({ error: 'Transaction not found' });
    }

    // Wait for transaction confirmation
    const receipt = await transaction.wait();
    if (!receipt || receipt.status !== 1) {
      return res.status(400).json({ error: 'Transaction failed' });
    }

    // Update order
    order.transactionHash = transactionHash;
    order.blockNumber = receipt.blockNumber;
    order.status = 'confirmed';
    order.updatedAt = new Date();
    await order.save();

    logger.info(`Order processed: ${orderId}, Transaction: ${transactionHash}`);
    res.json({
      message: 'Order processed successfully',
      order: {
        orderId: order.orderId,
        status: order.status,
        transactionHash: order.transactionHash,
        blockNumber: order.blockNumber
      }
    });

  } catch (error) {
    logger.error('Process order error:', error);
    res.status(500).json({ error: 'Failed to process order' });
  }
});

// Get user orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { page = 1, limit = 10, status } = req.query;

    const query = { userId };
    if (status) query.status = status;

    const orders = await Order.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Order.countDocuments(query);

    res.json({
      orders,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    logger.error('Get orders error:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get single order
app.get('/api/orders/:orderId', authenticateToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    const userId = req.user.userId;

    const order = await Order.findOne({ orderId, userId });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json({ order });

  } catch (error) {
    logger.error('Get order error:', error);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId).select('-password');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get user stats from blockchain if wallet connected
    let blockchainStats = {};
    if (user.walletAddress) {
      try {
        const purchases = await contract.getUserPurchases(user.walletAddress);
        const isLoyal = await contract.isLoyalCustomer(user.walletAddress);
        const discount = await contract.getUserDiscount(user.walletAddress);

        blockchainStats = {
          totalPurchases: purchases.length,
          isLoyalCustomer: isLoyal,
          discountPercentage: discount.toString()
        };
      } catch (error) {
        logger.warn('Failed to fetch blockchain stats:', error);
      }
    }

    res.json({
      user,
      blockchainStats
    });

  } catch (error) {
    logger.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, [
  body('firstName').optional().trim(),
  body('lastName').optional().trim(),
  body('phone').optional().trim(),
  body('address').optional().isObject(),
  body('preferences').optional().isObject()
], handleValidationErrors, async (req, res) => {
  try {
    const userId = req.user.userId;
    const updates = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { ...updates, updatedAt: new Date() },
      { new: true, runValidators: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    logger.info(`User profile updated: ${user.email}`);
    res.json({ message: 'Profile updated successfully', user });

  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Connect wallet to user account
app.post('/api/user/connect-wallet', authenticateToken, [
  body('walletAddress').isEthereumAddress(),
  body('signature').notEmpty()
], handleValidationErrors, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { walletAddress, signature } = req.body;

    // Verify wallet ownership (simplified)
    const message = `Connect wallet to JEN_STORE account: ${userId}`;
    const recoveredAddress = ethers.verifyMessage(message, signature);

    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
      return res.status(400).json({ error: 'Invalid wallet signature' });
    }

    // Check if wallet is already connected to another account
    const existingUser = await User.findOne({ 
      walletAddress: walletAddress.toLowerCase(),
      _id: { $ne: userId }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Wallet already connected to another account' });
    }

    // Update user
    const user = await User.findByIdAndUpdate(
      userId,
      { walletAddress: walletAddress.toLowerCase() },
      { new: true }
    ).select('-password');

    logger.info(`Wallet connected: ${walletAddress} to user: ${user.email}`);
    res.json({ 
      message: 'Wallet connected successfully',
      user
    });

  } catch (error) {
    logger.error('Connect wallet error:', error);
    res.status(500).json({ error: 'Failed to connect wallet' });
  }
});

// Get analytics (admin only)
app.get('/api/admin/analytics', authenticateToken, async (req, res) => {
  try {
    // Simple admin check (in production, use proper role-based access)
    const user = await User.findById(req.user.userId);
    if (user.email !== process.env.ADMIN_EMAIL) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const totalUsers = await User.countDocuments({ isActive: true });
    const totalOrders = await Order.countDocuments();
    const completedOrders = await Order.countDocuments({ status: 'delivered' });
    const pendingOrders = await Order.countDocuments({ status: { $in: ['pending', 'confirmed', 'processing'] } });

    // Calculate total revenue from completed orders
    const revenueData = await Order.aggregate([
      { $match: { status: 'delivered' } },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: { $toDouble: '$finalAmount' } }
        }
      }
    ]);

    const totalRevenue = revenueData[0]?.totalRevenue || 0;

    // Recent orders
    const recentOrders = await Order.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('userId', 'email firstName lastName');

    res.json({
      analytics: {
        totalUsers,
        totalOrders,
        completedOrders,
        pendingOrders,
        totalRevenue: totalRevenue.toFixed(2),
        recentOrders
      }
    });

  } catch (error) {
    logger.error('Get analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Webhook for blockchain events (if using a service like Alchemy)
app.post('/api/webhook/blockchain', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    // Verify webhook signature here in production
    const events = JSON.parse(req.body.toString());

    for (const event of events.logs || []) {
      if (event.address.toLowerCase() === contractAddress.toLowerCase()) {
        // Handle ProductPurchased event
        if (event.topics[0] === ethers.id('ProductPurchased(uint256,address,uint256,uint256,uint256)')) {
          const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
            ['uint256', 'address', 'uint256', 'uint256', 'uint256'],
            event.data
          );

          // Update order status if exists
          const order = await Order.findOne({
            walletAddress: decoded[1].toLowerCase(),
            transactionHash: event.transactionHash
          });

          if (order && order.status === 'confirmed') {
            order.status = 'processing';
            order.updatedAt = new Date();
            await order.save();

            logger.info(`Order status updated via webhook: ${order.orderId}`);
          }
        }
      }
    }

    res.status(200).json({ status: 'processed' });

  } catch (error) {
    logger.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  logger.info(`JEN_STORE Backend API running on port ${PORT}`);
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

module.exports = app;
