const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const axios = require('axios');
const nodemailer = require('nodemailer');

const { Op } = require('sequelize');
const sequelize = require('./src/config/database');
const User = require('./src/models/User');
const ConversionHistory = require('./src/models/ConversionHistory');
const Rating = require('./src/models/Rating');
const BugReport = require('./src/models/BugReport');
const Otp = require('./src/models/Otp');
const Notification = require('./src/models/Notification');
const ReportReply = require('./src/models/ReportReply');
const http = require('http');
const socketIo = require('socket.io');
const { validate } = require('./src/middleware/validation');
const TestResult = require('./src/models/TestResult');

// Global variables
const notifications = [];
const activeUsers = new Map();
const adminSockets = new Set();
const userActivities = new Map();

// In-memory storage for report replies and status (since database doesn't have these columns)
const reportReplies = new Map();



const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";



// Middleware
app.use(cors({ 
  origin: process.env.FRONTEND_URL || "http://localhost:3000", 
  credentials: true 
}));
app.use(express.json());

// In-memory storage (replace with database in production)
// let conversionHistory = []; // Removed as per edit hint
// let ratings = []; // Removed as per edit hint
// let bugReports = []; // Removed as per edit hint

// Track login events in memory
let loginEvents = [];

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Helper to send OTP email with styled HTML
function sendOtpEmail(email, otp) {
  const mailOptions = {
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    to: email,
    subject: 'Smart Converter OTP Code',
    text: `Your OTP code is: ${otp}`,
    html: `<div style="font-family:sans-serif;padding:24px;background:#f9fafb;border-radius:8px;max-width:400px;margin:auto;">
      <h2 style="color:#2563eb;margin-bottom:16px;">Smart Converter OTP Code</h2>
      <p style="font-size:16px;margin-bottom:8px;">Your one-time password (OTP) is:</p>
      <div style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#2563eb;margin-bottom:16px;">${otp}</div>
      <p style="font-size:14px;color:#6b7280;">This code will expire in 10 minutes.</p>
    </div>`
  };
  return transporter.sendMail(mailOptions);
}

// Helper to validate password
function isValidPassword(password) {
  // At least 6 chars, 1 uppercase, 1 number
  return /^(?=.*[A-Z])(?=.*\d).{6,}$/.test(password);
}

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  console.log('🔐 === AUTHENTICATE TOKEN MIDDLEWARE ===');
  console.log('🔐 Request headers:', req.headers);
  console.log('🔐 Authorization header:', req.headers['authorization']);
  
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  console.log('🔐 Extracted token:', token ? token.substring(0, 20) + '...' : 'null');
  console.log('🔐 Token exists:', !!token);

  if (!token) {
    console.log('❌ No token found in Authorization header');
    return res.status(401).json({ error: "Access token required" });
  }

  console.log('🔐 Verifying token with JWT_SECRET...');
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('❌ JWT verification failed:', err.message);
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    console.log('✅ JWT verification successful, user:', user);
    req.user = user;
    next();
  });
};

// Admin Authentication Middleware
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: "Admin token required" });
  }

  // For admin, we'll use a simple check - if token starts with 'admin-token-'
  if (token.startsWith('admin-token-')) {
    req.user = { isAdmin: true, userId: 'admin' };
    next();
  } else {
    // Try to verify as regular JWT token for admin access
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      // Check if this is an admin user (you can add admin check logic here)
      // For now, we'll allow any valid JWT token for admin access
      req.user = { isAdmin: true, userId: decoded.userId };
      next();
    } catch (error) {
      return res.status(403).json({ error: "Admin access required" });
    }
  }
};

// Health Check
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "OK", 
    message: "Smart Converter API is running", 
    timestamp: new Date().toISOString() 
  });
});

// Test currency conversion endpoint
app.get("/api/test-currency", async (req, res) => {
  try {
    const { from, to, amount } = req.query;
    console.log(`Testing currency conversion: ${amount} ${from} to ${to}`);
    
    const response = await axios.get(`https://api.exchangerate-api.com/v4/latest/${from}`, {
      timeout: 10000
    });
    
    const rates = response.data.rates;
    const result = amount * rates[to];
    
    res.json({
      success: true,
      from,
      to,
      amount: parseFloat(amount),
      result: parseFloat(result.toFixed(6)),
      rate: rates[to],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Test currency error:', error);
    res.status(500).json({ error: "Currency test failed", message: error.message });
  }
});

// Profile update endpoint
app.put("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    console.log('Profile update request received');
    console.log('Request body:', req.body);
    
    const { name, phone, address } = req.body;
    const userId = req.user.userId;
    
    console.log('User ID:', userId);
    console.log('Name:', name);
    console.log('Phone:', phone);
    console.log('Address:', address);
    
    // Validate required fields
    if (!name) {
      return res.status(400).json({ error: "Name is required" });
    }
    
    // Update user profile
    console.log('Finding user with ID:', userId);
    const user = await User.findByPk(userId);
    if (!user) {
      console.error('User not found with ID:', userId);
      return res.status(404).json({ error: "User not found" });
    }
    
    console.log('Current user data:', {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      address: user.address
    });
    
    // Only update allowed fields - email cannot be changed
    user.name = name;
    user.phone = phone || null;
    user.address = address || null;
    
    console.log('Updated user data:', {
      name: user.name,
      phone: user.phone,
      address: user.address
    });
    
    try {
      await user.save();
      console.log('User saved successfully');
    } catch (saveError) {
      console.error('Error saving user:', saveError);
      return res.status(500).json({ error: "Failed to save user profile", message: saveError.message });
    }
    
    // Return updated user data (without password)
    const userResponse = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      address: user.address,
      isAdmin: user.isAdmin,
      createdAt: user.createdAt
    };
    
    res.json({
      success: true,
      message: "Profile updated successfully",
      user: userResponse
    });
    
  } catch (error) {
    console.error('Profile update error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: "Failed to update profile", message: error.message });
  }
});

// Notifications endpoints
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Get user's notifications from database
    const userNotifications = await Notification.findAll({
      where: { userId },
      order: [['createdAt', 'DESC']],
      limit: 50
    });
    
    res.json({
      success: true,
      notifications: userNotifications
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

app.put("/api/notifications/:id/read", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    
    // Find and mark notification as read in database
    const notification = await Notification.findOne({
      where: { id, userId }
    });
    
    if (notification) {
      notification.isRead = true;
      await notification.save();
    }
    
    res.json({
      success: true,
      message: "Notification marked as read"
    });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ error: "Failed to mark notification as read" });
  }
});

app.put("/api/notifications/read-all", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Mark all user's notifications as read
    await Notification.update(
      { isRead: true },
      { where: { userId, isRead: false } }
    );
    
    res.json({
      success: true,
      message: "All notifications marked as read"
    });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ error: "Failed to mark notifications as read" });
  }
});

// Create notification helper function
const createNotification = async (userId, title, message, type = 'info') => {
  try {
    const notification = await Notification.create({
      id: Date.now().toString(),
      userId,
      title,
      message,
      type,
      isRead: false,
      createdAt: new Date().toISOString()
    });
  
    // Notify user via WebSocket if they're online
    const userSocket = activeUsers.get(userId);
    if (userSocket) {
      io.to(userSocket.socketId).emit('notification', {
        id: notification.id,
        title: notification.title,
        message: notification.message,
        type: notification.type,
        createdAt: notification.createdAt
      });
    }
    
    return notification;
  } catch (error) {
    console.error('Error creating notification:', error);
  }
};

// Authentication Routes
// Registration with OTP
app.post("/api/auth/register", validate('register'), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "Password must be at least 6 characters, include 1 uppercase letter and 1 number." });
    }
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: "User with this email already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      id: Date.now().toString(),
      name,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      isConfirmed: true,
      passwordResetPending: false
    });
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    // Transfer any pending notifications for this email (from public submissions)
    const pendingNotifications = notifications.filter(n => 
      n.userId.startsWith('contact-') || n.userId.startsWith('public-')
    );
    
    // Transfer notifications to the new user
    pendingNotifications.forEach(notification => {
      // Check if this notification is related to this user's email
      // For now, we'll transfer all pending notifications (in a real app, you'd match by email)
      notification.userId = user.id;
    });
    
    const { password: _, ...userWithoutPassword } = user.toJSON();
    res.json({
      success: true,
      message: "Registration successful. You can now log in.",
      user: userWithoutPassword,
      token
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/api/auth/login", validate('login'), async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt:', { email, password: password ? '***' : 'missing' });
    
    if (!email || !password) {
      return res.status(400).json({ error: "Email/UID and password are required" });
    }
    
    // Try to find user by email first, then by UID
    let user = await User.findOne({ where: { email } });
    console.log('User found by email:', user ? 'Yes' : 'No');
    
    if (!user) {
      // If not found by email, try by UID
      user = await User.findByPk(email);
      console.log('User found by UID:', user ? 'Yes' : 'No');
    }
    
    if (!user) {
      console.log('No user found for:', email);
      return res.status(400).json({ error: "Invalid email/UID or password" });
    }
    
    console.log('User found:', { id: user.id, name: user.name, email: user.email, isConfirmed: user.isConfirmed });
    
    if (!user.isConfirmed) {
      return res.status(403).json({ error: "Please confirm your email before logging in." });
    }
    
    console.log('Comparing passwords...');
    const isValid = await bcrypt.compare(password, user.password);
    console.log('Password comparison result:', isValid);
    
    if (!isValid) {
      return res.status(400).json({ error: "Invalid email/UID or password" });
    }
    
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    const { password: _, ...userWithoutPassword } = user.toJSON();
    
    // Transfer any pending notifications for this user (from public submissions)
    try {
      const pendingNotifications = await Notification.findAll({
        where: {
          userId: {
            [Op.or]: [
              { [Op.like]: 'contact-%' },
              { [Op.like]: 'public-%' }
            ]
          }
        }
      });
    
    // Transfer notifications to the logged-in user
      for (const notification of pendingNotifications) {
        await notification.update({ userId: user.id });
      }
      
      if (pendingNotifications.length > 0) {
        console.log(`Transferred ${pendingNotifications.length} pending notifications to user ${user.email}`);
      }
    } catch (error) {
      console.error('Error transferring notifications:', error);
    }
    
    console.log('Login successful for user:', user.name);
    res.json({
      success: true,
      message: "Login successful",
      user: userWithoutPassword,
      token
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// Create test user for debugging
app.post("/api/auth/create-test-user", async (req, res) => {
  try {
    const testUser = await User.findOne({ where: { email: 'test@test.com' } });
    if (testUser) {
      return res.json({ 
        success: true, 
        message: "Test user already exists",
        user: { email: testUser.email, id: testUser.id }
      });
    }

    const hashedPassword = await bcrypt.hash('Test123', 10);
    const user = await User.create({
      id: Date.now().toString(),
      name: 'Test User',
      email: 'test@test.com',
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      isConfirmed: true,
      passwordResetPending: false
    });

    res.json({
      success: true,
      message: "Test user created successfully",
      user: { email: user.email, id: user.id, password: 'Test123' }
    });
  } catch (error) {
    console.error("Test user creation error:", error);
    res.status(500).json({ error: "Failed to create test user" });
  }
});

// Update existing admin user to have isAdmin flag
app.post("/api/auth/update-admin-user", async (req, res) => {
  try {
    const adminUser = await User.findOne({ where: { email: 'admin@smartconverter.com' } });
    if (!adminUser) {
      return res.status(404).json({ error: "Admin user not found" });
    }
    
    adminUser.isAdmin = true;
    await adminUser.save();
    
    res.json({
      success: true,
      message: "Admin user updated successfully",
      user: { 
        email: adminUser.email, 
        id: adminUser.id, 
        name: adminUser.name,
        isAdmin: adminUser.isAdmin
      }
    });
  } catch (error) {
    console.error("Admin user update error:", error);
    res.status(500).json({ error: "Failed to update admin user" });
  }
});

// Create admin user for testing
app.post("/api/auth/create-admin-user", async (req, res) => {
  try {
    const adminUser = await User.findOne({ where: { email: 'admin@smartconverter.com' } });
    if (adminUser) {
      return res.json({ 
        success: true, 
        message: "Admin user already exists",
        user: { email: adminUser.email, id: adminUser.id, name: adminUser.name }
      });
    }

    const hashedPassword = await bcrypt.hash('Admin123', 10);
    const user = await User.create({
      id: 'admin-' + Date.now().toString(),
      name: 'Administrator',
      email: 'admin@smartconverter.com',
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      isConfirmed: true,
      isAdmin: true,
      passwordResetPending: false
    });

    res.json({
      success: true,
      message: "Admin user created successfully",
      user: { 
        email: user.email, 
        id: user.id, 
        name: user.name,
        password: 'Admin123' // Only for testing, remove in production
      }
    });
  } catch (error) {
    console.error("Admin user creation error:", error);
    res.status(500).json({ error: "Failed to create admin user" });
  }
});

// Forgot password: send OTP
app.post('/api/auth/forgot-password', validate('forgotPassword'), async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.passwordResetPending = true;
  await user.save();
  res.json({ success: true, message: 'Password reset initiated. You can now change your password.' });
});

// Forgot password: reset password
app.post('/api/auth/reset-password', validate('resetPassword'), async (req, res) => {
  const { email, newPassword } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.passwordResetPending) return res.status(400).json({ error: 'Password reset not initiated.' });
  if (!isValidPassword(newPassword)) {
    return res.status(400).json({ error: 'Password must be at least 6 characters, include 1 uppercase letter and 1 number.' });
  }
  user.password = await bcrypt.hash(newPassword, 10);
  user.passwordResetPending = false;
  await user.save();
  res.json({ success: true, message: 'Password reset successful. You can now log in.' });
});

// Send OTP endpoint
app.post('/api/auth/send-otp', validate('sendOtp'), async (req, res) => {
  try {
    const { email, purpose } = req.body;
    if (!email || !purpose) {
      return res.status(400).json({ error: 'Email and purpose are required.' });
    }
    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry
    await Otp.create({ email, otp, expires, purpose });
    await sendOtpEmail(email, otp);
    res.json({ success: true, message: 'OTP sent to email.' });
  } catch (err) {
    console.error('OTP send error:', err && (err.stack || err.message || err));
    if (err && err.response) {
      console.error('Nodemailer response:', err.response);
    }
    res.status(500).json({ error: 'Failed to send OTP email. Please check your email settings and try again.' });
  }
});

// Verify OTP endpoint
app.post('/api/auth/verify-otp', validate('verifyOtp'), async (req, res) => {
  try {
    const { email, otp, purpose } = req.body;
    const record = await Otp.findOne({ where: { email, otp, purpose } });
    if (!record) {
      return res.status(400).json({ error: 'Invalid OTP.' });
    }
    if (new Date() > record.expires) {
      await record.destroy();
      return res.status(400).json({ error: 'OTP expired.' });
    }
    await record.destroy();
    res.json({ success: true, message: 'OTP verified.' });
  } catch (err) {
    console.error('OTP verify error:', err && (err.stack || err.message || err));
    res.status(500).json({ error: 'Failed to verify OTP.' });
  }
});



// Get user profile
app.get("/api/auth/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const { password: _, ...userWithoutPassword } = user.toJSON();
    res.json({
      success: true,
      user: userWithoutPassword
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to get profile" });
  }
});

// Get stats for dashboard
app.get("/api/stats", authenticateToken, async (req, res) => {
  try {
    const totalUsers = await User.count();
    const totalConversions = await ConversionHistory.count();
    const totalRatings = await Rating.count();
    const totalReports = await BugReport.count();
    
    // Calculate average rating
    const ratings = await Rating.findAll();
    const averageRating = ratings.length > 0 
      ? ratings.reduce((sum, rating) => sum + rating.rating, 0) / ratings.length 
      : 0;

    res.json({
      success: true,
      stats: {
        totalUsers,
        totalConversions,
        totalRatings,
        totalReports,
        averageRating
      }
    });
  } catch (error) {
    console.error("Stats error:", error);
    res.status(500).json({ error: "Failed to get stats" });
  }
});

// Update user profile
app.put("/api/auth/profile", authenticateToken, validate('updateProfile'), async (req, res) => {
  try {
    const user = await User.findByPk(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const { name, email, password, phone, address, avatar } = req.body;
    if (name) user.name = name;
    if (email && email !== user.email) {
      // Check if email is taken
      const emailTaken = await User.findOne({ where: { email } });
      if (emailTaken) {
        return res.status(400).json({ error: "Email already in use" });
      }
      user.email = email;
    }
    if (phone !== undefined) user.phone = phone;
    if (address !== undefined) user.address = address;
    if (avatar !== undefined) user.avatar = avatar;
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters long" });
      }
      user.password = await bcrypt.hash(password, 10);
    }
    await user.save();
    const { password: _, ...userWithoutPassword } = user.toJSON();
    res.json({ success: true, user: userWithoutPassword });
  } catch (error) {
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// Test endpoint to check database
app.get("/api/test-conversions", async (req, res) => {
  try {
    console.log('🔍 Testing database connection...');
    
    // Test database connection
    await sequelize.authenticate();
    console.log('✅ Database connection successful');
    
    const allConversions = await ConversionHistory.findAll({
      order: [["timestamp", "DESC"]],
      limit: 10
    });
    
    console.log('✅ Found', allConversions.length, 'conversions in database');
    
    res.json({
      success: true,
      count: allConversions.length,
      conversions: allConversions,
      databaseStatus: 'connected'
    });
  } catch (error) {
    console.error("Test conversions error:", error);
    res.status(500).json({ 
      error: "Failed to get test conversions", 
      message: error.message,
      databaseStatus: 'error'
    });
  }
});

// Test conversion endpoint (no authentication required)
app.post("/api/test-convert", async (req, res) => {
  try {
    console.log('🧪 Test conversion request:', req.body);
    const { conversionType, fromUnit, toUnit, fromValue } = req.body;
    
    if (!conversionType || !fromUnit || !toUnit || fromValue === undefined) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    let result = null;

    // Simple weight conversion test
    if (conversionType === "weight") {
      if (fromUnit === "kg" && toUnit === "lb") {
        result = fromValue * 2.20462;
      } else if (fromUnit === "lb" && toUnit === "kg") {
        result = fromValue * 0.453592;
      } else {
        result = fromValue; // Same unit
      }
    } else {
      result = fromValue; // Default for other types
    }

    console.log('🧪 Test conversion result:', result);

    // Save to database with a test user ID
    const savedConversion = await ConversionHistory.create({
      id: Date.now().toString(),
      userId: 'test-user-123',
      conversionType,
      fromValue: parseFloat(fromValue),
      toValue: parseFloat(result.toFixed(6)),
      fromUnit,
      toUnit,
      timestamp: new Date().toISOString()
    });

    console.log('✅ Test conversion saved to database:', savedConversion.toJSON());

    res.json({
      success: true,
      result: {
        fromValue: parseFloat(fromValue),
        toValue: parseFloat(result.toFixed(6)),
        fromUnit,
        toUnit,
        conversionType
      },
      savedConversion: savedConversion.toJSON()
    });

  } catch (error) {
    console.error("Test conversion error:", error);
    res.status(500).json({ 
      error: "Test conversion failed", 
      message: error.message
    });
  }
});

// Debug endpoint to check authentication and history
app.get("/api/debug-history", async (req, res) => {
  try {
    console.log('🔍 Debug history request');
    console.log('🔍 Headers:', req.headers);
    
    const authHeader = req.headers['authorization'];
    console.log('🔍 Auth header:', authHeader);
    
    if (!authHeader) {
      return res.json({
        error: "No authorization header",
        message: "User is not logged in or token is missing"
      });
    }
    
    const token = authHeader.split(' ')[1];
    console.log('🔍 Token:', token);
    
    // Try to verify the token
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      console.log('🔍 Decoded token:', decoded);
      
      // Get user's history
      const userHistory = await ConversionHistory.findAll({
        where: { userId: decoded.userId },
        order: [["timestamp", "DESC"]],
        limit: 10
      });
      
      console.log('🔍 User history count:', userHistory.length);
      
      res.json({
        success: true,
        user: decoded,
        historyCount: userHistory.length,
        history: userHistory,
        message: "User is authenticated and history found"
      });
      
    } catch (jwtError) {
      console.log('🔍 JWT verification failed:', jwtError.message);
      res.json({
        error: "Invalid token",
        message: "Token is expired or invalid"
      });
    }
    
  } catch (error) {
    console.error("Debug history error:", error);
    res.status(500).json({ 
      error: "Debug failed", 
      message: error.message
    });
  }
});

// Conversion History Routes
app.get("/api/history", authenticateToken, async (req, res) => {
  try {
    console.log('📋 === BACKEND: HISTORY REQUEST ===');
    console.log('📋 Request headers:', req.headers);
    console.log('📋 Authorization header:', req.headers.authorization);
    console.log('📋 User object:', req.user);
    console.log('📋 Fetching history for user:', req.user.userId);
    
    const userHistory = await ConversionHistory.findAll({
      where: { userId: req.user.userId },
      order: [["timestamp", "DESC"]],
      limit: 50
    });
    
    console.log('📋 Found', userHistory.length, 'conversions for user');
    console.log('📋 History data:', userHistory.map(h => ({
      id: h.id,
      conversionType: h.conversionType,
      fromValue: h.fromValue,
      toValue: h.toValue,
      fromUnit: h.fromUnit,
      toUnit: h.toUnit,
      timestamp: h.timestamp
    })));
    
    res.json({
      success: true,
      history: userHistory
    });
  } catch (error) {
    console.error("Get history error:", error);
    res.status(500).json({ error: "Failed to get conversion history" });
  }
});

app.delete("/api/history/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await ConversionHistory.destroy({
      where: { id, userId: req.user.userId }
    });
    if (!deleted) {
      return res.status(404).json({ error: "Conversion not found" });
    }
    res.json({
      success: true,
      message: "Conversion deleted successfully"
    });
  } catch (error) {
    console.error("Delete history error:", error);
    res.status(500).json({ error: "Failed to delete conversion" });
  }
});

// Conversion Routes (now protected and saves history)
app.post("/api/convert", authenticateToken, validate('conversion'), async (req, res) => {
  try {
    const { conversionType, fromUnit, toUnit, fromValue } = req.body;
    

    
    if (!conversionType || !fromUnit || !toUnit || fromValue === undefined) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    let result = null;

    // Temperature conversions - Simple API-like approach
    if (conversionType === "temperature") {
      try {
        // Unit name mapping to handle both full names and abbreviations
        const unitMapping = {
          'c': 'Celsius',
          'celsius': 'Celsius',
          'Celsius': 'Celsius',
          'f': 'Fahrenheit',
          'fahrenheit': 'Fahrenheit',
          'Fahrenheit': 'Fahrenheit',
          'k': 'Kelvin',
          'kelvin': 'Kelvin',
          'Kelvin': 'Kelvin'
        };
        
        // Normalize unit names
        const normalizedFromUnit = unitMapping[fromUnit] || fromUnit;
        const normalizedToUnit = unitMapping[toUnit] || toUnit;
        
        // Simple temperature conversion with fallback rates
        const tempRates = {
          Celsius: { Fahrenheit: 1.8, Kelvin: 1 },
          Fahrenheit: { Celsius: 0.5556, Kelvin: 0.5556 },
          Kelvin: { Celsius: 1, Fahrenheit: 1.8 }
        };
        
        if (normalizedFromUnit === normalizedToUnit) {
          result = fromValue;
        } else if (normalizedFromUnit === "Celsius" && normalizedToUnit === "Fahrenheit") {
          result = fromValue * 1.8 + 32;
        } else if (normalizedFromUnit === "Fahrenheit" && normalizedToUnit === "Celsius") {
          result = (fromValue - 32) * 0.5556;
        } else if (normalizedFromUnit === "Celsius" && normalizedToUnit === "Kelvin") {
        result = fromValue + 273.15;
        } else if (normalizedFromUnit === "Kelvin" && normalizedToUnit === "Celsius") {
        result = fromValue - 273.15;
        } else if (normalizedFromUnit === "Fahrenheit" && normalizedToUnit === "Kelvin") {
          result = (fromValue - 32) * 0.5556 + 273.15;
        } else if (normalizedFromUnit === "Kelvin" && normalizedToUnit === "Fahrenheit") {
          result = (fromValue - 273.15) * 1.8 + 32;
        }
      } catch (error) {
        console.error('Temperature conversion error:', error.message);
        throw new Error(`Temperature conversion not supported: ${fromUnit} to ${toUnit}`);
      }
    }
    // Weight conversions - Simple API-like approach
    else if (conversionType === "weight") {
      try {
        // Unit name mapping to handle both full names and abbreviations
        const unitMapping = {
          'kg': 'Kilograms',
          'kilograms': 'Kilograms',
          'Kilograms': 'Kilograms',
          'lb': 'Pounds',
          'lbs': 'Pounds',
          'pounds': 'Pounds',
          'Pounds': 'Pounds',
          'g': 'Grams',
          'grams': 'Grams',
          'Grams': 'Grams',
          'oz': 'Ounces',
          'ounces': 'Ounces',
          'Ounces': 'Ounces'
        };
        
        // Normalize unit names
        const normalizedFromUnit = unitMapping[fromUnit] || fromUnit;
        const normalizedToUnit = unitMapping[toUnit] || toUnit;
        
        // Simple weight conversion with fallback rates
        const weightRates = {
          Kilograms: { Pounds: 2.20462, Grams: 1000, Ounces: 35.274 },
          Pounds: { Kilograms: 0.453592, Grams: 453.592, Ounces: 16 },
          Grams: { Kilograms: 0.001, Pounds: 0.00220462, Ounces: 0.035274 },
          Ounces: { Kilograms: 0.0283495, Pounds: 0.0625, Grams: 28.3495 }
        };
        
        if (normalizedFromUnit === normalizedToUnit) {
          result = fromValue;
        } else if (weightRates[normalizedFromUnit] && weightRates[normalizedFromUnit][normalizedToUnit]) {
          result = fromValue * weightRates[normalizedFromUnit][normalizedToUnit];
        } else {
          throw new Error(`Weight conversion not supported: ${fromUnit} to ${toUnit}`);
        }
      } catch (error) {
        console.error('Weight conversion error:', error.message);
        throw new Error(`Weight conversion not supported: ${fromUnit} to ${toUnit}`);
      }
    }
    // Length conversions - Simple API-like approach
    else if (conversionType === "length") {
      try {
        // Unit name mapping to handle both full names and abbreviations
        const unitMapping = {
          'm': 'Meters',
          'meters': 'Meters',
          'Meters': 'Meters',
          'ft': 'Feet',
          'feet': 'Feet',
          'Feet': 'Feet',
          'in': 'Inches',
          'inches': 'Inches',
          'Inches': 'Inches',
          'cm': 'Centimeters',
          'centimeters': 'Centimeters',
          'Centimeters': 'Centimeters',
          'mm': 'Centimeters',
          'km': 'Kilometers',
          'kilometers': 'Kilometers',
          'Kilometers': 'Kilometers',
          'mi': 'Miles',
          'miles': 'Miles',
          'Miles': 'Miles'
        };
        
        // Normalize unit names
        const normalizedFromUnit = unitMapping[fromUnit] || fromUnit;
        const normalizedToUnit = unitMapping[toUnit] || toUnit;
        

        
        // Simple length conversion with fallback rates
        const lengthRates = {
          Meters: { Feet: 3.28084, Inches: 39.3701, Centimeters: 100, Kilometers: 0.001, Miles: 0.000621371 },
          Feet: { Meters: 0.3048, Inches: 12, Centimeters: 30.48, Kilometers: 0.0003048, Miles: 0.000189394 },
          Inches: { Meters: 0.0254, Feet: 0.0833333, Centimeters: 2.54, Kilometers: 0.0000254, Miles: 0.0000157828 },
          Centimeters: { Meters: 0.01, Feet: 0.0328084, Inches: 0.393701, Kilometers: 0.00001, Miles: 0.00000621371 },
          Kilometers: { Meters: 1000, Feet: 3280.84, Inches: 39370.1, Centimeters: 100000, Miles: 0.621371 },
          Miles: { Meters: 1609.34, Feet: 5280, Inches: 63360, Centimeters: 160934, Kilometers: 1.60934 }
        };
        
        if (normalizedFromUnit === normalizedToUnit) {
          result = fromValue;
        } else if (lengthRates[normalizedFromUnit] && lengthRates[normalizedFromUnit][normalizedToUnit]) {
          result = fromValue * lengthRates[normalizedFromUnit][normalizedToUnit];
        } else {
          throw new Error(`Length conversion not supported: ${fromUnit} to ${toUnit}`);
        }
      } catch (error) {
        console.error('Length conversion error:', error.message);
        throw new Error(`Length conversion not supported: ${fromUnit} to ${toUnit}`);
      }
    }
    // Speed conversions - Simple API-like approach
    else if (conversionType === "speed") {
      try {
        // Unit name mapping to handle both full names and abbreviations
        const unitMapping = {
          'mph': 'MPH',
          'MPH': 'MPH',
          'kph': 'KPH',
          'km/h': 'KPH',
          'KPH': 'KPH',
          'm/s': 'm/s',
          'ms': 'm/s',
          'ft/s': 'ft/s',
          'fps': 'ft/s',
          'feet/s': 'ft/s'
        };
        
        // Normalize unit names
        const normalizedFromUnit = unitMapping[fromUnit] || fromUnit;
        const normalizedToUnit = unitMapping[toUnit] || toUnit;
        

        
        // Simple speed conversion with fallback rates
        const speedRates = {
          MPH: { KPH: 1.60934, 'm/s': 0.44704, 'ft/s': 1.46667 },
          KPH: { MPH: 0.621371, 'm/s': 0.277778, 'ft/s': 0.911344 },
          'm/s': { MPH: 2.23694, KPH: 3.6, 'ft/s': 3.28084 },
          'ft/s': { MPH: 0.681818, KPH: 1.09728, 'm/s': 0.3048 }
        };
        
        if (normalizedFromUnit === normalizedToUnit) {
          result = fromValue;
        } else if (speedRates[normalizedFromUnit] && speedRates[normalizedFromUnit][normalizedToUnit]) {
          result = fromValue * speedRates[normalizedFromUnit][normalizedToUnit];
        } else {
          throw new Error(`Speed conversion not supported: ${fromUnit} to ${toUnit}`);
        }
      } catch (error) {
        console.error('Speed conversion error:', error.message);
        throw new Error(`Speed conversion not supported: ${fromUnit} to ${toUnit}`);
      }
    }
    // Time conversions - Simple API-like approach
    else if (conversionType === "time") {
      try {
        // Unit name mapping to handle both full names and abbreviations
        const unitMapping = {
          's': 'Seconds',
          'sec': 'Seconds',
          'seconds': 'Seconds',
          'Seconds': 'Seconds',
          'm': 'Minutes',
          'min': 'Minutes',
          'minutes': 'Minutes',
          'Minutes': 'Minutes',
          'h': 'Hours',
          'hr': 'Hours',
          'hrs': 'Hours',
          'hours': 'Hours',
          'Hours': 'Hours',
          'd': 'Days',
          'day': 'Days',
          'days': 'Days',
          'Days': 'Days',
          'w': 'Weeks',
          'wk': 'Weeks',
          'weeks': 'Weeks',
          'Weeks': 'Weeks',
          'mo': 'Months',
          'month': 'Months',
          'months': 'Months',
          'Months': 'Months',
          'y': 'Years',
          'yr': 'Years',
          'year': 'Years',
          'years': 'Years',
          'Years': 'Years'
        };
        
        // Normalize unit names
        const normalizedFromUnit = unitMapping[fromUnit] || fromUnit;
        const normalizedToUnit = unitMapping[toUnit] || toUnit;
        

        
        // Simple time conversion with fallback rates
        const timeRates = {
          Seconds: { Minutes: 0.0166667, Hours: 0.000277778, Days: 0.0000115741, Weeks: 0.00000165344, Months: 0.000000380517, Years: 0.0000000317098 },
          Minutes: { Seconds: 60, Hours: 0.0166667, Days: 0.000694444, Weeks: 0.0000992063, Months: 0.0000228311, Years: 0.00000190259 },
          Hours: { Seconds: 3600, Minutes: 60, Days: 0.0416667, Weeks: 0.00595238, Months: 0.00136986, Years: 0.000114155 },
          Days: { Seconds: 86400, Minutes: 1440, Hours: 24, Weeks: 0.142857, Months: 0.0328767, Years: 0.00273973 },
          Weeks: { Seconds: 604800, Minutes: 10080, Hours: 168, Days: 7, Months: 0.230137, Years: 0.0191781 },
          Months: { Seconds: 2592000, Minutes: 43200, Hours: 720, Days: 30, Weeks: 4.28571, Years: 0.0833333 },
          Years: { Seconds: 31536000, Minutes: 525600, Hours: 8760, Days: 365, Weeks: 52.1429, Months: 12 }
        };
        
        if (normalizedFromUnit === normalizedToUnit) {
          result = fromValue;
        } else if (timeRates[normalizedFromUnit] && timeRates[normalizedFromUnit][normalizedToUnit]) {
          result = fromValue * timeRates[normalizedFromUnit][normalizedToUnit];
        } else {
          throw new Error(`Time conversion not supported: ${fromUnit} to ${toUnit}`);
        }
      } catch (error) {
        console.error('Time conversion error:', error.message);
        throw new Error(`Time conversion not supported: ${fromUnit} to ${toUnit}`);
      }
    }
    // Currency conversions with real-time rates
    else if (conversionType === "currency") {
      try {
        console.log(`Fetching real-time rates for ${fromUnit} to ${toUnit}`);
        
        // Fetch real-time exchange rates from Exchange Rate API
        const response = await axios.get(`https://api.exchangerate-api.com/v4/latest/${fromUnit}`, {
          timeout: 10000
        });
        
        const rates = response.data.rates;
        console.log(`Received rates for ${fromUnit}:`, rates);
        
        if (rates && rates[toUnit]) {
          result = fromValue * rates[toUnit];
          console.log(`Real-time conversion: ${fromValue} ${fromUnit} = ${result} ${toUnit} (rate: ${rates[toUnit]})`);
        } else {
          throw new Error(`Rate not found for ${toUnit}`);
        }
      } catch (error) {
        console.error('Currency API error:', error.message);
        
        // Fallback to hardcoded rates if API fails
        const fallbackRates = {
          USD: { EUR: 0.85, GBP: 0.73, JPY: 110, CAD: 1.25, AUD: 1.35, NPR: 133.45, INR: 74.5 },
          EUR: { USD: 1.18, GBP: 0.86, JPY: 129.41, CAD: 1.47, AUD: 1.59, NPR: 157.47, INR: 87.65 },
          GBP: { USD: 1.37, EUR: 1.16, JPY: 150.68, CAD: 1.71, AUD: 1.85, NPR: 182.83, INR: 102.05 },
          JPY: { USD: 0.0091, EUR: 0.0077, GBP: 0.0066, CAD: 0.0114, AUD: 0.0123, NPR: 1.21, INR: 0.68 },
          CAD: { USD: 0.80, EUR: 0.68, GBP: 0.58, JPY: 87.6, AUD: 1.08, NPR: 106.76, INR: 59.6 },
          AUD: { USD: 0.74, EUR: 0.63, GBP: 0.54, JPY: 81.48, CAD: 0.93, NPR: 98.85, INR: 55.19 },
          NPR: { USD: 0.0075, EUR: 0.0063, GBP: 0.0055, JPY: 0.83, CAD: 0.0094, AUD: 0.0101, INR: 0.56 },
          INR: { USD: 0.0134, EUR: 0.0114, GBP: 0.0098, JPY: 1.47, CAD: 0.0168, AUD: 0.0181, NPR: 1.79 }
        };
        
        if (fallbackRates[fromUnit] && fallbackRates[fromUnit][toUnit]) {
          result = fromValue * fallbackRates[fromUnit][toUnit];
          console.log(`Fallback conversion: ${fromValue} ${fromUnit} = ${result} ${toUnit}`);
        } else {
          throw new Error(`Currency conversion not supported: ${fromUnit} to ${toUnit}`);
        }
      }
    }

    // Check if conversion was successful
    if (result === null) {
      return res.status(400).json({ 
        error: "Conversion not supported", 
        message: `Cannot convert from ${fromUnit} to ${toUnit} for ${conversionType} type` 
      });
    }

    const conversionResult = {
      fromValue: parseFloat(fromValue),
      toValue: parseFloat(result.toFixed(6)),
      fromUnit,
      toUnit,
      conversionType
    };

    // Save conversion history
    console.log('💾 Saving conversion to database...');
    console.log('💾 User ID:', req.user.userId);
    console.log('💾 Conversion data:', {
      conversionType,
      fromValue: parseFloat(fromValue),
      toValue: parseFloat(result.toFixed(6)),
      fromUnit,
      toUnit
    });
    
    const savedConversion = await ConversionHistory.create({
      id: Date.now().toString(),
      userId: req.user.userId,
      conversionType,
      fromValue: parseFloat(fromValue),
      toValue: parseFloat(result.toFixed(6)),
      fromUnit,
      toUnit,
      timestamp: new Date().toISOString()
    });

    console.log('✅ Conversion saved successfully:', savedConversion.toJSON());

    // Get user details for real-time notification
    const user = await User.findByPk(req.user.userId);
    const conversionWithUser = {
      ...savedConversion.toJSON(),
      userName: user ? user.name : 'Unknown',
      userEmail: user ? user.email : 'Unknown'
    };

    console.log('📡 Emitting newConversion event:', conversionWithUser);

    // Emit real-time update to all connected admins
    io.emit('newConversion', {
      conversion: conversionWithUser,
      timestamp: new Date().toISOString()
    });

    // Track user activity
    const activity = {
      type: 'conversion',
      action: `Converted ${fromValue} ${fromUnit} to ${result.toFixed(6)} ${toUnit}`,
      conversionType,
      timestamp: new Date()
    };
    
    if (!userActivities.has(req.user.userId)) {
      userActivities.set(req.user.userId, []);
    }
    userActivities.get(req.user.userId).push(activity);
    
    // Keep only last 10 activities
    if (userActivities.get(req.user.userId).length > 10) {
      userActivities.set(req.user.userId, userActivities.get(req.user.userId).slice(-10));
    }

    // Note: Conversion notifications removed as per user request
    // Only bug reports, feature requests, and contact messages will trigger notifications



    res.json({
      success: true,
      result: conversionResult
    });

  } catch (error) {
    res.status(400).json({ error: "Conversion failed", message: error.message });
  }
});

// Units endpoint (public)
app.get("/api/units/:conversionType", (req, res) => {
  const { conversionType } = req.params;
  const units = {
    temperature: ["Celsius", "Fahrenheit", "Kelvin"],
    weight: ["Kilograms", "Pounds", "Grams", "Ounces"],
    length: ["Meters", "Feet", "Inches", "Centimeters", "Kilometers", "Miles"],
    speed: ["MPH", "KPH", "m/s", "ft/s"],
    currency: ["USD", "EUR", "GBP", "JPY", "CAD", "AUD", "NPR", "INR"],
    time: ["Seconds", "Minutes", "Hours", "Days", "Weeks", "Months", "Years"]
  };

  const availableUnits = units[conversionType];
  if (!availableUnits) {
    return res.status(400).json({ error: "Invalid conversion type" });
  }

  res.json({ conversionType, units: availableUnits });
});

// Ratings API
// Save or update a user's rating for a tool
app.post("/api/ratings", authenticateToken, validate('rating'), async (req, res) => {
  try {
    const { tool, rating } = req.body;
    if (!tool || typeof rating !== "number" || rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Tool and rating (1-5) are required" });
    }
    // Check if user already rated this tool
    let existing = await Rating.findOne({ where: { userId: req.user.userId, tool } });
    if (existing) {
      existing.rating = rating;
      existing.timestamp = new Date().toISOString();
      await existing.save();
    } else {
      await Rating.create({
        id: Date.now().toString(),
        userId: req.user.userId,
        tool,
        rating,
        timestamp: new Date().toISOString()
      });
    }

    // Track user activity
    const activity = {
      type: 'rating',
      action: `Rated ${tool} with ${rating} stars`,
      tool,
      rating,
      timestamp: new Date()
    };
    
    if (!userActivities.has(req.user.userId)) {
      userActivities.set(req.user.userId, []);
    }
    userActivities.get(req.user.userId).push(activity);
    
    // Keep only last 10 activities
    if (userActivities.get(req.user.userId).length > 10) {
      userActivities.set(req.user.userId, userActivities.get(req.user.userId).slice(-10));
    }

    // Note: Rating notifications removed as per user request
    // Only bug reports, feature requests, and contact messages will trigger notifications

    res.json({ success: true, message: "Rating saved" });
  } catch (error) {
    console.error("Save rating error:", error);
    res.status(500).json({ error: "Failed to save rating" });
  }
});

// Get average rating, count, and current user's rating for a tool
app.get("/api/ratings/:tool", authenticateToken, async (req, res) => {
  try {
    const { tool } = req.params;
    const toolRatings = await Rating.findAll({ where: { tool } });
    const count = toolRatings.length;
    const avg = count ? (toolRatings.reduce((sum, r) => sum + r.rating, 0) / count) : 0;
    const userRating = toolRatings.find(r => r.userId === req.user.userId)?.rating || null;
    res.json({
      success: true,
      tool,
      average: avg,
      count,
      userRating
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to get ratings" });
  }
});

// Bug Reports & Feature Requests API
// Submit a bug report or feature request
app.post("/api/reports", authenticateToken, validate('bugReport'), async (req, res) => {
  try {
    const { type, message } = req.body;
    if (!type || !message) {
      return res.status(400).json({ error: "Type and message are required" });
    }
    
    const report = await BugReport.create({
      id: Date.now().toString(),
      userId: req.user.userId,
      type, // 'bug' or 'feature'
      message,
      status: 'pending',
      timestamp: new Date().toISOString()
    });

    // Get user info for real-time notification
    const user = await User.findByPk(req.user.userId);
    
    // Notify all admins about new report in real-time
    adminSockets.forEach(adminSocketId => {
      io.to(adminSocketId).emit('newReport', {
        report: {
          id: report.id,
          userId: report.userId,
          userName: user.name,
          userEmail: user.email,
          type: report.type,
          message: report.message,
          status: report.status,
          timestamp: report.timestamp
        },
        timestamp: new Date()
      });
    });

    // Track user activity
    const activity = {
      type: 'report',
      action: `Submitted ${type} report`,
      reportType: type,
      timestamp: new Date()
    };
    
    if (!userActivities.has(req.user.userId)) {
      userActivities.set(req.user.userId, []);
    }
    userActivities.get(req.user.userId).push(activity);
    
    // Keep only last 10 activities
    if (userActivities.get(req.user.userId).length > 10) {
      userActivities.set(req.user.userId, userActivities.get(req.user.userId).slice(-10));
    }

    // Send auto-reply notification to user
    const autoReplyMessage = type === 'bug' 
      ? "Thank you for reporting this bug! Our team has been notified and will investigate the issue. We'll get back to you soon with updates."
      : "Thank you for your feature request! We appreciate your input and will review your suggestion. We'll notify you when we have updates.";
    
    await createNotification(
      req.user.userId,
      `Thank you for your ${type === 'bug' ? 'bug report' : 'feature request'}! 🎉`,
      autoReplyMessage,
      type === 'bug' ? 'bug_report' : 'feature_request'
    );

    res.json({ success: true, message: "Report submitted" });
  } catch (error) {
    console.error("Submit report error:", error);
    res.status(500).json({ error: "Failed to submit report" });
  }
});

// Public: Submit bug report or feature request (no login required)
app.post("/api/reports/public", async (req, res) => {
  try {
    const { name, email, type, message, browser, device } = req.body;
    
    if (!name || !email || !type || !message) {
      return res.status(400).json({ error: "Name, email, type, and message are required" });
    }
    
    if (!['bug', 'feature'].includes(type)) {
      return res.status(400).json({ error: "Type must be 'bug' or 'feature'" });
    }
    
    // Create a temporary user ID for public reports
    const tempUserId = 'public-' + Date.now().toString();
    
    const report = await BugReport.create({
      id: Date.now().toString(),
      userId: tempUserId,
      type,
      message: `[Public Report] ${message}\n\nFrom: ${name} (${email})\nBrowser: ${browser || 'Unknown'}\nDevice: ${device || 'Unknown'}`,
      timestamp: new Date().toISOString()
    });
    
    // Store additional info in memory for admin reference
    reportReplies.set(report.id, {
      publicReport: true,
      reporterName: name,
      reporterEmail: email,
      browser: browser,
      device: device,
      submittedAt: new Date().toISOString()
    });
    
    // Notify all admins about new public report in real-time
    adminSockets.forEach(adminSocketId => {
      io.to(adminSocketId).emit('newReport', {
        report: {
          id: report.id,
          userId: report.userId,
          userName: name,
          userEmail: email,
          type: report.type,
          message: report.message,
          status: 'pending',
          timestamp: report.timestamp
        },
        timestamp: new Date()
      });
    });
    
    // Send auto-reply notification to public user (stored for when they log in)
    const autoReplyMessage = type === 'bug' 
      ? "Thank you for reporting this bug! Our team has been notified and will investigate the issue. We'll get back to you soon with updates."
      : "Thank you for your feature request! We appreciate your input and will review your suggestion. We'll notify you when we have updates.";
    
    // Store auto-reply for when user creates account or logs in
    await createNotification(
      tempUserId,
      `Thank you for your ${type === 'bug' ? 'bug report' : 'feature request'}! 🎉`,
      autoReplyMessage,
      type === 'bug' ? 'bug_report' : 'feature_request'
    );
    
    res.json({ 
      success: true, 
      message: "Report submitted successfully",
      reportId: report.id
    });
  } catch (error) {
    console.error('Public report error:', error);
    res.status(500).json({ error: "Failed to submit report" });
  }
});

// Public: Submit contact message (no login required)
app.post("/api/contact/public", async (req, res) => {
  try {
    const { name, email, message } = req.body;
    
    if (!name || !email || !message) {
      return res.status(400).json({ error: "Name, email, and message are required" });
    }
    
    // Create a temporary user ID for public contact messages
    const tempUserId = 'contact-' + Date.now().toString();
    
    const contactMessage = await BugReport.create({
      id: Date.now().toString(),
      userId: tempUserId,
      type: 'contact',
      message: `[Contact Message]\n\nFrom: ${name} (${email})\n\nMessage: ${message}`,
      timestamp: new Date().toISOString()
    });
    
    // Store additional info in memory for admin reference
    reportReplies.set(contactMessage.id, {
      publicContact: true,
      contactName: name,
      contactEmail: email,
      submittedAt: new Date().toISOString()
    });
    
    // Notify all admins about new contact message in real-time
    adminSockets.forEach(adminSocketId => {
      io.to(adminSocketId).emit('newReport', {
        report: {
          id: contactMessage.id,
          userId: contactMessage.userId,
          userName: name,
          userEmail: email,
          type: 'contact',
          message: contactMessage.message,
          status: 'pending',
          timestamp: contactMessage.timestamp
        },
        timestamp: new Date()
      });
    });
    
    // Send auto-reply notification to contact user (stored for when they log in)
    const autoReplyMessage = "Thank you for contacting us! We have received your message and will get back to you as soon as possible. Our team typically responds within 24-48 hours.";
    
    // Store auto-reply for when user creates account or logs in
    await createNotification(
      tempUserId,
      "Thank you for contacting us! 📧",
      autoReplyMessage,
      'contact'
    );
    
    res.json({ 
      success: true, 
      message: "Contact message submitted successfully",
      messageId: contactMessage.id
    });
  } catch (error) {
    console.error('Public contact error:', error);
    res.status(500).json({ error: "Failed to submit contact message" });
  }
});

// Fetch all reports (admin only)
app.get("/api/admin/reports", authenticateAdmin, async (req, res) => {
  try {
    const reports = await BugReport.findAll({
      order: [['timestamp', 'DESC']]
    });
    
    // Get all users for lookup
    const users = await User.findAll();
    const userMap = new Map(users.map(user => [user.id, user]));
    
    // Get all replies from database
    const replies = await ReportReply.findAll();
    const replyMap = new Map(replies.map(reply => [reply.reportId, reply]));
    
    // Transform data to include user email and name, plus reply information
    const transformedReports = reports.map(report => {
      const user = userMap.get(report.userId);
      const replyData = replyMap.get(report.id) || reportReplies.get(report.id);
      
      return {
        ...report.toJSON(),
        userEmail: user ? user.email : 'Unknown User',
        userName: user ? user.name : 'Unknown User',
        status: replyData ? replyData.status : report.status || 'pending',
        reply: replyData ? replyData.reply : null,
        repliedAt: replyData ? replyData.repliedAt : null,
        repliedBy: replyData ? replyData.repliedBy : null,
        autoMessageSent: replyData ? replyData.autoMessageSent : false,
        autoMessageContent: replyData ? replyData.autoMessageContent : null
      };
    });
    
    res.json({ success: true, reports: transformedReports });
  } catch (error) {
    console.error('Reports fetch error:', error);
    res.status(500).json({ error: "Failed to fetch reports" });
  }
});

// Fetch report replies (admin only)
app.get("/api/admin/report-replies", authenticateAdmin, async (req, res) => {
  try {
    // Fetch replies from database
    const dbReplies = await ReportReply.findAll({
      order: [['repliedAt', 'DESC']]
    });
    
    // Convert database replies to the expected format
    const repliesObject = {};
    dbReplies.forEach(reply => {
      repliesObject[reply.reportId] = {
        reply: reply.reply,
        status: reply.status,
        repliedAt: reply.repliedAt,
        repliedBy: reply.repliedBy,
        reportId: reply.reportId,
        userId: reply.userId
      };
    });
    
    // Also include any in-memory replies for backward compatibility
    reportReplies.forEach((value, key) => {
      if (!repliesObject[key]) {
        repliesObject[key] = value;
      }
    });
    
    res.json({ success: true, replies: repliesObject });
  } catch (error) {
    console.error('Report replies fetch error:', error);
    res.status(500).json({ error: "Failed to fetch report replies" });
  }
});

// Admin Routes - Get all conversions
app.get("/api/admin/conversions", authenticateAdmin, async (req, res) => {
  try {
    const conversions = await ConversionHistory.findAll({
      order: [['timestamp', 'DESC']]
    });
    
    // Get all users for lookup
    const users = await User.findAll();
    const userMap = new Map(users.map(user => [user.id, user]));
    
    // Transform data to include user email and name
    const transformedConversions = conversions.map(conversion => {
      const user = userMap.get(conversion.userId);
      return {
        ...conversion.toJSON(),
        userEmail: user ? user.email : 'Unknown User',
        userName: user ? user.name : 'Unknown User'
      };
    });
    
    res.json({ conversions: transformedConversions });
  } catch (error) {
    console.error("Conversions fetch error:", error);
    res.status(500).json({ error: "Failed to fetch conversions" });
  }
});

// Admin Routes - Get all ratings
app.get("/api/admin/ratings", authenticateAdmin, async (req, res) => {
  try {
    const ratings = await Rating.findAll({
      order: [['timestamp', 'DESC']]
    });
    
    // Get all users for lookup
    const users = await User.findAll();
    const userMap = new Map(users.map(user => [user.id, user]));
    
    // Calculate average ratings by tool
    const toolRatings = {};
    ratings.forEach(rating => {
      if (!toolRatings[rating.tool]) {
        toolRatings[rating.tool] = [];
      }
      toolRatings[rating.tool].push(rating.rating);
    });
    
    const averageRatings = {};
    Object.keys(toolRatings).forEach(tool => {
      const avg = toolRatings[tool].reduce((sum, rating) => sum + rating, 0) / toolRatings[tool].length;
      averageRatings[tool] = parseFloat(avg.toFixed(2));
    });
    
    // Transform data to include user email and name
    const transformedRatings = ratings.map(rating => {
      const user = userMap.get(rating.userId);
      return {
        ...rating.toJSON(),
        userEmail: user ? user.email : 'Unknown User',
        userName: user ? user.name : 'Unknown User',
        averageRating: averageRatings[rating.tool] || 0
      };
    });
    
    res.json({ 
      ratings: transformedRatings,
      averageRatings,
      totalRatings: ratings.length
    });
  } catch (error) {
    console.error("Ratings fetch error:", error);
    res.status(500).json({ error: "Failed to fetch ratings" });
  }
});

// Comprehensive stats for admin
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.count();
    const totalConversions = await ConversionHistory.count();
    const totalReports = await BugReport.count();
    const totalRatings = await Rating.count();
    
    // Calculate average rating
    const ratings = await Rating.findAll();
    const averageRating = ratings.length > 0 
      ? ratings.reduce((sum, rating) => sum + rating.rating, 0) / ratings.length 
      : 0;

    res.json({
      totalUsers,
      totalConversions,
      totalReports,
      totalRatings,
      averageRating
    });
  } catch (error) {
    console.error("Stats fetch error:", error);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// Admin Routes - Get all notifications
app.get("/api/admin/notifications", authenticateAdmin, async (req, res) => {
  try {
    const notifications = await Notification.findAll({
      order: [['createdAt', 'DESC']],
      limit: 100
    });
    
    // Get all users for lookup
    const users = await User.findAll();
    const userMap = new Map(users.map(user => [user.id, user]));
    
    // Transform data to include user info
    const transformedNotifications = notifications.map(notification => {
      const user = userMap.get(notification.userId);
      return {
        ...notification.toJSON(),
        userEmail: user ? user.email : 'Unknown User',
        userName: user ? user.name : 'Unknown User'
      };
    });
    
    res.json({ notifications: transformedNotifications });
  } catch (error) {
    console.error("Notifications fetch error:", error);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// Admin Routes - Get all users
app.get("/api/admin/users", authenticateAdmin, async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'name', 'email', 'createdAt', 'isConfirmed', 'phone', 'address', 'avatar'],
      order: [['createdAt', 'DESC']]
    });
    
    // Transform data for frontend
    const transformedUsers = users.map(user => ({
      id: user.id,
      username: user.name,
      email: user.email,
      role: user.email === 'admin@smartconverter.com' ? 'Admin' : (user.isConfirmed ? 'User' : 'Pending'),
      createdAt: user.createdAt,
      phone: user.phone,
      address: user.address,
      avatar: user.avatar
    }));
    
    res.json({ users: transformedUsers });
  } catch (error) {
    console.error("Users fetch error:", error);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// Admin Routes - Get specific user profile
app.get("/api/admin/users/:userId", authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findByPk(userId);
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Check if this is the admin user
    const isAdminUser = user.email === 'admin@smartconverter.com';
    
    let conversions, ratings, reports;
    
    if (isAdminUser) {
      // For admin user, show total counts from all users
      conversions = await ConversionHistory.findAll({
        order: [['timestamp', 'DESC']],
        limit: 20
      });
      
      ratings = await Rating.findAll({
        order: [['timestamp', 'DESC']]
      });
      
      reports = await BugReport.findAll({
        order: [['timestamp', 'DESC']]
      });
    } else {
      // For regular users, show their personal data
      conversions = await ConversionHistory.findAll({
        where: { userId },
        order: [['timestamp', 'DESC']],
        limit: 20
      });
      
      ratings = await Rating.findAll({
        where: { userId },
        order: [['timestamp', 'DESC']]
      });
      
      reports = await BugReport.findAll({
        where: { userId },
        order: [['timestamp', 'DESC']]
      });
    }
    
    // Get user's activities
    const activities = userActivities.get(userId) || [];
    
    const { password: _, ...userWithoutPassword } = user.toJSON();
    
    res.json({
      success: true,
      user: userWithoutPassword,
      conversions,
      ratings,
      reports,
      activities
    });
  } catch (error) {
    console.error("User profile fetch error:", error);
    res.status(500).json({ error: "Failed to fetch user profile" });
  }
});

// Notification Routes
// Get user notifications
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    const userNotifications = notifications.filter(n => n.userId === req.user.userId);
    res.json({
      success: true,
      notifications: userNotifications.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// Mark notification as read
app.put("/api/notifications/:id/read", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const notification = notifications.find(n => n.id === id && n.userId === req.user.userId);
    if (notification) {
      notification.isRead = true;
    }
    res.json({ success: true, message: "Notification marked as read" });
  } catch (error) {
    res.status(500).json({ error: "Failed to mark notification as read" });
  }
});

// Mark all notifications as read
app.put("/api/notifications/read-all", authenticateToken, async (req, res) => {
  try {
    notifications.forEach(n => {
      if (n.userId === req.user.userId) {
        n.isRead = true;
      }
    });
    res.json({ success: true, message: "All notifications marked as read" });
  } catch (error) {
    res.status(500).json({ error: "Failed to mark notifications as read" });
  }
});

// Admin: Send notification to specific user
app.post("/api/admin/notifications", authenticateAdmin, async (req, res) => {
  try {
    const { userId, title, message, type = 'info' } = req.body;
    if (!userId || !title || !message) {
      return res.status(400).json({ error: "User ID, title, and message are required" });
    }
    
    // Create notification in database
    const notification = await Notification.create({
      id: Date.now().toString(),
      userId,
      title,
      message,
      type,
      isRead: false,
      createdAt: new Date().toISOString()
    });
    
    // Send real-time notification to user if they're online
    const userSocket = activeUsers.get(userId);
    if (userSocket) {
      io.to(userSocket.socketId).emit('notification', {
        id: notification.id,
        title: notification.title,
        message: notification.message,
        type: notification.type,
        createdAt: notification.createdAt
      });
    }
    
    res.json({ success: true, message: "Notification sent successfully" });
  } catch (error) {
    console.error('Error sending notification:', error);
    res.status(500).json({ error: "Failed to send notification" });
  }
});

// Admin: Send notification to all users
app.post("/api/admin/notifications/broadcast", authenticateAdmin, async (req, res) => {
  try {
    const { title, message, type = 'info' } = req.body;
    if (!title || !message) {
      return res.status(400).json({ error: "Title and message are required" });
    }
    
    const allUsers = await User.findAll();
    const notifications = [];
    
    for (const user of allUsers) {
      const notification = await Notification.create({
        id: Date.now().toString() + '_' + user.id,
        userId: user.id,
        title,
        message,
        type,
        isRead: false,
        createdAt: new Date().toISOString()
      });
      notifications.push(notification);
      
      // Send real-time notification to user if they're online
      const userSocket = activeUsers.get(user.id);
      if (userSocket) {
        io.to(userSocket.socketId).emit('notification', {
          id: notification.id,
          title: notification.title,
          message: notification.message,
          type: notification.type,
          createdAt: notification.createdAt
        });
      }
    }
    
    res.json({ success: true, message: `Notification sent to ${allUsers.length} users` });
  } catch (error) {
    console.error('Error sending broadcast notification:', error);
    res.status(500).json({ error: "Failed to send broadcast notification" });
  }
});

// Admin: Get all notifications (for admin panel)
app.get("/api/admin/notifications", authenticateAdmin, async (req, res) => {
  try {
    const allNotifications = await Notification.findAll({
      order: [['createdAt', 'DESC']]
    });
    
    res.json({
      success: true,
      notifications: allNotifications
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// Admin: Update and resend notification to users
app.put("/api/admin/notifications/:id/update", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, message, type = 'info' } = req.body;
    
    if (!title || !message) {
      return res.status(400).json({ error: "Title and message are required" });
    }
    
    const notification = await Notification.findByPk(id);
    if (!notification) {
      return res.status(404).json({ error: "Notification not found" });
    }
    
    // Update the notification
    await notification.update({
      title,
      message,
      type,
      updatedAt: new Date().toISOString()
    });
    
    // Resend to user if they're online
    const userSocket = activeUsers.get(notification.userId);
    if (userSocket) {
      io.to(userSocket.socketId).emit('notification', {
        id: notification.id,
        title: notification.title,
        message: notification.message,
        type: notification.type,
        createdAt: notification.createdAt,
        updatedAt: notification.updatedAt
      });
    }
    
    res.json({ 
      success: true, 
      message: "Notification updated and resent successfully",
      notification: {
        id: notification.id,
        title: notification.title,
        message: notification.message,
        type: notification.type,
        createdAt: notification.createdAt,
        updatedAt: notification.updatedAt
      }
    });
  } catch (error) {
    console.error('Error updating notification:', error);
    res.status(500).json({ error: "Failed to update notification" });
  }
});

// Admin: Resend notification to all users (for broadcast notifications)
app.post("/api/admin/notifications/:id/resend", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const notification = await Notification.findByPk(id);
    if (!notification) {
      return res.status(404).json({ error: "Notification not found" });
    }
    
    // Get all users
    const allUsers = await User.findAll();
    let sentCount = 0;
    
    // Resend to all online users
    for (const user of allUsers) {
      const userSocket = activeUsers.get(user.id);
      if (userSocket) {
        io.to(userSocket.socketId).emit('notification', {
          id: notification.id,
          title: notification.title,
          message: notification.message,
          type: notification.type,
          createdAt: notification.createdAt
        });
        sentCount++;
      }
    }
    
    res.json({ 
      success: true, 
      message: `Notification resent to ${sentCount} online users`,
      sentCount
    });
  } catch (error) {
    console.error('Error resending notification:', error);
    res.status(500).json({ error: "Failed to resend notification" });
  }
});

// Admin: Update all previous notifications and resend to users
app.post("/api/admin/notifications/update-all", authenticateAdmin, async (req, res) => {
  try {
    const { title, message, type = 'info' } = req.body;
    
    if (!title || !message) {
      return res.status(400).json({ error: "Title and message are required" });
    }
    
    // Get all notifications
    const allNotifications = await Notification.findAll();
    let updatedCount = 0;
    let sentCount = 0;
    
    // Update each notification
    for (const notification of allNotifications) {
      await notification.update({
        title,
        message,
        type,
        updatedAt: new Date().toISOString()
      });
      updatedCount++;
      
      // Resend to user if they're online
      const userSocket = activeUsers.get(notification.userId);
      if (userSocket) {
        io.to(userSocket.socketId).emit('notification', {
          id: notification.id,
          title: notification.title,
          message: notification.message,
          type: notification.type,
          createdAt: notification.createdAt,
          updatedAt: notification.updatedAt
        });
        sentCount++;
      }
    }
    
    res.json({ 
      success: true, 
      message: `Updated ${updatedCount} notifications and resent to ${sentCount} online users`,
      updatedCount,
      sentCount
    });
  } catch (error) {
    console.error('Error updating all notifications:', error);
    res.status(500).json({ error: "Failed to update notifications" });
  }
});

// Admin: Get user activities
app.get("/api/admin/user-activities", authenticateAdmin, async (req, res) => {
  try {
    const activities = [];
    for (const [userId, userActivityList] of userActivities.entries()) {
      const user = await User.findByPk(userId);
      if (user) {
        activities.push({
          userId,
          userName: user.name,
          userEmail: user.email,
          activities: userActivityList
        });
      }
    }
    
    res.json({
      success: true,
      activities: activities.sort((a, b) => {
        const aLatest = a.activities[a.activities.length - 1]?.timestamp || 0;
        const bLatest = b.activities[b.activities.length - 1]?.timestamp || 0;
        return new Date(bLatest) - new Date(aLatest);
      })
    });
  } catch (error) {
    console.error('Get user activities error:', error);
    res.status(500).json({ error: "Failed to fetch user activities" });
  }
});

// Admin: Reply to bug report or feature request
app.post("/api/admin/reports/:id/reply", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reply, status } = req.body;
    
    if (!reply) {
      return res.status(400).json({ error: "Reply message is required" });
    }
    
    const report = await BugReport.findByPk(id);
    if (!report) {
      return res.status(404).json({ error: "Report not found" });
    }
    
    // Get user info for notification
    const user = await User.findByPk(report.userId);
    
    // Store reply and status in database
    await ReportReply.create({
      id: Date.now().toString(),
      reportId: id,
      userId: report.userId,
      reply: reply,
      status: status || 'resolved',
      repliedBy: 'admin',
      repliedAt: new Date().toISOString(),
      autoMessageSent: false,
      autoMessageContent: null
    });
    
    // Also keep in memory for backward compatibility
    reportReplies.set(id, {
      reply: reply,
      status: status || 'resolved',
      repliedAt: new Date().toISOString(),
      repliedBy: 'admin',
      reportId: id,
      userId: report.userId
    });
    
    // Send admin reply notification to user
    await createNotification(
      report.userId,
      `Response to your ${report.type === 'bug' ? 'bug report' : 'feature request'} 📧`,
      `Admin Response: ${reply}`,
      'admin_reply'
    );
    
    // Update report status in database
    await report.update({ status: status || 'resolved' });
    
    // Send real-time notification to user if they're online
    const userSocket = Array.from(activeUsers.entries()).find(([userId, userData]) => userId === report.userId);
    if (userSocket) {
      io.to(userSocket[1].socketId).emit('notification', {
        id: Date.now().toString(),
        title: `Response to your ${report.type === 'bug' ? 'bug report' : 'feature request'} 📧`,
        message: `Admin Response: ${reply}`,
        type: 'admin_reply',
        createdAt: new Date().toISOString()
      });
    }
    
    res.json({ 
      success: true, 
      message: "Reply sent successfully and report marked as resolved",
      report: {
        id: report.id,
        status: status || 'resolved',
        reply: reply,
        repliedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Reply error:', error);
    res.status(500).json({ error: "Failed to send reply" });
  }
});



// Admin: Update report status
app.put("/api/admin/reports/:id/status", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    const validStatuses = ['pending', 'in_progress', 'resolved'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }
    
    const report = await BugReport.findByPk(id);
    if (!report) {
      return res.status(404).json({ error: "Report not found" });
    }
    
    report.status = status;
    await report.save();
    
    res.json({ success: true, message: "Status updated successfully" });
  } catch (error) {
    console.error('Status update error:', error);
    res.status(500).json({ error: "Failed to update status" });
  }
});

// Socket.IO event handlers
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // User authentication
  socket.on('authenticate', async (data) => {
    try {
      const { token, isAdmin } = data;
      
      if (isAdmin) {
        // Admin authentication
        if (token && token.startsWith('admin-token-')) {
          adminSockets.add(socket.id);
          socket.emit('authenticated', { isAdmin: true });
          console.log('Admin authenticated:', socket.id);
          
          // Send current active users to admin
          const activeUsersList = Array.from(activeUsers.values()).map(user => ({
            id: user.user.id,
            name: user.user.name,
            email: user.user.email,
            lastActivity: user.lastActivity,
            socketId: user.socketId
          }));
          socket.emit('activeUsers', activeUsersList);
          
          // Send admin online status to all users
          activeUsers.forEach(userData => {
            io.to(userData.socketId).emit('adminStatus', { isOnline: true });
          });
        }
      } else {
        // Regular user authentication
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findByPk(decoded.userId);
        
        if (user) {
          activeUsers.set(user.id, {
            socketId: socket.id,
            user: {
              id: user.id,
              name: user.name,
              email: user.email
            },
            lastActivity: new Date()
          });
          
          socket.userId = user.id;
          socket.emit('authenticated', { isAdmin: false, user: { id: user.id, name: user.name, email: user.email } });
          console.log('User authenticated:', user.name, socket.id);
          
          // Send admin online status to user
          socket.emit('adminStatus', { isOnline: adminSockets.size > 0 });
          
          // Notify admins about new active user
          adminSockets.forEach(adminSocketId => {
            io.to(adminSocketId).emit('userActivity', {
              type: 'user_online',
              user: { id: user.id, name: user.name, email: user.email },
              timestamp: new Date()
            });
          });
        }
      }
    } catch (error) {
      console.error('Authentication error:', error);
      socket.emit('authError', { message: 'Authentication failed' });
    }
  });

  // Handle bug report and feature request submissions
  socket.on('submitReport', async (data) => {
    try {
      const { type, message, token } = data;
      
      // Verify user token
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findByPk(decoded.userId);
      
      if (!user) {
        socket.emit('reportError', { message: 'User not found' });
        return;
      }
      
      const report = await BugReport.create({
        id: Date.now().toString(),
        userId: user.id,
        type,
        message,
        status: 'pending',
        timestamp: new Date().toISOString()
      });
      
      // Notify all admins about new report in real-time
      adminSockets.forEach(adminSocketId => {
        io.to(adminSocketId).emit('newReport', {
          report: {
            id: report.id,
            userId: report.userId,
            userName: user.name,
            userEmail: user.email,
            type: report.type,
            message: report.message,
            status: report.status,
            timestamp: report.timestamp
          },
          timestamp: new Date()
        });
      });
      
      socket.emit('reportSubmitted', { success: true, reportId: report.id });
      
    } catch (error) {
      console.error('Socket report submission error:', error);
      socket.emit('reportError', { message: 'Failed to submit report' });
    }
  });

  // User activity tracking
  socket.on('userActivity', (data) => {
    if (socket.userId && activeUsers.has(socket.userId)) {
      const userData = activeUsers.get(socket.userId);
      userData.lastActivity = new Date();
      activeUsers.set(socket.userId, userData);
      
      // Notify admins about user activity
      adminSockets.forEach(adminSocketId => {
        io.to(adminSocketId).emit('userActivity', {
          type: 'activity',
          user: userData.user,
          activity: data.activity,
          timestamp: new Date()
        });
      });
    }
  });

  // Disconnect handling
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    
    // Remove from admin sockets
    if (adminSockets.has(socket.id)) {
      adminSockets.delete(socket.id);
      
      // Notify all users that admin is offline
      activeUsers.forEach(userData => {
        io.to(userData.socketId).emit('adminStatus', { isOnline: adminSockets.size > 0 });
      });
      return;
    }
    
    // Remove from active users
    if (socket.userId && activeUsers.has(socket.userId)) {
      const userData = activeUsers.get(socket.userId);
      activeUsers.delete(socket.userId);
      
      // Notify admins about user going offline
      adminSockets.forEach(adminSocketId => {
        io.to(adminSocketId).emit('userActivity', {
          type: 'user_offline',
          user: userData.user,
          timestamp: new Date()
        });
      });
    }
  });
});

// Real-time stats update function
const updateRealTimeStats = async () => {
  try {
    const totalUsers = await User.count();
    const totalConversions = await ConversionHistory.count();
    const totalReports = await BugReport.count();
    const totalRatings = await Rating.count();
    const activeUsersCount = activeUsers.size;
    
    // Calculate average rating
    const ratings = await Rating.findAll();
    const averageRating = ratings.length > 0 
      ? ratings.reduce((sum, rating) => sum + rating.rating, 0) / ratings.length 
      : 0;

    const stats = {
      totalUsers,
      totalConversions,
      totalReports,
      totalRatings,
      averageRating,
      activeUsersCount,
      lastUpdated: new Date()
    };

    // Send updated stats to all admin sockets
    adminSockets.forEach(adminSocketId => {
      io.to(adminSocketId).emit('statsUpdate', stats);
    });
  } catch (error) {
    console.error('Error updating real-time stats:', error);
  }
};

// Test Results API (Admin only)
app.get("/api/admin/test-results", authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, status, testSuite, environment } = req.query;
    const offset = (page - 1) * limit;
    
    const whereClause = {};
    if (status) whereClause.status = status;
    if (testSuite) whereClause.testSuite = testSuite;
    if (environment) whereClause.environment = environment;

    const results = await TestResult.findAndCountAll({
      where: whereClause,
      order: [['timestamp', 'DESC']],
      limit: parseInt(limit),
      offset: parseInt(offset)
    });

    res.json({
      success: true,
      data: {
        results: results.rows,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(results.count / limit),
          totalResults: results.count,
          resultsPerPage: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('Error fetching test results:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch test results' });
  }
});

app.get("/api/admin/test-results/summary", authenticateAdmin, async (req, res) => {
  try {
    const { days = 7 } = req.query;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    const results = await TestResult.findAll({
      where: {
        timestamp: {
          [Op.gte]: startDate
        }
      },
      attributes: ['status', 'testSuite', 'timestamp']
    });

    const summary = {
      total: results.length,
      passed: results.filter(r => r.status === 'PASS').length,
      failed: results.filter(r => r.status === 'FAIL').length,
      skipped: results.filter(r => r.status === 'SKIP').length,
      bySuite: {},
      byDay: {}
    };

    // Group by test suite
    results.forEach(result => {
      if (!summary.bySuite[result.testSuite]) {
        summary.bySuite[result.testSuite] = { total: 0, passed: 0, failed: 0, skipped: 0 };
      }
      summary.bySuite[result.testSuite].total++;
      summary.bySuite[result.testSuite][result.status.toLowerCase()]++;
    });

    // Group by day
    results.forEach(result => {
      const day = result.timestamp.toISOString().split('T')[0];
      if (!summary.byDay[day]) {
        summary.byDay[day] = { total: 0, passed: 0, failed: 0, skipped: 0 };
      }
      summary.byDay[day].total++;
      summary.byDay[day][result.status.toLowerCase()]++;
    });

    res.json({
      success: true,
      data: summary
    });
  } catch (error) {
    console.error('Error fetching test summary:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch test summary' });
  }
});

app.delete("/api/admin/test-results", authenticateAdmin, async (req, res) => {
  try {
    const { days } = req.query;
    
    if (days) {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - parseInt(days));
      
      const deletedCount = await TestResult.destroy({
        where: {
          timestamp: {
            [Op.lt]: startDate
          }
        }
      });
      
      res.json({
        success: true,
        message: `Deleted ${deletedCount} test results older than ${days} days`
      });
    } else {
      const deletedCount = await TestResult.destroy({
        where: {},
        truncate: true
      });
      
      res.json({
        success: true,
        message: `Deleted all ${deletedCount} test results`
      });
    }
  } catch (error) {
    console.error('Error deleting test results:', error);
    res.status(500).json({ success: false, error: 'Failed to delete test results' });
  }
});

// Update stats every 30 seconds
setInterval(updateRealTimeStats, 30000);

// Start server
sequelize.sync({ force: false }).then(() => {
  console.log("✅ Database synchronized successfully");
  server.listen(PORT, () => {
    console.log("🚀 Smart Converter Backend running on port " + PORT);
    console.log("📡 WebSocket server ready for real-time connections");
  });
}).catch((err) => {
  console.error('Unable to connect to the database:', err);
});

module.exports = { app, server };
