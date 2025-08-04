const axios = require('axios');
const { Sequelize } = require('sequelize');
const request = require('supertest');
const path = require('path');
require('dotenv').config();

// Test configuration
const BASE_URL = 'http://localhost:5001';
const TEST_USER = {
  email: 'test@example.com',
  password: 'Test123',
  name: 'Test User'
};

let authToken = null;
let testUserId = null;

// Database connections
const mainDb = new Sequelize(
  process.env.DB_NAME || 'smart_converter',
  process.env.DB_USER || 'root',
  process.env.DB_PASS || '12345678',
  {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    dialect: 'mysql',
    logging: false
  }
);

const testDb = new Sequelize(
  process.env.TEST_DB_NAME || 'testing',
  process.env.DB_USER || 'root',
  process.env.DB_PASS || '12345678',
  {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    dialect: 'mysql',
    logging: false
  }
);

// Test Result Model for storing test results
const TestResult = testDb.define('TestResult', {
  testSuite: {
    type: Sequelize.STRING,
    allowNull: false
  },
  testName: {
    type: Sequelize.STRING,
    allowNull: false
  },
  status: {
    type: Sequelize.ENUM('PASS', 'FAIL'),
    allowNull: false
  },
  duration: {
    type: Sequelize.INTEGER,
    allowNull: false
  },
  errorMessage: {
    type: Sequelize.TEXT,
    allowNull: true
  },
  environment: {
    type: Sequelize.STRING,
    defaultValue: 'test'
  },
  timestamp: {
    type: Sequelize.DATE,
    defaultValue: Sequelize.NOW
  },
  nodeVersion: {
    type: Sequelize.STRING
  },
  osInfo: {
    type: Sequelize.STRING
  }
});

// Test utilities
const saveTestResult = async (testSuite, testName, status, duration, errorMessage = null) => {
  try {
    await TestResult.create({
      testSuite,
      testName,
      status,
      duration,
      errorMessage,
      environment: 'test',
      timestamp: new Date(),
      nodeVersion: process.version,
      osInfo: `${process.platform} ${process.arch}`
    });
  } catch (error) {
    console.error('Error saving test result:', error.message);
  }
};

const cleanupDatabase = async () => {
  try {
    // Clean up test data from main database
    await mainDb.query('DELETE FROM BugReports WHERE userId LIKE "test-%"');
    await mainDb.query('DELETE FROM ConversionHistories WHERE userId LIKE "test-%"');
    await mainDb.query('DELETE FROM Ratings WHERE userId LIKE "test-%"');
    await mainDb.query('DELETE FROM Users WHERE email LIKE "test%"');
    console.log('✅ Main database cleaned up');
  } catch (error) {
    console.error('❌ Error cleaning main database:', error.message);
  }
};

const createTestUser = async () => {
  try {
    const response = await axios.post(`${BASE_URL}/api/auth/register`, TEST_USER);
    if (response.data.success) {
      testUserId = response.data.user.id;
      console.log('✅ Test user created');
    }
  } catch (error) {
    console.log('ℹ️ Test user might already exist');
  }
};

const loginTestUser = async () => {
  try {
    const response = await axios.post(`${BASE_URL}/api/auth/login`, {
      email: TEST_USER.email,
      password: TEST_USER.password
    });
    
    if (response.data.success) {
      authToken = response.data.token;
      console.log('✅ Test user logged in');
    }
  } catch (error) {
    console.error('❌ Login failed:', error.response?.data || error.message);
  }
};

// Test functions
const testHealthEndpoint = async () => {
  const startTime = Date.now();
  try {
    const response = await axios.get(`${BASE_URL}/api/health`);
    const duration = Date.now() - startTime;
    
    if (response.data.status === 'OK') {
      await saveTestResult('API', 'Health Endpoint', 'PASS', duration);
      console.log('✅ Health endpoint working');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('API', 'Health Endpoint', 'FAIL', duration, error.message);
    console.error('❌ Health endpoint failed:', error.message);
    return false;
  }
};

const testDatabaseConnection = async () => {
  const startTime = Date.now();
  try {
    await mainDb.authenticate();
    await testDb.authenticate();
    const duration = Date.now() - startTime;
    await saveTestResult('Database', 'Connection Test', 'PASS', duration);
    console.log('✅ Database connections successful');
    return true;
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('Database', 'Connection Test', 'FAIL', duration, error.message);
    console.error('❌ Database connection failed:', error.message);
    return false;
  }
};

const testConversionAPI = async () => {
  const startTime = Date.now();
  try {
    const conversionData = {
      conversionType: 'temperature',
      fromUnit: 'Celsius',
      toUnit: 'Fahrenheit',
      fromValue: 25
    };

    const response = await axios.post(`${BASE_URL}/api/convert`, conversionData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    const duration = Date.now() - startTime;

    if (response.data.success && response.data.result.toValue === 77) {
      await saveTestResult('API', 'Conversion API', 'PASS', duration);
      console.log('✅ Conversion API working');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('API', 'Conversion API', 'FAIL', duration, error.response?.data?.message || error.message);
    console.error('❌ Conversion API failed:', error.response?.data || error.message);
    return false;
  }
};

const testBugReportAPI = async () => {
  const startTime = Date.now();
  try {
    const reportData = {
      type: 'bug',
      message: 'Test bug report from API test'
    };

    const response = await axios.post(`${BASE_URL}/api/reports`, reportData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    const duration = Date.now() - startTime;

    if (response.data.success) {
      await saveTestResult('API', 'Bug Report API', 'PASS', duration);
      console.log('✅ Bug Report API working');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('API', 'Bug Report API', 'FAIL', duration, error.response?.data?.message || error.message);
    console.error('❌ Bug Report API failed:', error.response?.data || error.message);
    return false;
  }
};

const testPublicBugReportAPI = async () => {
  const startTime = Date.now();
  try {
    const reportData = {
      name: 'Test User',
      email: 'test@example.com',
      type: 'bug',
      message: 'Test public bug report',
      browser: 'Chrome',
      device: 'Desktop'
    };

    const response = await axios.post(`${BASE_URL}/api/reports/public`, reportData);
    const duration = Date.now() - startTime;

    if (response.data.success) {
      await saveTestResult('API', 'Public Bug Report API', 'PASS', duration);
      console.log('✅ Public Bug Report API working');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('API', 'Public Bug Report API', 'FAIL', duration, error.response?.data?.message || error.message);
    console.error('❌ Public Bug Report API failed:', error.response?.data || error.message);
    return false;
  }
};

const testContactAPI = async () => {
  const startTime = Date.now();
  try {
    const contactData = {
      name: 'Test User',
      email: 'test@example.com',
      message: 'Test contact message'
    };

    const response = await axios.post(`${BASE_URL}/api/contact/public`, contactData);
    const duration = Date.now() - startTime;

    if (response.data.success) {
      await saveTestResult('API', 'Contact API', 'PASS', duration);
      console.log('✅ Contact API working');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('API', 'Contact API', 'FAIL', duration, error.response?.data?.message || error.message);
    console.error('❌ Contact API failed:', error.response?.data || error.message);
    return false;
  }
};

const testUnitsAPI = async () => {
  const startTime = Date.now();
  try {
    const response = await axios.get(`${BASE_URL}/api/units/temperature`);
    const duration = Date.now() - startTime;

    if (response.data.units && response.data.units.includes('Celsius')) {
      await saveTestResult('API', 'Units API', 'PASS', duration);
      console.log('✅ Units API working');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('API', 'Units API', 'FAIL', duration, error.response?.data?.message || error.message);
    console.error('❌ Units API failed:', error.response?.data || error.message);
    return false;
  }
};

// User Management Tests
const testUserCreationWithoutImage = async () => {
  const startTime = Date.now();
  try {
    const uniqueUsername = `testuser_noimage_${Date.now()}`;
    const uniqueEmail = `noimage_${Date.now()}@example.com`;

    const response = await request(BASE_URL)
      .post('/api/auth/register')
      .send({
        name: uniqueUsername,
        email: uniqueEmail,
        password: 'securepassword123'
      });

    const duration = Date.now() - startTime;

    if (response.body.success) {
      await saveTestResult('User Management', 'Create User Without Image', 'PASS', duration);
      console.log('✅ User creation without image working');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('User Management', 'Create User Without Image', 'FAIL', duration, error.message);
    console.error('❌ User creation without image failed:', error.message);
    return false;
  }
};

const testUserCreationWithMissingFields = async () => {
  const startTime = Date.now();
  try {
    const response = await request(BASE_URL)
      .post('/api/auth/register')
      .send({
        name: 'test_incomplete',
        email: 'incomplete@example.com'
        // Missing password
      });

    const duration = Date.now() - startTime;

    if (!response.body.success) {
      await saveTestResult('User Management', 'Create User Missing Fields', 'PASS', duration);
      console.log('✅ User creation validation working (missing fields)');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('User Management', 'Create User Missing Fields', 'FAIL', duration, error.message);
    console.error('❌ User creation validation failed:', error.message);
    return false;
  }
};

const testUserLogin = async () => {
  const startTime = Date.now();
  try {
    const userData = {
      email: TEST_USER.email,
      password: TEST_USER.password
    };

    const response = await request(BASE_URL)
      .post('/api/auth/login')
      .send(userData);

    const duration = Date.now() - startTime;

    if (response.body.success) {
      await saveTestResult('User Management', 'User Login', 'PASS', duration);
      console.log('✅ User login working');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('User Management', 'User Login', 'FAIL', duration, error.message);
    console.error('❌ User login failed:', error.message);
    return false;
  }
};

const testGetAllUsers = async () => {
  const startTime = Date.now();
  try {
    const response = await request(BASE_URL)
      .get('/api/users')
      .set('Authorization', `Bearer ${authToken}`);

    const duration = Date.now() - startTime;

    if (response.body.success && Array.isArray(response.body.users)) {
      await saveTestResult('User Management', 'Get All Users', 'PASS', duration);
      console.log('✅ Get all users working');
      return true;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('User Management', 'Get All Users', 'FAIL', duration, error.message);
    console.error('❌ Get all users failed:', error.message);
    return false;
  }
};

const testUnauthorizedAccess = async () => {
  const startTime = Date.now();
  try {
    const response = await request(BASE_URL)
      .get('/api/users');

    const duration = Date.now() - startTime;

    // Check for any unauthorized response (401, 403, or error response)
    if (response.status === 401 || response.status === 403 || !response.body.success) {
      await saveTestResult('Authorization', 'Unauthorized Access', 'PASS', duration);
      console.log('✅ Unauthorized access protection working');
      return true;
    } else {
      await saveTestResult('Authorization', 'Unauthorized Access', 'FAIL', duration, `Expected unauthorized access, got status ${response.status}`);
      console.log('❌ Unauthorized access test failed: Expected unauthorized access');
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('Authorization', 'Unauthorized Access', 'FAIL', duration, error.message);
    console.error('❌ Unauthorized access test failed:', error.message);
    return false;
  }
};

// Main test runner
const runComprehensiveTests = async () => {
  console.log('🚀 Starting Comprehensive API Tests...\n');
  
  const results = {
    // Database and Health
    database: false,
    health: false,
    
    // Core API Tests
    conversion: false,
    bugReport: false,
    publicBugReport: false,
    contact: false,
    units: false,
    
    // User Management Tests
    userCreationNoImage: false,
    userCreationMissingFields: false,
    userLogin: false,
    getAllUsers: false,
    unauthorizedAccess: false
  };

  // Initialize test database
  try {
    await testDb.sync({ force: false });
    console.log('✅ Test database synchronized');
  } catch (error) {
    console.error('❌ Test database sync failed:', error.message);
  }

  // Test database connection first
  results.database = await testDatabaseConnection();
  
  // Test health endpoint
  results.health = await testHealthEndpoint();
  
  // Setup test user
  await cleanupDatabase();
  await createTestUser();
  await loginTestUser();
  
  // Run API tests
  if (authToken) {
    results.conversion = await testConversionAPI();
    results.bugReport = await testBugReportAPI();
  }
  
  results.publicBugReport = await testPublicBugReportAPI();
  results.contact = await testContactAPI();
  results.units = await testUnitsAPI();
  
  // Run User Management tests
  results.userCreationNoImage = await testUserCreationWithoutImage();
  results.userCreationMissingFields = await testUserCreationWithMissingFields();
  results.userLogin = await testUserLogin();
  results.getAllUsers = await testGetAllUsers();
  results.unauthorizedAccess = await testUnauthorizedAccess();
  
  // Cleanup
  await cleanupDatabase();
  await mainDb.close();
  await testDb.close();
  
  // Print results
  console.log('\n📊 Comprehensive Test Results:');
  console.log('================================');
  Object.entries(results).forEach(([test, passed]) => {
    console.log(`${passed ? '✅' : '❌'} ${test}: ${passed ? 'PASSED' : 'FAILED'}`);
  });
  
  const passedTests = Object.values(results).filter(Boolean).length;
  const totalTests = Object.keys(results).length;
  
  console.log(`\n🎯 Overall: ${passedTests}/${totalTests} tests passed`);
  
  if (passedTests === totalTests) {
    console.log('🎉 All tests passed! Your API is working perfectly.');
  } else {
    console.log('⚠️ Some tests failed. Check the errors above.');
  }
  
  // Show test results from database
  try {
    const testResults = await TestResult.findAll({
      order: [['timestamp', 'DESC']],
      limit: 10
    });
    
    console.log('\n📋 Recent Test Results from Database:');
    console.log('=====================================');
    testResults.forEach(result => {
      console.log(`${result.status === 'PASS' ? '✅' : '❌'} ${result.testSuite} - ${result.testName} (${result.duration}ms)`);
    });
  } catch (error) {
    console.log('Could not retrieve test results from database');
  }
};

// Run tests if this file is executed directly
if (require.main === module) {
  runComprehensiveTests().catch(console.error);
}

module.exports = {
  runComprehensiveTests,
  testHealthEndpoint,
  testDatabaseConnection,
  testConversionAPI,
  testBugReportAPI,
  testPublicBugReportAPI,
  testContactAPI,
  testUnitsAPI,
  testUserCreationWithoutImage,
  testUserCreationWithMissingFields,
  testUserLogin,
  testGetAllUsers,
  testUnauthorizedAccess,
  saveTestResult
}; 