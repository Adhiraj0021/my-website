const { schemas } = require('./src/middleware/validation.js');
const axios = require('axios');
const { Sequelize } = require('sequelize');
require('dotenv').config();

// Test configuration
const BASE_URL = 'http://localhost:5001';

// Database connection for test results
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

// Test Result Model for storing validation test results
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
      timestamp: new Date()
    });
  } catch (error) {
    console.error('Error saving test result:', error.message);
  }
};

const testSchemaValidation = async (schemaName, testData, shouldPass = true, expectedErrors = []) => {
  const startTime = Date.now();
  try {
    const schema = schemas[schemaName];
    const { error, value } = schema.validate(testData, {
      abortEarly: false,
      stripUnknown: true
    });

    const duration = Date.now() - startTime;

    if (shouldPass && !error) {
      await saveTestResult('Joi Validation', `${schemaName} - Valid Data`, 'PASS', duration);
      console.log(`✅ ${schemaName} - Valid data passed`);
      return true;
    } else if (!shouldPass && error) {
      const errorMessages = error.details.map(detail => detail.message);
      const hasExpectedErrors = expectedErrors.length === 0 || 
        expectedErrors.some(expected => errorMessages.some(msg => msg.includes(expected)));
      
      if (hasExpectedErrors) {
        await saveTestResult('Joi Validation', `${schemaName} - Invalid Data`, 'PASS', duration);
        console.log(`✅ ${schemaName} - Invalid data correctly rejected`);
        return true;
      } else {
        await saveTestResult('Joi Validation', `${schemaName} - Invalid Data`, 'FAIL', duration, 
          `Expected errors: ${expectedErrors.join(', ')}. Got: ${errorMessages.join(', ')}`);
        console.log(`❌ ${schemaName} - Invalid data validation failed`);
        return false;
      }
    } else {
      const status = shouldPass ? 'FAIL' : 'PASS';
      const message = shouldPass ? 'Validation should have passed' : 'Validation should have failed';
      await saveTestResult('Joi Validation', `${schemaName} - ${message}`, status, duration, 
        shouldPass ? 'Validation failed unexpectedly' : 'Validation passed unexpectedly');
      console.log(`❌ ${schemaName} - ${message}`);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    await saveTestResult('Joi Validation', `${schemaName} - Error`, 'FAIL', duration, error.message);
    console.log(`❌ ${schemaName} - Test error: ${error.message}`);
    return false;
  }
};

// Test API endpoints with validation
const testAPIValidation = async (endpoint, testData, shouldPass = true, expectedErrors = []) => {
  const startTime = Date.now();
  try {
    const response = await axios.post(`${BASE_URL}${endpoint}`, testData);
    const duration = Date.now() - startTime;

    if (shouldPass && response.status === 200) {
      await saveTestResult('API Validation', `${endpoint} - Valid Data`, 'PASS', duration);
      console.log(`✅ ${endpoint} - Valid data passed`);
      return true;
    } else if (!shouldPass && response.status === 400) {
      const errorMessages = response.data.errors || [];
      const hasExpectedErrors = expectedErrors.length === 0 || 
        expectedErrors.some(expected => errorMessages.some(msg => msg.includes(expected)));
      
      if (hasExpectedErrors) {
        await saveTestResult('API Validation', `${endpoint} - Invalid Data`, 'PASS', duration);
        console.log(`✅ ${endpoint} - Invalid data correctly rejected`);
        return true;
      } else {
        await saveTestResult('API Validation', `${endpoint} - Invalid Data`, 'FAIL', duration,
          `Expected errors: ${expectedErrors.join(', ')}. Got: ${errorMessages.join(', ')}`);
        console.log(`❌ ${endpoint} - Invalid data validation failed`);
        return false;
      }
    } else {
      const status = shouldPass ? 'FAIL' : 'PASS';
      const message = shouldPass ? 'API should have accepted data' : 'API should have rejected data';
      await saveTestResult('API Validation', `${endpoint} - ${message}`, status, duration,
        `Status: ${response.status}, Data: ${JSON.stringify(response.data)}`);
      console.log(`❌ ${endpoint} - ${message}`);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    if (!shouldPass && error.response?.status === 400) {
      const errorMessages = error.response.data.errors || [];
      const hasExpectedErrors = expectedErrors.length === 0 || 
        expectedErrors.some(expected => errorMessages.some(msg => msg.includes(expected)));
      
      if (hasExpectedErrors) {
        await saveTestResult('API Validation', `${endpoint} - Invalid Data`, 'PASS', duration);
        console.log(`✅ ${endpoint} - Invalid data correctly rejected`);
        return true;
      }
    }
    
    await saveTestResult('API Validation', `${endpoint} - Error`, 'FAIL', duration, error.message);
    console.log(`❌ ${endpoint} - Test error: ${error.message}`);
    return false;
  }
};

// Schema validation tests
const runSchemaTests = async () => {
  console.log('\n🧪 Testing Joi Schema Validation...\n');

  const results = [];

  // Register schema tests
  results.push(await testSchemaValidation('register', {
    name: 'John Doe',
    email: 'john@example.com',
    password: 'Password123'
  }, true));

  results.push(await testSchemaValidation('register', {
    name: 'J',
    email: 'invalid-email',
    password: 'weak'
  }, false, ['at least 2 characters', 'valid email', 'at least 6 characters']));

  // Login schema tests
  results.push(await testSchemaValidation('login', {
    email: 'john@example.com',
    password: 'Password123'
  }, true));

  results.push(await testSchemaValidation('login', {
    email: 'invalid-email',
    password: ''
  }, false, ['valid email', 'Password is required']));

  // Conversion schema tests
  results.push(await testSchemaValidation('conversion', {
    conversionType: 'temperature',
    fromUnit: 'Celsius',
    toUnit: 'Fahrenheit',
    fromValue: 25
  }, true));

  results.push(await testSchemaValidation('conversion', {
    conversionType: 'invalid',
    fromUnit: '',
    toUnit: '',
    fromValue: -5
  }, false, ['one of: length, weight, temperature', 'From unit is required', 'positive']));

  // Bug report schema tests
  results.push(await testSchemaValidation('bugReport', {
    type: 'bug',
    message: 'This is a valid bug report with enough characters to pass validation'
  }, true));

  results.push(await testSchemaValidation('bugReport', {
    type: 'invalid',
    message: 'Short'
  }, false, ['either "bug" or "feature"', 'at least 10 characters']));

  // Rating schema tests
  results.push(await testSchemaValidation('rating', {
    tool: 'Temperature Converter',
    rating: 5,
    comment: 'Great tool!'
  }, true));

  results.push(await testSchemaValidation('rating', {
    tool: '',
    rating: 6,
    comment: 'A'.repeat(501)
  }, false, ['Tool name is required', 'cannot exceed 5', 'cannot exceed 500 characters']));

  // OTP schema tests
  results.push(await testSchemaValidation('sendOtp', {
    email: 'test@example.com'
  }, true));

  results.push(await testSchemaValidation('verifyOtp', {
    email: 'test@example.com',
    otp: '123456'
  }, true));

  results.push(await testSchemaValidation('verifyOtp', {
    email: 'invalid-email',
    otp: '12345'
  }, false, ['valid email', 'exactly 6 digits']));

  // Password reset schema tests
  results.push(await testSchemaValidation('resetPassword', {
    token: 'valid-token',
    password: 'NewPassword123'
  }, true));

  results.push(await testSchemaValidation('resetPassword', {
    token: '',
    password: 'weak'
  }, false, ['Reset token is required', 'at least 6 characters', 'uppercase letter']));

  return results;
};

// API validation tests
const runAPITests = async () => {
  console.log('\n🌐 Testing API Endpoint Validation...\n');

  const results = [];

  // Test conversion API validation
  results.push(await testAPIValidation('/api/convert', {
    conversionType: 'temperature',
    fromUnit: 'Celsius',
    toUnit: 'Fahrenheit',
    fromValue: 25
  }, false, ['Authorization token missing'])); // Should fail without auth

  results.push(await testAPIValidation('/api/convert', {
    conversionType: 'invalid',
    fromUnit: '',
    toUnit: '',
    fromValue: -5
  }, false, ['one of: length, weight, temperature', 'From unit is required', 'positive']));

  // Test bug report API validation
  results.push(await testAPIValidation('/api/reports/public', {
    name: 'Test User',
    email: 'test@example.com',
    type: 'bug',
    message: 'This is a valid bug report with enough characters to pass validation',
    browser: 'Chrome',
    device: 'Desktop'
  }, true));

  results.push(await testAPIValidation('/api/reports/public', {
    name: '',
    email: 'invalid-email',
    type: 'invalid',
    message: 'Short',
    browser: 'Chrome',
    device: 'Desktop'
  }, false, ['Name, email, type, and message are required', 'valid email', 'either "bug" or "feature"', 'at least 10 characters']));

  // Test contact API validation
  results.push(await testAPIValidation('/api/contact/public', {
    name: 'Test User',
    email: 'test@example.com',
    message: 'This is a valid contact message'
  }, true));

  results.push(await testAPIValidation('/api/contact/public', {
    name: '',
    email: 'invalid-email',
    message: ''
  }, false, ['Name, email, and message are required', 'valid email']));

  return results;
};

// Main test runner
const runValidationTests = async () => {
  console.log('🚀 Starting Joi Validation Test Suite...\n');

  try {
    // Initialize test database
    await testDb.sync({ force: false });
    console.log('✅ Test database synchronized');

    // Run schema tests
    const schemaResults = await runSchemaTests();
    
    // Run API tests
    const apiResults = await runAPITests();

    // Combine results
    const allResults = [...schemaResults, ...apiResults];
    const passedTests = allResults.filter(Boolean).length;
    const totalTests = allResults.length;

    console.log('\n📊 Validation Test Results:');
    console.log('===========================');
    console.log(`✅ Passed: ${passedTests}`);
    console.log(`❌ Failed: ${totalTests - passedTests}`);
    console.log(`📈 Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`);

    if (passedTests === totalTests) {
      console.log('\n🎉 All validation tests passed! Your Joi schemas are working perfectly.');
    } else {
      console.log('\n⚠️ Some validation tests failed. Check the errors above.');
    }

    // Show recent test results from database
    try {
      const testResults = await TestResult.findAll({
        where: {
          testSuite: ['Joi Validation', 'API Validation']
        },
        order: [['timestamp', 'DESC']],
        limit: 10
      });

      console.log('\n📋 Recent Validation Test Results:');
      console.log('==================================');
      testResults.forEach(result => {
        console.log(`${result.status === 'PASS' ? '✅' : '❌'} ${result.testName} (${result.duration}ms)`);
      });
    } catch (error) {
      console.log('Could not retrieve validation test results from database');
    }

  } catch (error) {
    console.error('❌ Validation test suite failed:', error.message);
  } finally {
    await testDb.close();
  }
};

// Run tests if this file is executed directly
if (require.main === module) {
  runValidationTests().catch(console.error);
}

module.exports = {
  runValidationTests,
  testSchemaValidation,
  testAPIValidation
}; 