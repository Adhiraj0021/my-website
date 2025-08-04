#!/usr/bin/env node

const { schemas } = require('./src/middleware/validation.js');

console.log('🧪 Manual Joi Validation Testing');
console.log('================================\n');

// Function to test a specific schema
const testSchema = (schemaName, testData, description) => {
  console.log(`\n🔍 Testing: ${description}`);
  console.log(`📝 Schema: ${schemaName}`);
  console.log(`📊 Data:`, JSON.stringify(testData, null, 2));
  
  try {
    const schema = schemas[schemaName];
    const { error, value } = schema.validate(testData, {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      console.log('❌ Validation FAILED');
      console.log('🚨 Errors:');
      error.details.forEach((detail, index) => {
        console.log(`   ${index + 1}. ${detail.message}`);
      });
    } else {
      console.log('✅ Validation PASSED');
      console.log('✨ Validated data:', JSON.stringify(value, null, 2));
    }
  } catch (err) {
    console.log('💥 Test ERROR:', err.message);
  }
  
  console.log('─'.repeat(50));
};

// Test scenarios
console.log('🚀 Starting manual validation tests...\n');

// Test 1: Valid user registration
testSchema('register', {
  name: 'John Doe',
  email: 'john@example.com',
  password: 'Password123'
}, 'Valid User Registration');

// Test 2: Invalid user registration (short name)
testSchema('register', {
  name: 'J',
  email: 'john@example.com',
  password: 'Password123'
}, 'Invalid User Registration - Short Name');

// Test 3: Invalid user registration (weak password)
testSchema('register', {
  name: 'John Doe',
  email: 'john@example.com',
  password: 'weak'
}, 'Invalid User Registration - Weak Password');

// Test 4: Valid conversion
testSchema('conversion', {
  conversionType: 'temperature',
  fromUnit: 'Celsius',
  toUnit: 'Fahrenheit',
  fromValue: 25
}, 'Valid Conversion');

// Test 5: Invalid conversion (negative value)
testSchema('conversion', {
  conversionType: 'temperature',
  fromUnit: 'Celsius',
  toUnit: 'Fahrenheit',
  fromValue: -5
}, 'Invalid Conversion - Negative Value');

// Test 6: Valid bug report
testSchema('bugReport', {
  type: 'bug',
  message: 'This is a valid bug report with enough characters to pass validation'
}, 'Valid Bug Report');

// Test 7: Invalid bug report (short message)
testSchema('bugReport', {
  type: 'bug',
  message: 'Short'
}, 'Invalid Bug Report - Short Message');

// Test 8: Valid rating
testSchema('rating', {
  tool: 'Temperature Converter',
  rating: 5,
  comment: 'Great tool!'
}, 'Valid Rating');

// Test 9: Invalid rating (out of range)
testSchema('rating', {
  tool: 'Temperature Converter',
  rating: 6,
  comment: 'Great tool!'
}, 'Invalid Rating - Out of Range');

// Test 10: Valid OTP verification
testSchema('verifyOtp', {
  email: 'test@example.com',
  otp: '123456'
}, 'Valid OTP Verification');

// Test 11: Invalid OTP verification (wrong length)
testSchema('verifyOtp', {
  email: 'test@example.com',
  otp: '12345'
}, 'Invalid OTP Verification - Wrong Length');

// Test 12: Valid password reset
testSchema('resetPassword', {
  token: 'valid-token',
  password: 'NewPassword123'
}, 'Valid Password Reset');

// Test 13: Invalid password reset (weak password)
testSchema('resetPassword', {
  token: 'valid-token',
  password: 'weak'
}, 'Invalid Password Reset - Weak Password');

console.log('\n🎯 Manual validation testing completed!');
console.log('\n💡 Tips:');
console.log('   • Use this script to test specific validation scenarios');
console.log('   • Modify the test data to test edge cases');
console.log('   • Add new test cases by calling testSchema()');
console.log('   • Check the error messages to understand validation rules'); 