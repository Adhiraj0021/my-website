#!/usr/bin/env node

const { runComprehensiveTests } = require('./comprehensive-api.test.js');

console.log('🧪 Smart Converter Comprehensive API Test Suite');
console.log('==============================================\n');

// Check if server is running
const checkServer = async () => {
  const axios = require('axios');
  try {
    await axios.get('http://localhost:5001/api/health');
    return true;
  } catch (error) {
    return false;
  }
};

const main = async () => {
  console.log('🔍 Checking if server is running...');
  const serverRunning = await checkServer();
  
  if (!serverRunning) {
    console.log('❌ Server is not running on http://localhost:5001');
    console.log('💡 Please start the server first:');
    console.log('   cd smart-converter/backend && npm start');
    process.exit(1);
  }
  
  console.log('✅ Server is running, starting comprehensive tests...\n');
  
  try {
    await runComprehensiveTests();
  } catch (error) {
    console.error('❌ Comprehensive test suite failed:', error.message);
    process.exit(1);
  }
};

main(); 