const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const TestResult = sequelize.define('TestResult', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  testSuite: {
    type: DataTypes.STRING,
    allowNull: false,
    comment: 'Name of the test suite (e.g., "Database Tests", "API Tests")'
  },
  testName: {
    type: DataTypes.STRING,
    allowNull: false,
    comment: 'Name of the individual test'
  },
  status: {
    type: DataTypes.ENUM('PASS', 'FAIL', 'SKIP', 'PENDING'),
    allowNull: false,
    defaultValue: 'PENDING'
  },
  duration: {
    type: DataTypes.FLOAT,
    allowNull: true,
    comment: 'Test execution time in milliseconds'
  },
  errorMessage: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Error message if test failed'
  },
  errorStack: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Full error stack trace if test failed'
  },
  testData: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Additional test data or context'
  },
  environment: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'test',
    comment: 'Environment where test was run (test, staging, production)'
  },
  timestamp: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  },
  nodeVersion: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Node.js version used for testing'
  },
  osInfo: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Operating system information'
  }
}, {
  timestamps: true,
  indexes: [
    {
      fields: ['testSuite', 'testName']
    },
    {
      fields: ['status']
    },
    {
      fields: ['timestamp']
    },
    {
      fields: ['environment']
    }
  ]
});

module.exports = TestResult; 