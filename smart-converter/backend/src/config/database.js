const { Sequelize } = require('sequelize');
require('dotenv').config();

const isTestEnvironment = process.env.NODE_ENV === 'test';
console.log(`Running in ${isTestEnvironment ? 'Test' : 'Development'} mode. `);

const sequelize = new Sequelize(
  isTestEnvironment ? process.env.TEST_DB_NAME : process.env.DB_NAME,
  // process.env.DB_NAME || 'smart_converter',
  process.env.DB_USER || 'root',
  process.env.DB_PASS || '12345678',
  {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    dialect: 'mysql',
    logging: false,
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    },
    define: {
      timestamps: false
    }
  }
);

module.exports = sequelize; 