const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Otp = sequelize.define('Otp', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false
  },
  otp: {
    type: DataTypes.STRING,
    allowNull: false
  },
  expires: {
    type: DataTypes.DATE,
    allowNull: false
  },
  purpose: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  updatedAt: false
});

module.exports = Otp; 