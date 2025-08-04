const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const ConversionHistory = sequelize.define('ConversionHistory', {
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
    allowNull: false
  },
  userId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  fromValue: DataTypes.FLOAT,
  toValue: DataTypes.FLOAT,
  fromUnit: DataTypes.STRING,
  toUnit: DataTypes.STRING,
  conversionType: DataTypes.STRING,
  timestamp: {
    type: DataTypes.DATE,
    allowNull: false
  }
}, {
  updatedAt: false
});

module.exports = ConversionHistory; 