const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
    allowNull: false
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  },
  createdAt: {
    type: DataTypes.DATE,
    allowNull: false
  },
  isConfirmed: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  // isAdmin: {
  //   type: DataTypes.BOOLEAN,
  //   defaultValue: false
  // },
  passwordResetPending: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  phone: DataTypes.STRING,
  address: DataTypes.STRING,
  avatar: DataTypes.STRING
}, {
  timestamps: true,
  createdAt: true,
  updatedAt: false
});

module.exports = User; 