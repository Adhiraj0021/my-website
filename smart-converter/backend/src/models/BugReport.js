const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const BugReport = sequelize.define('BugReport', {
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
    allowNull: false
  },
  userId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  type: {
    type: DataTypes.STRING,
    allowNull: false
  },
  message: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  // status: {
  //   type: DataTypes.ENUM('pending', 'in_progress', 'resolved', 'closed'),
  //   defaultValue: 'pending'
  // },
  // reply: {
  //   type: DataTypes.TEXT,
  //   allowNull: true
  // },
  // repliedAt: {
  //   type: DataTypes.DATE,
  //   allowNull: true
  // },
  // repliedBy: {
  //   type: DataTypes.STRING,
  //   allowNull: true
  // },
  timestamp: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  }
}, {
  timestamps: true,
  createdAt: true,
  updatedAt: false
});

module.exports = BugReport; 