const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const ReportReply = sequelize.define('ReportReply', {
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
    allowNull: false
  },
  reportId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  userId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  reply: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  status: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'resolved'
  },
  repliedBy: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'admin'
  },
  repliedAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  },
  autoMessageSent: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false
  },
  autoMessageContent: {
    type: DataTypes.TEXT,
    allowNull: true
  }
}, {
  tableName: 'report_replies',
  timestamps: false
});

module.exports = ReportReply; 