const mongoose = require('mongoose');

const AccessLogSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  userId: { type: String },
  userRole: { type: String },
  path: { type: String },
  ip: { type: String },
  userAgent: { type: String }
});

module.exports = mongoose.model('AccessLog', AccessLogSchema);
