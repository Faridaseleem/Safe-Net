const mongoose = require('mongoose');

const SuspiciousLogSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  activity: { type: String, required: true },
  details: { type: Object },
  userId: { type: String },
  path: { type: String },
  ip: { type: String },
  userAgent: { type: String }
});

module.exports = mongoose.model('SuspiciousLog', SuspiciousLogSchema);
