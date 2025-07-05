const express = require('express');
const router = express.Router();
const AccessLog = require('../models/AccessLog');
const SuspiciousLog = require('../models/SuspiciousLog');

router.post('/access', async (req, res) => {
  try {
    const { userId, userRole, path, timestamp, userAgent } = req.body;
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];

    console.log("🟢 /access called with:", {
      userId,
      userRole,
      path,
      timestamp,
      ip,
      userAgent
    });

    await AccessLog.create({
      timestamp,
      userId,
      userRole,
      path,
      ip,
      userAgent
    });

    console.log("✅ Log inserted successfully");

    res.status(200).json({ message: 'Access logged successfully' });
  } catch (error) {
    console.error('❌ Error logging access:', error);
    res.status(500).json({ message: 'Failed to log access' });
  }
});


router.post('/suspicious-activity', async (req, res) => {
  try {
    const { activity, details, timestamp, userAgent, path, userId } = req.body;
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];

    await SuspiciousLog.create({
      timestamp,
      activity,
      details,
      userId,
      path,
      ip,
      userAgent
    });

    res.status(200).json({ message: 'Suspicious activity logged successfully' });
  } catch (error) {
    console.error('Error logging suspicious activity:', error);
    res.status(500).json({ message: 'Failed to log suspicious activity' });
  }
});
// View latest 100 access logs
router.get('/admin/access-logs', async (req, res) => {
  try {
    const logs = await AccessLog.find().sort({ timestamp: -1 }).limit(100);
    res.status(200).json(logs);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch access logs' });
  }
});

// View latest 100 suspicious activity logs
router.get('/admin/suspicious-logs', async (req, res) => {
  try {
    const logs = await SuspiciousLog.find().sort({ timestamp: -1 }).limit(100);
    res.status(200).json(logs);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch suspicious logs' });
  }
});

module.exports = router; 