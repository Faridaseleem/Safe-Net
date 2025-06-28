const express = require('express');
const router = express.Router();

// Log access attempts
router.post('/access', async (req, res) => {
  try {
    const { userId, userRole, path, timestamp, userAgent } = req.body;
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];

    console.log('🔍 ACCESS LOG:', {
      timestamp: new Date(timestamp).toLocaleString(),
      userId,
      userRole,
      path,
      ip,
      userAgent: userAgent?.substring(0, 100) // Truncate for readability
    });

    // Here you could save to database if needed
    // const accessLog = new AccessLog({ userId, userRole, path, timestamp, ip, userAgent });
    // await accessLog.save();

    res.status(200).json({ message: 'Access logged successfully' });
  } catch (error) {
    console.error('Error logging access:', error);
    res.status(500).json({ message: 'Failed to log access' });
  }
});

// Log suspicious activity
router.post('/suspicious-activity', async (req, res) => {
  try {
    const { activity, details, timestamp, userAgent, path, userId } = req.body;
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];

    console.log('🚨 SUSPICIOUS ACTIVITY DETECTED:', {
      timestamp: new Date(timestamp).toLocaleString(),
      activity,
      details,
      userId,
      path,
      ip,
      userAgent: userAgent?.substring(0, 100)
    });

    // Log with more prominent formatting for security events
    console.log('='.repeat(80));
    console.log('🚨 SECURITY ALERT 🚨');
    console.log('Activity:', activity);
    console.log('Details:', JSON.stringify(details, null, 2));
    console.log('User ID:', userId);
    console.log('Path:', path);
    console.log('IP:', ip);
    console.log('User Agent:', userAgent);
    console.log('='.repeat(80));

    // Here you could:
    // 1. Save to database
    // 2. Send email alert to admin
    // 3. Trigger security measures
    // 4. Rate limit the IP if needed

    res.status(200).json({ message: 'Suspicious activity logged successfully' });
  } catch (error) {
    console.error('Error logging suspicious activity:', error);
    res.status(500).json({ message: 'Failed to log suspicious activity' });
  }
});

module.exports = router; 