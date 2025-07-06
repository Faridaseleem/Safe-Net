const securityMiddleware = async (req, res, next) => {
  const timestamp = new Date().toISOString();
  const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
  const userAgent = req.headers['user-agent'];
  const method = req.method;
  const path = req.path;
  const userId = req.session?.user?.id || 'anonymous';
  const SuspiciousLog = require("../models/SuspiciousLog");


  // Log all requests
  console.log(`🔍 ${timestamp} - ${method} ${path} - IP: ${ip} - User: ${userId}`);

  // Detect suspicious patterns
  const suspiciousPatterns = [
    /\.\./, // Directory traversal
    /<script/i, // XSS attempts
    /union.*select/i, // SQL injection
    /eval\(/i, // Code injection
    /document\.cookie/i, // Cookie theft attempts
  ];

  const requestString = JSON.stringify(req.body) + JSON.stringify(req.query) + req.path;
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(requestString)) {
      console.log('🚨 SUSPICIOUS ACTIVITY DETECTED:');
      console.log('Pattern:', pattern);
      console.log('Request:', {
        method,
        path,
        ip,
        userId,
        userAgent,
        body: req.body,
        query: req.query
      });
      console.log('='.repeat(80));

      try {
        await SuspiciousLog.create({
          timestamp,
          activity: "SUSPICIOUS_PATTERN_DETECTED",
          details: {
            pattern: pattern.toString(),
            body: req.body,
            query: req.query,
            reason: "Blocked pattern detected in request"
          },
          userId,
          path,
          ip,
          userAgent
        });
      } catch (err) {
        console.error("❌ Failed to log suspicious pattern:", err);
      }

      break;
    }
}


  // Rate limiting check
  const key = `${ip}-${path}`;
  if (!req.app.locals.rateLimit) {
    req.app.locals.rateLimit = {};
  }
  
  if (!req.app.locals.rateLimit[key]) {
    req.app.locals.rateLimit[key] = { count: 0, resetTime: Date.now() + 60000 }; // 1 minute window
  }

  // Reset counter if window expired
  if (Date.now() > req.app.locals.rateLimit[key].resetTime) {
    req.app.locals.rateLimit[key] = { count: 0, resetTime: Date.now() + 60000 };
  }

  req.app.locals.rateLimit[key].count++;

  // Log if rate limit exceeded
  if (req.app.locals.rateLimit[key].count > 100) { // 100 requests per minute
    console.log('🚨 RATE LIMIT EXCEEDED:', {
      ip,
      path,
      count: req.app.locals.rateLimit[key].count,
      userId
    });
  }

  next();
};

module.exports = securityMiddleware; 