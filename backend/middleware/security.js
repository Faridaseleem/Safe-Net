const securityMiddleware = (req, res, next) => {
  const timestamp = new Date().toISOString();
  const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
  const userAgent = req.headers['user-agent'];
  const method = req.method;
  const path = req.path;
  const userId = req.session?.user?.id || 'anonymous';

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
      
      // You could also send alerts here
      break;
    }
  }

  // Rate limiting check (simple implementation)
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