/**
 * NoSQL Injection Protection Middleware
 * 
 * This middleware protects against various NoSQL injection attacks including:
 * - Object injection attacks (e.g., {"$gt": ""})
 * - Array injection attacks (e.g., {"$in": []})
 * - Operator injection attacks (e.g., {"$ne": null})
 * - JavaScript injection in queries
 * - MongoDB operator injection
 * - Type confusion attacks
 */

const nosqlInjectionProtection = (req, res, next) => {
  // SECURITY MEASURE 1: Sanitize request body
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeObject(req.body);
  }

  // SECURITY MEASURE 2: Sanitize query parameters
  if (req.query && typeof req.query === 'object') {
    req.query = sanitizeObject(req.query);
  }

  // SECURITY MEASURE 3: Sanitize URL parameters
  if (req.params && typeof req.params === 'object') {
    req.params = sanitizeObject(req.params);
  }

  // SECURITY MEASURE 4: Log suspicious patterns for monitoring
  const suspiciousPatterns = detectSuspiciousPatterns(req);
  if (suspiciousPatterns.length > 0) {
    logSuspiciousActivity(req, suspiciousPatterns);
  }

  next();
};

/*
 * SECURITY FUNCTION: Sanitize objects to prevent NoSQL injection
 */
function sanitizeObject(obj) {
  if (obj === null || obj === undefined) {
    return obj;
  }

  // SECURITY CHECK: If it's a string, sanitize it
  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }

  // SECURITY CHECK: If it's an array, sanitize each element
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }

  // SECURITY CHECK: If it's an object, sanitize each property
  if (typeof obj === 'object') {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(obj)) {
      // SECURITY MEASURE: Block MongoDB operators in keys
      if (isMongoOperator(key)) {
        console.log('🚨 BLOCKED: MongoDB operator in key:', key);
        continue;
      }

      // SECURITY MEASURE: Block MongoDB operators in values
      if (typeof value === 'object' && value !== null && isMongoOperatorObject(value)) {
        console.log('🚨 BLOCKED: MongoDB operator object:', value);
        continue; 
      }

      // SECURITY MEASURE: Recursively sanitize nested objects
      sanitized[key] = sanitizeObject(value);
    }

    return sanitized;
  }

  return obj;
}

/**
 * SECURITY FUNCTION: Sanitize strings to prevent injection
 */
function sanitizeString(str) {
  if (typeof str !== 'string') {
    return str;
  }

  // SECURITY MEASURE: Remove null bytes
  str = str.replace(/\0/g, '');

  // SECURITY MEASURE: Remove MongoDB operators from strings
  const mongoOperators = [
    '$where', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
    '$exists', '$type', '$mod', '$regex', '$text', '$search',
    '$elemMatch', '$size', '$all', '$not', '$or', '$and', '$nor'
  ];

  for (const operator of mongoOperators) {
    // SECURITY CHECK: Block strings that start with MongoDB operators
    if (str.toLowerCase().startsWith(operator.toLowerCase())) {
      console.log('🚨 BLOCKED: String starting with MongoDB operator:', str);
      return ''; // Return empty string to prevent injection
    }
  }

  // SECURITY MEASURE: Block JavaScript code patterns
  const jsPatterns = [
    /javascript:/i,
    /data:text\/html/i,
    /vbscript:/i,
    /on\w+\s*=/i, // Event handlers
    /<script/i,
    /eval\s*\(/i,
    /function\s*\(/i
  ];

  for (const pattern of jsPatterns) {
    if (pattern.test(str)) {
      console.log('🚨 BLOCKED: JavaScript pattern detected:', str);
      return ''; // Return empty string to prevent injection
    }
  }

  // SECURITY MEASURE: Limit string length to prevent DoS
  if (str.length > 10000) {
    console.log('🚨 BLOCKED: String too long:', str.length);
    return str.substring(0, 10000);
  }

  return str;
}

/**
 * SECURITY FUNCTION: Check if a key is a MongoDB operator
 */
function isMongoOperator(key) {
  if (typeof key !== 'string') {
    return false;
  }

  // SECURITY CHECK: Block all MongoDB operators
  const mongoOperators = [
    '$where', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
    '$exists', '$type', '$mod', '$regex', '$text', '$search',
    '$elemMatch', '$size', '$all', '$not', '$or', '$and', '$nor',
    '$set', '$unset', '$inc', '$push', '$pull', '$addToSet',
    '$pop', '$rename', '$currentDate', '$mul', '$min', '$max'
  ];

  return mongoOperators.includes(key);
}

/**
 * SECURITY FUNCTION: Check if an object contains MongoDB operators
 * Detects objects that might be used for NoSQL injection
 */
function isMongoOperatorObject(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return false;
  }

  // SECURITY CHECK: Check if any key is a MongoDB operator
  for (const key of Object.keys(obj)) {
    if (isMongoOperator(key)) {
      return true;
    }
  }

  // SECURITY CHECK: Recursively check nested objects
  for (const value of Object.values(obj)) {
    if (typeof value === 'object' && value !== null) {
      if (isMongoOperatorObject(value)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * SECURITY FUNCTION: Detect suspicious patterns in requests
 */
function detectSuspiciousPatterns(req) {
  const suspiciousPatterns = [];

  // SECURITY CHECK: Look for MongoDB operators in request
  const requestString = JSON.stringify(req.body) + JSON.stringify(req.query) + JSON.stringify(req.params);
  
  const mongoPatterns = [
    /\$where/i,
    /\$ne/i,
    /\$gt/i,
    /\$gte/i,
    /\$lt/i,
    /\$lte/i,
    /\$in/i,
    /\$nin/i,
    /\$exists/i,
    /\$type/i,
    /\$mod/i,
    /\$regex/i,
    /\$text/i,
    /\$search/i,
    /\$elemMatch/i,
    /\$size/i,
    /\$all/i,
    /\$not/i,
    /\$or/i,
    /\$and/i,
    /\$nor/i
  ];

  for (const pattern of mongoPatterns) {
    if (pattern.test(requestString)) {
      suspiciousPatterns.push(`MongoDB operator detected: ${pattern.source}`);
    }
  }

  // SECURITY CHECK: Look for JavaScript injection patterns
  const jsPatterns = [
    /javascript:/i,
    /data:text\/html/i,
    /vbscript:/i,
    /on\w+\s*=/i,
    /<script/i,
    /eval\s*\(/i,
    /function\s*\(/i
  ];

  for (const pattern of jsPatterns) {
    if (pattern.test(requestString)) {
      suspiciousPatterns.push(`JavaScript injection pattern: ${pattern.source}`);
    }
  }

  // SECURITY CHECK: Look for type confusion attempts
  const typeConfusionPatterns = [
    /"0":\s*"1"/, // Array-like objects
    /"__proto__"/, // Prototype pollution
    /"constructor"/, // Constructor access
    /"prototype"/ // Prototype access
  ];

  for (const pattern of typeConfusionPatterns) {
    if (pattern.test(requestString)) {
      suspiciousPatterns.push(`Type confusion attempt: ${pattern.source}`);
    }
  }

  return suspiciousPatterns;
}

/**
 * SECURITY FUNCTION: Log suspicious activity for monitoring
 */
function logSuspiciousActivity(req, patterns) {
  const timestamp = new Date().toISOString();
  const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
  const userAgent = req.headers['user-agent'];
  const userId = req.session?.user?.id || 'anonymous';

  console.log('🚨 NOSQL INJECTION ATTEMPT DETECTED:');
  console.log('='.repeat(80));
  console.log('Timestamp:', timestamp);
  console.log('IP Address:', ip);
  console.log('User ID:', userId);
  console.log('User Agent:', userAgent);
  console.log('Method:', req.method);
  console.log('Path:', req.path);
  console.log('Suspicious Patterns:', patterns);
  console.log('Request Body:', JSON.stringify(req.body, null, 2));
  console.log('Request Query:', JSON.stringify(req.query, null, 2));
  console.log('Request Params:', JSON.stringify(req.params, null, 2));
  console.log('='.repeat(80));

  // SECURITY MEASURE: You could also send alerts here
  
}

module.exports = nosqlInjectionProtection; 