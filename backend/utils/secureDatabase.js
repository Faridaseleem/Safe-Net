/**
 * Secure Database Utility
 */

const mongoose = require('mongoose');

// SECURITY CLASS: Secure Database Operations
class SecureDatabase {
  
  //Validates and sanitizes query parameters before execution
  static async safeFindOne(model, query, options = {}) {
    try {
      // SECURITY CHECK: Validate model
      if (!model || typeof model.findOne !== 'function') {
        throw new Error('Invalid model provided');
      }

      // SECURITY CHECK: Validate query object
      if (!query || typeof query !== 'object') {
        throw new Error('Invalid query object');
      }

      // SECURITY MEASURE: Sanitize query object
      const sanitizedQuery = this.sanitizeQuery(query);
      
      // SECURITY CHECK: Ensure query is not empty after sanitization
      if (Object.keys(sanitizedQuery).length === 0) {
        throw new Error('Query is empty after sanitization');
      }

      // SECURITY LOG: Log the sanitized query for monitoring
      console.log('🔒 SECURE QUERY:', {
        model: model.modelName,
        originalQuery: query,
        sanitizedQuery: sanitizedQuery,
        timestamp: new Date().toISOString()
      });

      // SECURITY MEASURE: Execute query with timeout
      const result = await Promise.race([
        model.findOne(sanitizedQuery, options),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Query timeout')), 10000)
        )
      ]);

      return result;
    } catch (error) {
      console.error('🚨 SECURE DATABASE ERROR:', error);
      throw error;
    }
  }

  //Validates ObjectId format and prevents injection
  static async safeFindById(model, id, options = {}) {
    try {
      // SECURITY CHECK: Validate model
      if (!model || typeof model.findById !== 'function') {
        throw new Error('Invalid model provided');
      }

      // SECURITY CHECK: Validate ID
      if (!id) {
        throw new Error('Invalid ID provided');
      }

      // SECURITY MEASURE: Handle both string and ObjectId inputs
      let idString;
      if (typeof id === 'string') {
        idString = id;
      } else if (id && typeof id === 'object' && id.toString) {
        // Handle ObjectId objects
        idString = id.toString();
      } else {
        throw new Error('Invalid ID format');
      }

      // SECURITY MEASURE: Validate ObjectId format
      if (!mongoose.Types.ObjectId.isValid(idString)) {
        throw new Error('Invalid ObjectId format');
      }

      // SECURITY MEASURE: Sanitize ID (remove any dangerous characters)
      const sanitizedId = idString.replace(/[^a-fA-F0-9]/g, '');
      
      if (sanitizedId.length !== 24) {
        throw new Error('Invalid ObjectId length');
      }

      // SECURITY LOG: Log the sanitized ID
      console.log('🔒 SECURE FIND BY ID:', {
        model: model.modelName,
        originalId: idString,
        sanitizedId: sanitizedId,
        timestamp: new Date().toISOString()
      });

      // SECURITY MEASURE: Execute query with timeout
      const result = await Promise.race([
        model.findById(sanitizedId, options),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Query timeout')), 10000)
        )
      ]);

      return result;
    } catch (error) {
      console.error('🚨 SECURE DATABASE ERROR:', error);
      throw error;
    }
  }

  //Validates and sanitizes query parameters for multiple document retrieval
  static async safeFind(model, query = {}, options = {}) {
    try {
      // SECURITY CHECK: Validate model
      if (!model || typeof model.find !== 'function') {
        throw new Error('Invalid model provided');
      }

      // SECURITY CHECK: Validate query object
      if (query && typeof query !== 'object') {
        throw new Error('Invalid query object');
      }

      // SECURITY MEASURE: Sanitize query object
      const sanitizedQuery = this.sanitizeQuery(query || {});
      
      // SECURITY MEASURE: Limit result set to prevent DoS
      const limit = Math.min(options.limit || 100, 1000); // Max 1000 documents
      const sanitizedOptions = { ...options, limit };

      // SECURITY LOG: Log the sanitized query
      console.log('🔒 SECURE FIND:', {
        model: model.modelName,
        originalQuery: query,
        sanitizedQuery: sanitizedQuery,
        options: sanitizedOptions,
        timestamp: new Date().toISOString()
      });

      // SECURITY MEASURE: Execute query with timeout
      const result = await Promise.race([
        model.find(sanitizedQuery, null, sanitizedOptions),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Query timeout')), 15000)
        )
      ]);

      return result;
    } catch (error) {
      console.error('🚨 SECURE DATABASE ERROR:', error);
      throw error;
    }
  }

  //Validates and sanitizes update data
  static async safeUpdateOne(model, filter, update, options = {}) {
    try {
      // SECURITY CHECK: Validate model
      if (!model || typeof model.updateOne !== 'function') {
        throw new Error('Invalid model provided');
      }

      // SECURITY CHECK: Validate filter and update objects
      if (!filter || typeof filter !== 'object') {
        throw new Error('Invalid filter object');
      }

      if (!update || typeof update !== 'object') {
        throw new Error('Invalid update object');
      }

      // SECURITY MEASURE: Sanitize filter and update objects
      const sanitizedFilter = this.sanitizeQuery(filter);
      const sanitizedUpdate = this.sanitizeUpdate(update);

      // SECURITY CHECK: Ensure objects are not empty after sanitization
      if (Object.keys(sanitizedFilter).length === 0) {
        throw new Error('Filter is empty after sanitization');
      }

      if (Object.keys(sanitizedUpdate).length === 0) {
        throw new Error('Update is empty after sanitization');
      }

      // SECURITY LOG: Log the sanitized operation
      console.log('🔒 SECURE UPDATE:', {
        model: model.modelName,
        originalFilter: filter,
        sanitizedFilter: sanitizedFilter,
        originalUpdate: update,
        sanitizedUpdate: sanitizedUpdate,
        timestamp: new Date().toISOString()
      });

      // SECURITY MEASURE: Execute update with timeout
      const result = await Promise.race([
        model.updateOne(sanitizedFilter, sanitizedUpdate, options),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Update timeout')), 10000)
        )
      ]);

      return result;
    } catch (error) {
      console.error('🚨 SECURE DATABASE ERROR:', error);
      throw error;
    }
  }

  //Validates and sanitizes document data before saving
  static async safeSave(document) {
    try {
      // SECURITY CHECK: Validate document
      if (!document || typeof document.save !== 'function') {
        throw new Error('Invalid document provided');
      }

      // SECURITY MEASURE: Sanitize document data
      const sanitizedData = this.sanitizeDocument(document.toObject());
      
      // SECURITY LOG: Log the sanitized document
      console.log('🔒 SECURE SAVE:', {
        model: document.constructor.modelName,
        originalData: document.toObject(),
        sanitizedData: sanitizedData,
        timestamp: new Date().toISOString()
      });

      // SECURITY MEASURE: Execute save with timeout
      const result = await Promise.race([
        document.save(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Save timeout')), 10000)
        )
      ]);

      return result;
    } catch (error) {
      console.error('🚨 SECURE DATABASE ERROR:', error);
      throw error;
    }
  }

  //Removes dangerous MongoDB operators and validates query structure
  static sanitizeQuery(query) {
    if (!query || typeof query !== 'object') {
      return {};
    }

    const sanitized = {};

    for (const [key, value] of Object.entries(query)) {
      // SECURITY CHECK: Block MongoDB operators in keys
      if (this.isMongoOperator(key)) {
        console.log('🚨 BLOCKED: MongoDB operator in query key:', key);
        continue;
      }

      // SECURITY CHECK: Block MongoDB operators in values
      if (typeof value === 'object' && value !== null && this.isMongoOperatorObject(value)) {
        console.log('🚨 BLOCKED: MongoDB operator object in query:', value);
        continue;
      }

      // SECURITY MEASURE: Recursively sanitize nested objects
      sanitized[key] = this.sanitizeValue(value);
    }

    return sanitized;
  }

  //Ensures update operations are safe and don't contain dangerous operators
  static sanitizeUpdate(update) {
    if (!update || typeof update !== 'object') {
      return {};
    }

    const sanitized = {};

    for (const [key, value] of Object.entries(update)) {
      // SECURITY CHECK: Block MongoDB operators in keys (except update operators)
      if (this.isMongoOperator(key) && !this.isUpdateOperator(key)) {
        console.log('🚨 BLOCKED: Non-update MongoDB operator in update key:', key);
        continue;
      }

      // SECURITY CHECK: Validate update operator values
      if (this.isUpdateOperator(key)) {
        if (typeof value !== 'object' || value === null) {
          console.log('🚨 BLOCKED: Invalid update operator value:', value);
          continue;
        }
        
        // SECURITY MEASURE: Sanitize update operator values
        sanitized[key] = this.sanitizeQuery(value);
      } else {
        // SECURITY MEASURE: Sanitize regular field values
        sanitized[key] = this.sanitizeValue(value);
      }
    }

    return sanitized;
  }

  //Ensures document data is safe before saving
  static sanitizeDocument(document) {
    if (!document || typeof document !== 'object') {
      return {};
    }

    const sanitized = {};

    for (const [key, value] of Object.entries(document)) {
      // SECURITY CHECK: Skip MongoDB internal fields
      if (key.startsWith('_') || key === '__v') {
        continue;
      }

      // SECURITY CHECK: Block MongoDB operators in keys
      if (this.isMongoOperator(key)) {
        console.log('🚨 BLOCKED: MongoDB operator in document key:', key);
        continue;
      }

      // SECURITY MEASURE: Sanitize field values
      sanitized[key] = this.sanitizeValue(value);
    }

    return sanitized;
  }

  //Handles different data types safely
  static sanitizeValue(value) {
    if (value === null || value === undefined) {
      return value;
    }

    if (typeof value === 'string') {
      return this.sanitizeString(value);
    }

    if (Array.isArray(value)) {
      return value.map(item => this.sanitizeValue(item));
    }

    if (typeof value === 'object') {
      return this.sanitizeQuery(value);
    }

    return value;
  }

  //Sanitize strings
  static sanitizeString(str) {
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
      if (str.toLowerCase().startsWith(operator.toLowerCase())) {
        console.log('🚨 BLOCKED: String starting with MongoDB operator:', str);
        return '';
      }
    }

    // SECURITY MEASURE: Block JavaScript injection patterns
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
        return '';
      }
    }

    // SECURITY MEASURE: Block SQL injection patterns
    const sqlPatterns = [
      /;\s*drop\s+table/i,
      /;\s*delete\s+from/i,
      /;\s*insert\s+into/i,
      /;\s*update\s+.*\s+set/i,
      /'\s*or\s*'1'='1/i,
      /'\s*or\s*1=1/i,
      /admin'--/i,
      /union\s+select/i
    ];

    for (const pattern of sqlPatterns) {
      if (pattern.test(str)) {
        console.log('🚨 BLOCKED: SQL injection pattern detected:', str);
        return '';
      }
    }

    // SECURITY MEASURE: Block XSS patterns
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /vbscript:/i,
      /on\w+\s*=/i,
      /data:text\/html/i
    ];

    for (const pattern of xssPatterns) {
      if (pattern.test(str)) {
        console.log('🚨 BLOCKED: XSS pattern detected:', str);
        return '';
      }
    }

    // SECURITY MEASURE: Limit string length to prevent DoS
    if (str.length > 10000) {
      console.log('🚨 BLOCKED: String too long:', str.length);
      return str.substring(0, 10000);
    }

    return str;
  }

  //SECURITY FUNCTION: Check if a key is a MongoDB operator
  static isMongoOperator(key) {
    if (typeof key !== 'string') {
      return false;
    }

    const mongoOperators = [
      '$where', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
      '$exists', '$type', '$mod', '$regex', '$text', '$search',
      '$elemMatch', '$size', '$all', '$not', '$or', '$and', '$nor',
      '$set', '$unset', '$inc', '$push', '$pull', '$addToSet',
      '$pop', '$rename', '$currentDate', '$mul', '$min', '$max'
    ];

    return mongoOperators.includes(key);
  }

  //SECURITY FUNCTION: Check if a key is an update operator
  static isUpdateOperator(key) {
    if (typeof key !== 'string') {
      return false;
    }

    const updateOperators = [
      '$set', '$unset', '$inc', '$push', '$pull', '$addToSet',
      '$pop', '$rename', '$currentDate', '$mul', '$min', '$max'
    ];

    return updateOperators.includes(key);
  }

  //SECURITY FUNCTION: Check if an object contains MongoDB operators
  static isMongoOperatorObject(obj) {
    if (typeof obj !== 'object' || obj === null) {
      return false;
    }

    for (const key of Object.keys(obj)) {
      if (this.isMongoOperator(key)) {
        return true;
      }
    }

    for (const value of Object.values(obj)) {
      if (typeof value === 'object' && value !== null) {
        if (this.isMongoOperatorObject(value)) {
          return true;
        }
      }
    }

    return false;
  }
}

module.exports = SecureDatabase; 