# Safe-Net Access Control System

## Overview
This document describes the comprehensive access control system implemented in Safe-Net to secure all pages and log suspicious activities.

## Features

### 🔒 Authentication & Authorization
- **Protected Routes**: All pages except public ones require authentication
- **Role-Based Access**: Different access levels for standard, premium, and admin users
- **Session Management**: Secure session handling with MongoDB storage
- **Automatic Redirects**: Unauthenticated users are redirected to login

### 📊 Activity Logging
- **Access Logging**: All page accesses are logged with user details
- **Suspicious Activity Detection**: Automatic detection and logging of suspicious patterns
- **Security Alerts**: Prominent console logging for security events
- **Rate Limiting**: Basic rate limiting to prevent abuse

### 🛡️ Security Features
- **XSS Protection**: Detection of script injection attempts
- **SQL Injection Protection**: Detection of SQL injection patterns
- **Directory Traversal Protection**: Detection of path traversal attempts
- **Rate Limiting**: Request rate monitoring and alerting

## Access Control Matrix

| Page | Authentication Required | Allowed Roles | Notes |
|------|------------------------|---------------|-------|
| `/` (Root) | ❌ | All | Landing page |
| `/signup` | ❌ | All | Registration |
| `/select-plan` | ❌ | All | Plan selection |
| `/verify` | ❌ | All | Email verification |
| `/login` | ❌ | All | Login page |
| `/home` | ✅ | standard, premium, admin | Dashboard |
| `/scan-url` | ✅ | standard, premium, admin | URL scanning |
| `/scan-email` | ✅ | standard, premium, admin | Email scanning |
| `/education` | ✅ | standard, premium, admin | Educational content |
| `/change-plan` | ✅ | standard, premium, admin | Plan management |
| `/report-url` | ✅ | standard, premium, admin | URL reporting |
| `/admin/reports` | ✅ | admin | Admin panel |

## Logging System

### Access Logs
- User ID and role
- Accessed path
- Timestamp
- IP address
- User agent

### Suspicious Activity Logs
- Activity type (UNAUTHORIZED_ACCESS_ATTEMPT, UNAUTHORIZED_ROLE_ACCESS)
- Detailed context
- User information
- IP address
- Timestamp

### Security Alerts
- Pattern-based detection
- Rate limit violations
- Suspicious request patterns

## Implementation Details

### Frontend Components
- `ProtectedRoute.js`: Main access control component
- `UserContext.js`: Authentication state management
- `App.js`: Route protection implementation

### Backend Components
- `logRoutes.js`: Logging endpoints
- `security.js`: Security middleware
- `auth.js`: Authentication routes

### Security Patterns Detected
- Directory traversal (`../`)
- XSS attempts (`<script`)
- SQL injection (`union select`)
- Code injection (`eval(`)
- Cookie theft attempts (`document.cookie`)

## Usage

### For Developers
1. Wrap protected components with `ProtectedRoute`
2. Specify required roles using `allowedRoles` prop
3. Set `requireAuth={false}` for public routes
4. Use `logAccess={false}` to disable access logging for specific routes

### For Administrators
- Monitor console logs for security alerts
- Check access logs for user activity
- Review suspicious activity reports
- Monitor rate limiting violations

## Security Best Practices
1. Always use HTTPS in production
2. Regularly review access logs
3. Monitor for suspicious patterns
4. Keep session timeouts reasonable
5. Implement proper password policies
6. Regular security audits

## Troubleshooting

### Common Issues
1. **Infinite redirects**: Check UserContext loading state
2. **Session issues**: Verify MongoDB connection
3. **CORS errors**: Ensure proper CORS configuration
4. **Logging failures**: Check network connectivity

### Debug Mode
Enable detailed logging by checking console output for:
- 🔍 Access logs
- 🚨 Security alerts
- ✅ Successful operations
- ❌ Error messages 