import React, { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';
import axios from 'axios';

const ProtectedRoute = ({ 
  children, 
  allowedRoles = [], 
  requireAuth = true,
  logAccess = true 
}) => {
  const { user, loading } = useUser();
  const location = useLocation();
  const [isChecking, setIsChecking] = useState(true);

  // Log suspicious activity
  const logSuspiciousActivity = async (activity, details) => {
    try {
      await axios.post('https://localhost:5000/api/log/suspicious-activity', {
        activity,
        details,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        ip: null, // Will be captured by backend
        path: location.pathname,
        userId: user?.id || 'anonymous'
      }, { withCredentials: true });
    } catch (error) {
      console.error('Failed to log suspicious activity:', error);
    }
  };

  useEffect(() => {
    const checkAccess = async () => {
      // If no authentication required, allow access
      if (!requireAuth) {
        setIsChecking(false);
        return;
      }

      // If still loading, wait
      if (loading) {
        return;
      }

      // If not authenticated, redirect to login
      if (!user) {
        await logSuspiciousActivity('UNAUTHORIZED_ACCESS_ATTEMPT', {
          attemptedPath: location.pathname,
          reason: 'User not authenticated'
        });
        setIsChecking(false);
        return;
      }

      // If roles are specified, check if user has required role
      if (allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
        await logSuspiciousActivity('UNAUTHORIZED_ROLE_ACCESS', {
          attemptedPath: location.pathname,
          userRole: user.role,
          requiredRoles: allowedRoles,
          userId: user.id
        });
        setIsChecking(false);
        return;
      }

      // Log successful access if logging is enabled
      if (logAccess) {
        try {
          await axios.post('https://localhost:5000/api/log/access', {
            userId: user.id,
            userRole: user.role,
            path: location.pathname,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent
          }, { withCredentials: true });
        } catch (error) {
          console.error('Failed to log access:', error);
        }
      }

      setIsChecking(false);
    };

    checkAccess();
  }, [user, loading, location.pathname, requireAuth, allowedRoles, logAccess]);

  // Show loading while checking
  if (loading || isChecking) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        backgroundColor: '#121629',
        color: '#F8F8F2'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '2rem', marginBottom: '1rem' }}>🔒</div>
          <div>Checking access...</div>
        </div>
      </div>
    );
  }

  // If not authenticated, redirect to login
  if (requireAuth && !user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // If user doesn't have required role, redirect to home
  if (allowedRoles.length > 0 && user && !allowedRoles.includes(user.role)) {
    return <Navigate to="/home" replace />;
  }

  // Allow access
  return children;
};

export default ProtectedRoute; 