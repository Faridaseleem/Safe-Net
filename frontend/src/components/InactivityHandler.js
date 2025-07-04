import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';

const INACTIVITY_LIMIT = 0.2 * 60 * 1000; // 30 minutes
// For testing, you can change this value (e.g., 0.25 * 60 * 1000 for 15 seconds)

const InactivityHandler = () => {
  const { user, logout } = useUser();
  const navigate = useNavigate();
  const timerRef = useRef();

  useEffect(() => {
    if (!user) return; // Only set timer if user is logged in

    const handleInactivity = () => {
      logout();
      navigate('/login', { state: { sessionExpired: true } });
    };

    const resetInactivityTimer = () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(handleInactivity, INACTIVITY_LIMIT);
    };

    // List of events that indicate user activity
    const events = ['mousemove', 'keydown', 'mousedown', 'touchstart'];
    events.forEach(event => window.addEventListener(event, resetInactivityTimer));
    resetInactivityTimer();

    return () => {
      events.forEach(event => window.removeEventListener(event, resetInactivityTimer));
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [user, logout, navigate]);

  return null; // This component does not render anything
};

export default InactivityHandler; 