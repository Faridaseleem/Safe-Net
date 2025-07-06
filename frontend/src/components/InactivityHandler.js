import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../contexts/UserContext';

const INACTIVITY_LIMIT = 30 * 60 * 1000; // 30 minutes
const InactivityHandler = () => {
  const { user, logout } = useUser();
  const navigate = useNavigate();
  const timerRef = useRef();

  useEffect(() => {
    if (!user) return; 

    const handleInactivity = () => {
      logout();
      navigate('/login', { state: { sessionExpired: true } });
    };

    const resetInactivityTimer = () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(handleInactivity, INACTIVITY_LIMIT);
    };
    const events = ['mousemove', 'keydown', 'mousedown', 'touchstart'];
    events.forEach(event => window.addEventListener(event, resetInactivityTimer));
    resetInactivityTimer();

    return () => {
      events.forEach(event => window.removeEventListener(event, resetInactivityTimer));
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [user, logout, navigate]);

  return null; 
};

export default InactivityHandler; 