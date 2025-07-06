import React, { createContext, useState, useContext, useEffect } from 'react';
import axios from 'axios';

const UserContext = createContext();

export const useUser = () => {
  const context = useContext(UserContext);
  if (!context) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};

export const UserProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanCount, setScanCount] = useState(null);
  const fetchCurrentUser = async () => {
    try {
      console.log('Fetching current user...');
      const response = await axios.get('https://localhost:5000/api/auth/current-user', {
        withCredentials: true
      });
      
      console.log('Current user response:', response.data);
      
      if (response.data.user) {
        setUser(response.data.user);
        console.log('User set from session:', response.data.user);
        await fetchScanCount();
      }
    } catch (error) {
      console.error('Error fetching current user:', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const fetchScanCount = async () => {
    try {
      const response = await axios.get('https://localhost:5000/api/scan-count', {
        withCredentials: true
      });
      setScanCount(response.data);
      console.log('Scan count fetched:', response.data);
    } catch (error) {
      console.error('Error fetching scan count:', error);
      setScanCount(null);
    }
  };

  const refreshScanCount = async () => {
    await fetchScanCount();
  };

  useEffect(() => {
    fetchCurrentUser();
  }, []);

  const login = async (userData) => {
    console.log('Setting user in context:', userData);
    setUser(userData);
    await fetchScanCount();
  };
  const updateUser = (updatedUser) => {
    console.log('Updating user in context:', updatedUser);
    setUser(updatedUser);
  };

  const refreshUser = async () => {
    await fetchCurrentUser();
  };

  const logout = async () => {
    console.log('Logging out user');
    try {
      await axios.post('https://localhost:5000/api/auth/logout', {}, {
        withCredentials: true
      });
    } catch (error) {
      console.error('Error during logout:', error);
    } finally {
      setUser(null);
      setScanCount(null);
    }
  };

  console.log('UserContext - Current user:', user);
  console.log('UserContext - Loading:', loading);
  console.log('UserContext - Scan count:', scanCount);

  return (
    <UserContext.Provider value={{ 
      user, 
      setUser, 
      login,
      updateUser, 
      refreshUser,
      logout,
      loading,
      scanCount,
      refreshScanCount
    }}>
      {children}
    </UserContext.Provider>
  );
};