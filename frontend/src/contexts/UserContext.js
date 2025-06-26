// UserContext.js - with better debugging
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

  // Function to fetch current user from session
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
      }
    } catch (error) {
      console.error('Error fetching current user:', error);
    } finally {
      setLoading(false);
    }
  };

  // Load user on mount
  useEffect(() => {
    fetchCurrentUser();
  }, []);

  // Login function
  const login = (userData) => {
    console.log('Setting user in context:', userData);
    setUser(userData);
  };

  // Function to update user
  const updateUser = (updatedUser) => {
    console.log('Updating user in context:', updatedUser);
    setUser(updatedUser);
  };

  // Function to refresh user from backend
  const refreshUser = async () => {
    await fetchCurrentUser();
  };

  const logout = () => {
    console.log('Logging out user');
    setUser(null);
  };

  // Log current state
  console.log('UserContext - Current user:', user);
  console.log('UserContext - Loading:', loading);

  return (
    <UserContext.Provider value={{ 
      user, 
      setUser, 
      login,
      updateUser, 
      refreshUser,
      logout,
      loading 
    }}>
      {children}
    </UserContext.Provider>
  );
};