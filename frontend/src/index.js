import React from 'react';
import ReactDOM from 'react-dom/client'; // For React 18+
import App from './App'; // Your main App component
import { UserProvider } from './contexts/UserContext'; // Import UserProvider you will create

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <UserProvider>
      <App />
    </UserProvider>
  </React.StrictMode>
);
