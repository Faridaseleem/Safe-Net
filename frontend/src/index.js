import React from 'react';
import ReactDOM from 'react-dom/client'; // For React 18+
import App from './App'; // Ensure this import matches the file name


const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);