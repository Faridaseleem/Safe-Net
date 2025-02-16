import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Navbar from "./components/Navbar";  // Navigation bar at the top
import Home from "./pages/Home";  // Main page
import ScanURL from "./pages/ScanURL";  // URL Scanning page
import ScanEmail from "./pages/ScanEmail";  // Email Scanning page
import Education from "./pages/Education";  // Education page
import Login from "./pages/Login";  // Login page
import Signup from "./pages/Signup";  // Signup page
import ChangePlan from "./pages/ChangePlan";  // Subscription page
import "./App.css";

const App = () => {
  return (
    <Router>
      <Navbar /> {/* Top Menu */}
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/scan-url" element={<ScanURL />} />
        <Route path="/scan-email" element={<ScanEmail />} />
        <Route path="/education" element={<Education />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/change-plan" element={<ChangePlan />} />
      </Routes>
    </Router>
  );
};

export default App;
