import React from "react";
import axios from 'axios';
import { BrowserRouter as Router, Route, Routes, Navigate } from "react-router-dom";
import Navbar from "./components/Navbar";
import ProtectedRoute from "./components/ProtectedRoute";
import Home from "./pages/Home";
import ScanURL from "./pages/ScanURL";
import ScanEmail from "./pages/ScanEmail";
import Education from "./pages/Education";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import ChangePlan from "./pages/ChangePlan";
import Verify from "./pages/Verify";
import SelectPlan from "./pages/SelectPlan";
import RootPage from "./pages/RootPage";
import ReportURL from "./pages/ReportURL";  // User URL report page
import AdminReportURLs from "./pages/AdminReportedURLs"; // Admin report management page
import Chatbot from "./components/Chatbot"; // NEW: Import Chatbot component**
import { useUser } from "./contexts/UserContext";
import "./App.css";

axios.defaults.withCredentials = true;

const App = () => {
  const { user, loading } = useUser();
  console.log("Current user in App:", user);

  // Show loading while checking authentication
  if (loading) {
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
          <div>Loading...</div>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <Routes>
        {/* Public routes - no authentication required */}
        <Route path="/" element={
          <ProtectedRoute requireAuth={false}>
            <RootPage />
          </ProtectedRoute>
        } />
        <Route path="/signup" element={
          <ProtectedRoute requireAuth={false}>
            <Signup />
          </ProtectedRoute>
        } />
        <Route path="/select-plan" element={
          <ProtectedRoute requireAuth={false}>
            <SelectPlan />
          </ProtectedRoute>
        } />
        <Route path="/verify" element={
          <ProtectedRoute requireAuth={false}>
            <Verify />
          </ProtectedRoute>
        } />
        <Route path="/login" element={
          <ProtectedRoute requireAuth={false}>
            <Login />
          </ProtectedRoute>
        } />

        {/* Protected routes - require authentication */}
        <Route path="/home" element={
          <ProtectedRoute>
            <>
              <Navbar />
              {(user && (user.role === 'premium' || user.role === 'admin')) && <Chatbot />}
              <Home />
            </>
          </ProtectedRoute>
        } />
        
        <Route path="/scan-url" element={
          <ProtectedRoute>
            <>
              <Navbar />
              {(user && (user.role === 'premium' || user.role === 'admin')) && <Chatbot />}
              <ScanURL />
            </>
          </ProtectedRoute>
        } />
        
        <Route path="/scan-email" element={
          <ProtectedRoute>
            <>
              <Navbar />
              {(user && (user.role === 'premium' || user.role === 'admin')) && <Chatbot />}
              <ScanEmail />
            </>
          </ProtectedRoute>
        } />
        
        <Route path="/education" element={
          <ProtectedRoute>
            <>
              <Navbar />
              {(user && (user.role === 'premium' || user.role === 'admin')) && <Chatbot />}
              <Education />
            </>
          </ProtectedRoute>
        } />
        
        <Route path="/change-plan" element={
          <ProtectedRoute>
            <>
              <Navbar />
              {(user && (user.role === 'premium' || user.role === 'admin')) && <Chatbot />}
              <ChangePlan />
            </>
          </ProtectedRoute>
        } />
        
        <Route path="/report-url" element={
          <ProtectedRoute>
            <>
              <Navbar />
              {(user && (user.role === 'premium' || user.role === 'admin')) && <Chatbot />}
              <ReportURL />
            </>
          </ProtectedRoute>
        } />

        {/* Admin-only routes */}
        <Route path="/admin/reports" element={
          <ProtectedRoute allowedRoles={['admin']}>
            <>
              <Navbar />
              <Chatbot />
              <AdminReportURLs />
            </>
          </ProtectedRoute>
        } />

        {/* Catch all other routes and redirect to home if authenticated, or login if not */}
        <Route path="*" element={
          user ? <Navigate to="/home" replace /> : <Navigate to="/login" replace />
        } />
      </Routes>
    </Router>
  );
};

export default App;
