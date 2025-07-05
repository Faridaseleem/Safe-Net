// ChangePlan.js - Add debugging at the top
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useUser } from "../contexts/UserContext";
import axios from "axios";
import "./ChangePlan.css";

const ChangePlan = () => {
  const { user, updateUser, loading: userLoading } = useUser();
  const [currentPlan, setCurrentPlan] = useState("");
  const [selectedPlan, setSelectedPlan] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  // Debug logging
  console.log("ChangePlan - Current user:", user);
  console.log("ChangePlan - User loading:", userLoading);

  useEffect(() => {
    // Wait for user context to load
    if (userLoading) {
      console.log("Still loading user data...");
      return;
    }

    // Check if user is logged in
    if (!user || !user.email) {
      console.log("No user found, redirecting to login");
      alert("Please login first");
      navigate("/login");
    } else {
      console.log("User found:", user);
      setCurrentPlan(user.role || "standard");
      setSelectedPlan(user.role || "standard");
    }
  }, [user, userLoading, navigate]);

  // Show loading state while user context is loading
  if (userLoading) {
    return <div>Loading user data...</div>;
  }

  // Rest of your component code...
  const handlePlanSelect = (plan) => {
    setSelectedPlan(plan.toLowerCase());
    setMessage("");
  };

  const handleUpdatePlan = async () => {
    if (selectedPlan === currentPlan) {
      setMessage("You already have this plan!");
      return;
    }

    setLoading(true);
    setMessage("");

    try {
      const response = await axios.post(
        "https://localhost:5000/api/auth/change-plan",
        {
          userId: user.id,
          newPlan: selectedPlan
        },
        {
          withCredentials: true
        }
      );

      if (response.data.success) {
        const updatedUser = { ...user, role: selectedPlan };
        updateUser(updatedUser);
        
        setCurrentPlan(selectedPlan);
        setMessage("Plan updated successfully!");
        
        setTimeout(() => {
          navigate("/home");
        }, 2000);
      }

    } catch (error) {
      console.error("Error updating plan:", error);
      setMessage(error.response?.data?.message || "Failed to update plan. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  // Don't render the main component if no user
  if (!user || !user.email) {
    return null;
  }

  return (
    <div className="change-plan-wrapper">
      <div className="change-plan-container">
        <h2 className="change-plan-title">Change Your Plan</h2>
        <p className="current-plan-info">
          Hello, <strong>{user?.name}</strong>! Your current plan is: 
          <span className={`current-plan-badge ${currentPlan}`}>
            {currentPlan.toUpperCase()}
          </span>
        </p>

        <div className="plans-container">
          {/* Standard Plan */}
          <div 
            className={`plan-card ${selectedPlan === "standard" ? "selected" : ""} ${currentPlan === "standard" ? "current" : ""}`}
            onClick={() => handlePlanSelect("standard")}
          >
            {currentPlan === "standard" && <div className="current-label">CURRENT PLAN</div>}
            <h3>Standard Plan</h3>
            <div className="plan-price">Free</div>
            <ul className="plan-features">
              <li>✔ URL and Email file scanning</li>
              <li>✔ VirusTotal API integration</li>
              <li>✔ Access to security reports</li>
              <li>✔ Limited to 10 scans per day</li>
              <li>✗ No AI-powered chatbot</li>
              <li>✗ Basic risk scoring</li>
            </ul>
          </div>

          {/* Premium Plan */}
          <div 
            className={`plan-card ${selectedPlan === "premium" ? "selected" : ""} ${currentPlan === "premium" ? "current" : ""}`}
            onClick={() => handlePlanSelect("premium")}
          >
            {currentPlan === "premium" && <div className="current-label">CURRENT PLAN</div>}
            <div className="premium-badge">RECOMMENDED</div>
            <h3>Premium Plan</h3>
            <div className="plan-price">$9.99<span>/month</span></div>
            <ul className="plan-features">
              <li>✔ Everything in Standard</li>
              <li>✔ Advanced phishing detection</li>
              <li>✔ AI-powered chatbot</li>
              <li>✔ Advanced risk scoring</li>
              <li>✔ Unlimited scanning</li>
              <li>✔ Priority support</li>
            </ul>
          </div>
        </div>

        {message && (
          <div className={`message ${message.includes("success") ? "success" : "error"}`}>
            {message}
          </div>
        )}

        <div className="action-buttons">
          
          <button 
            className="update-button" 
            onClick={handleUpdatePlan}
            disabled={loading || selectedPlan === currentPlan}
          >
            {loading ? "Updating..." : 
             selectedPlan === "premium" && currentPlan === "standard" ? "Upgrade to Premium" :
             selectedPlan === "standard" && currentPlan === "premium" ? "Downgrade to Standard" :
             "Update Plan"}
          </button>
          <button 
            className="cancel-button" 
            onClick={() => navigate("/home")}
            disabled={loading}
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};

export default ChangePlan;