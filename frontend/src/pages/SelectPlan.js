import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import "./SelectPlan.css";

const SelectPlan = () => {
  const [selectedPlan, setSelectedPlan] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();
  const email = new URLSearchParams(location.search).get("email");

  useEffect(() => {
    if (!email) {
      alert("Please sign up first");
      navigate("/signup");
    }
  }, [email, navigate]);

  const handlePlanSelect = (plan) => {
    setSelectedPlan(plan);
  };

  const handleProceed = async () => {
    if (!selectedPlan) {
      alert("Please select a plan to proceed.");
      return;
    }

    try {
      // Update the user's plan in the backend
      await axios.post("https://localhost:5000/api/auth/update-plan", {
        email: email,
        plan: selectedPlan.toLowerCase()
      });

      
      navigate(`/verify?email=${email}`);
    } catch (error) {
      alert("Failed to update plan. Please try again.");
      console.error("Error updating plan:", error);
    }
  };

  return (
    <div className="select-plan-wrapper">
      <div className="select-plan-container">
        <h2 className="select-plan-title">Choose Your Security Plan</h2>
        <p className="select-plan-subtitle">
          Select the best plan that fits your needs to ensure safe browsing and phishing detection.
        </p>
        
        <div className="plans">
          {/* Standard Plan */}
          <div 
            className={`plan ${selectedPlan === "Standard" ? "selected" : ""}`} 
            onClick={() => handlePlanSelect("Standard")}
          >
            <h3>Standard Plan</h3>
            <p>✔ URL and Email file scanning with VirusTotal API</p>
            <p>✔ Access to security reports</p>
            <p>✔ Limited scanning (10 scans per day)</p>
            <p className="price">💰 Free</p>
          </div>

          {/* Premium Plan */}
          <div 
            className={`plan ${selectedPlan === "Premium" ? "selected" : ""}`} 
            onClick={() => handlePlanSelect("Premium")}
          >
            <h3>Premium Plan</h3>
            <p>✔ Advanced phishing detection with multiple APIs</p>
            <p>✔ AI-powered chatbot integration</p>
            <p>✔ Risk scoring in security reports</p>
            <p>✔ Unlimited scanning</p>
            <p className="price">💰 $9.99/month</p>
          </div>
        </div>

        <button className="select-plan-button" onClick={handleProceed}>
          Proceed to Verification
        </button>
      </div>
    </div>
  );
};

export default SelectPlan;