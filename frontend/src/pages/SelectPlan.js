import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./SelectPlan.css";

const SelectPlan = () => {
  const [selectedPlan, setSelectedPlan] = useState(null);
  const navigate = useNavigate();

  const handlePlanSelect = (plan) => {
    setSelectedPlan(plan);
  };

  const handleProceed = () => {
    if (selectedPlan) {
      alert(`You have selected the ${selectedPlan} plan.`);
      navigate("/login"); // Redirect to login after selection
    } else {
      alert("Please select a plan to proceed.");
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

        <button className="select-plan-button" onClick={handleProceed}>Proceed to Login</button>
      </div>
    </div>
  );
};

export default SelectPlan;
