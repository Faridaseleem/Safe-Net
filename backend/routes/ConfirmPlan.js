// ConfirmPlan.js
import React, { useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import axios from "axios";

const ConfirmPlan = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const email = new URLSearchParams(location.search).get("email");

  useEffect(() => {
    const updateUserPlan = async () => {
      const pendingPlan = localStorage.getItem('pendingPlan');
      
      if (!pendingPlan || !email) {
        navigate('/select-plan');
        return;
      }

      try {
        await axios.post("http://localhost:5000/api/auth/update-plan", {
          email,
          plan: pendingPlan
        });
        
        localStorage.removeItem('pendingPlan');
        localStorage.removeItem('selectedPlan');
        
        alert("Plan successfully set! Please login to continue.");
        navigate('/login');
      } catch (error) {
        console.error("Error updating plan:", error);
        alert("Failed to update plan. Please try again.");
        navigate('/select-plan');
      }
    };

    updateUserPlan();
  }, [email, navigate]);

  return (
    <div>
      <h2>Setting up your plan...</h2>
    </div>
  );
};

export default ConfirmPlan;