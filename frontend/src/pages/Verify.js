
import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import "./Verify.css";

const Verify = () => {
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const email = new URLSearchParams(location.search).get("email");

  const handleVerify = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await axios.post("https://localhost:5000/api/auth/verify", { email, code });
      navigate("/login"); // Redirect to plan selection page
    } catch (err) {
      setError(err.response?.data?.message || "Verification failed. Try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="verify-wrapper">
      <div className="verify-container">
        <h2>Email Verification</h2>
        <p>Enter the verification code sent to {email}.</p>
        <form className="verify-form" onSubmit={handleVerify}>
          <input
            className="verify-input"
            type="text"
            placeholder="Verification Code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
          />
          <button className="verify-button" type="submit" disabled={loading}>
            {loading ? "Verifying..." : "Verify"}
          </button>
        </form>
        {error && <p className="verify-error">{error}</p>}
      </div>
    </div>
  );
};

export default Verify;
