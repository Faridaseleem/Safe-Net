import React from "react";
import { useNavigate } from "react-router-dom";
import "./Home.css";
import logo from "../assets/logo.png";

const Home = () => {
  const navigate = useNavigate();

  return (
    <div className="home-container">
      <img src={logo} alt="SafeNet Logo" className="logo" />
      <div className="security-banner">
    <p>🛡️ <strong>SafeNet:</strong> Your First Line of Defense Against Online Threats! <br />
    🔍 One click, instant results—because your online security matters! <br />
    🚀 Browse with confidence, let SafeNet be your digital shield!</p>
     </div>

      
     <p><strong>Choose a service below:</strong></p>
      
      <div className="home-buttons">
        <button onClick={() => navigate("/scan-url")}>🔍 Scan a URL</button>
        <button onClick={() => navigate("/scan-email")}>📧 Scan an Email</button>
        <button onClick={() => navigate("/report-url")}>🚨 Report a URL</button>
        <button onClick={() => navigate("/education")}>🌐 Education</button>
      </div>
    </div>
  );
};

export default Home;
