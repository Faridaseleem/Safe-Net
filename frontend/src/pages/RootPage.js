import React from "react";
import { useNavigate } from "react-router-dom";
import "./RootPage.css";
import logo from "../assets/logo.png";
import bannerImage from "../assets/root5.png";
import icon1 from "../assets/icon1.svg"; // Multi-layered Protection
import icon2 from "../assets/icon2.svg"; // Real-time Threat Intelligence
import icon3 from "../assets/icon3.svg"; // Automated Response
import icon4 from "../assets/icon4.png"; // Automated Response

const RootPage = () => {
  const navigate = useNavigate();

  return (
    <div className="root-container">
      {/* Header - Logo and Buttons */}
      <div className="header">
        <img src={logo} alt="SafeNet Logo" className="logo" />
        <div className="button-group">
          <button className="btn login-btn" onClick={() => navigate("/login")}>Login</button>
          <button className="btn signup-btn" onClick={() => navigate("/signup")}>Sign Up</button>
        </div>
      </div>

      {/* First Banner Section */}
      <div className="banner">
        <div className="banner-text">
          <h1>
            <span>Fortify Security, </span>
           
            <span>Defeat Phishing.</span>
            
          </h1>
          <p>
            In today’s digital world, online threats are everywhere.
            SafeNet is here to protect you from phishing scams and malicious attacks.
          </p>
        </div>
        <img src={bannerImage} alt="Banner" className="banner-image" />
      </div>

      {/* Features Section */}
      <div className="features-container">
        <div className="feature">
          <img src={icon1} alt="Threat Detection" className="feature-icon" />
          <h2>Threat Detection</h2>
          <p>Scan URLs and email files to identify phishing and cyber threats in real-time.</p>
        </div>
        <div className="feature">
          <img src={icon2} alt="Security Awareness" className="feature-icon" />
          <h2>Security Awareness</h2>
          <p>Learn to spot and avoid phishing threats with educational content.</p>
        </div>
        <div className="feature">
          <img src={icon3} alt="API Integration" className="feature-icon" />
          <h2>API Integration</h2>
          <p>Enhance security with multiple API integrations for accurate threat analysis.</p>
        </div>
        <div className="feature">
          <img src={icon4} alt="Chatbot Assistance" className="feature-icon" />
          <h2>Chatbot Assistance</h2>
          <p>Get instant security awareness tips and scan URLs with our   Chatbot. </p>
        </div>
      </div>
    </div>
  );
};

export default RootPage;
