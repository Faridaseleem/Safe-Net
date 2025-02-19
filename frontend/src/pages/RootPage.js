import React from "react";
import { useNavigate } from "react-router-dom";
import "./RootPage.css";
import logo from "../assets/logo.png";

const RootPage = () => {
  const navigate = useNavigate();

  return (
    <div className="root-container">
      {/* Logo */}
      <img src={logo} alt="SafeNet Logo" className="logo" />

      {/* Box containing title and description */}
      <div className="info-box">
        <h1 className="title">Welcome to SafeNet – Your Ultimate Cybersecurity Shield! 🛡️</h1>
        
        <p className="subtitle">
          In today’s digital world, online threats are everywhere. SafeNet is here to protect you from phishing scams and malicious attacks. 
          Whether you're scanning URLs, checking emails, or staying informed with our security tips, we ensure a safer browsing experience.
          <br /><br />
          Sign up now and take control of your online safety—because your security matters!🚀
          <br />
          Stay safe, browse confidently, and let SafeNet be your trusted digital guardian!🔒
        </p>
      </div>

      {/* Buttons */}
      <div className="button-group">
        <button className="btn login-btn" onClick={() => navigate("/login")}>Login</button>
        <button className="btn signup-btn" onClick={() => navigate("/signup")}>Sign Up</button>
      </div>
    </div>
  );
};

export default RootPage;
