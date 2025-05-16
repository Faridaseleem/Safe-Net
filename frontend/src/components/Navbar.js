import React from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import "./Navbar.css";
import logo from "../assets/navlogo.png";

const Navbar = () => {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      const response = await axios.post("http://localhost:5000/api/auth/logout", {}, { withCredentials: true });
      if (response.status === 200) {
        alert("You have been logged out!");
        navigate("/login");
      } else {
        alert("Logout failed: " + response.data.message);
      }
    } catch (error) {
      alert("An error occurred during logout.");
    }
  };

  return (
    <nav className="navbar">
      <div className="logo1">
        <img src={logo} alt="SafeNet Logo" className="logo1" />
      </div>
      <ul className="nav-links">
        <li><Link to="/home"><strong>HOME</strong></Link></li>
        {/* Removed Scan URL, Scan Email, Report URL, Education links */}
        <li><button className="logout-btn" onClick={handleLogout}><strong>Logout</strong></button></li>
      </ul>
    </nav>
  );
};

export default Navbar;
