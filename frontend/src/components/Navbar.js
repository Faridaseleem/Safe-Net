import React from "react";
import { Link } from "react-router-dom";
import "./Navbar.css";
import logo from "../assets/navlogo.png";

const Navbar = () => {
  return (
    <nav className="navbar">
      <div className="logo1"><img src={logo} alt="SafeNet Logo" className="logo1" /></div>
      <ul className="nav-links">
      <li><Link to="/login"><strong>Login</strong></Link></li>
      <li><Link to="/signup"><strong>Sign Up</strong></Link></li>
      <li><Link to="/change-plan"><strong>Change Plan</strong></Link></li>
    </ul>
    </nav>
  );
};

export default Navbar;
