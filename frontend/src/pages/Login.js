import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import { useUser } from "../contexts/UserContext";
import "./Login.css";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { setUser } = useUser(); 
  const from = location.state?.from?.pathname || "/home";

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      console.log("Attempting login for:", email);
      
      const response = await axios.post(
        "https://localhost:5000/api/auth/login",
        {
          email: email.trim(),
          password: password.trim(),
        },
        {
          withCredentials: true,
          headers: {
            'Content-Type': 'application/json',
          }
    });

      console.log("Login response:", response.data);

      if (response.data.user) {
        setUser({
          id: response.data.user.id,
          name: response.data.user.name,
          email: response.data.user.email,
          role: response.data.user.role
        });
        
        console.log("User set in context:", response.data.user);
        
    
        
        if (response.data.user.role === 'admin') {
          navigate("/admin/reports");
        } else {
          navigate(from);
        }
      }
    } catch (err) {
      console.error("Login error:", err);
      setError(err.response?.data?.message || "Login failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-wrapper">
      <div className="login-container">
        <h2>Login</h2>
        {from !== "/home" && (
          <p style={{ color: "#F8F8F2", marginBottom: "1rem", fontSize: "0.9rem" }}>
            Please log in to access {from}
          </p>
        )}
        <form className="login-form" onSubmit={handleLogin}>
          <input
            className="login-input"
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <input
            className="login-input"
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <button className="login-button" type="submit" disabled={loading}>
            {loading ? "Logging in..." : "Login"}
          </button>
        </form>
        {error && <p className="login-error">{error}</p>}
        <div className="login-links">
          <p className="login-link">Don't have an account? <a href="/signup">Sign up</a></p>
        </div>
      </div>
    </div>
  );
};

export default Login;