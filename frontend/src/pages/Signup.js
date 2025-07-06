import React, { useState } from "react";
import { useNavigate } from "react-router-dom"; 
import axios from "axios";
import "./Signup.css";

const Signup = () => {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [passwordErrors, setPasswordErrors] = useState([]);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const navigate = useNavigate();

  // Password validation
  const validatePassword = (password) => {
    const errors = [];
    
    if (password.length < 8) {
      errors.push("Password must be at least 8 characters long");
    }
    if (!/[A-Z]/.test(password)) {
      errors.push("Password must contain at least one uppercase letter");
    }
    if (!/[a-z]/.test(password)) {
      errors.push("Password must contain at least one lowercase letter");
    }
    if (!/[0-9]/.test(password)) {
      errors.push("Password must contain at least one number");
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push("Password must contain at least one special character (!@#$%^&*)");
    }
    
    return errors;
  };

  // Handle password change with validation
  const handlePasswordChange = (e) => {
    const newPassword = e.target.value;
    setPassword(newPassword);
    setPasswordErrors(validatePassword(newPassword));
  };
  const passwordsMatch = password === confirmPassword && password.length > 0;
  const isPasswordValid = passwordErrors.length === 0 && password.length > 0;
  const isFormValid = name.trim() && email.trim() && isPasswordValid && passwordsMatch;

  const handleSignup = async (e) => {
    e.preventDefault();
    setError("");
    
    // Final validation before submission
    if (!isFormValid) {
      if (!isPasswordValid) {
        setError("Please fix password requirements before submitting.");
        return;
      }
      if (!passwordsMatch) {
        setError("Passwords do not match.");
        return;
      }
      return;
    }

    setLoading(true);
  
    // Get selected plan
    let selectedPlan = localStorage.getItem('selectedPlan');
    let role = 'standard';
    if (selectedPlan && selectedPlan === 'premium') role = 'premium';
    console.log('Signup role being sent:', role);

    try {
      const response = await axios.post("https://localhost:5000/api/auth/signup", {
        name,
        email: email.trim(),
        password: password.trim(),
        role,
      });
  
      
      navigate(`/select-plan?email=${email}`); 
    } catch (err) {
      setError(err.response?.data?.message || "Signup failed. Try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="signup-wrapper">
      <div className="signup-container">
        <h2>Sign Up</h2>
        <form className="signup-form" onSubmit={handleSignup}>
          <input
            className="signup-input"
            type="text"
            placeholder="Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <input
            className="signup-input"
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          
          {/* Password Input */}
          <div className="password-input-container">
            <input
              className={`signup-input ${passwordErrors.length > 0 && password.length > 0 ? 'error' : ''}`}
              type={showPassword ? "text" : "password"}
              placeholder="Password"
              value={password}
              onChange={handlePasswordChange}
              required
            />
            <button
              type="button"
              className="password-toggle"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? "👁️" : "👁️‍🗨️"}
            </button>
          </div>

          {/* Password Requirements */}
          {password.length > 0 && (
            <div className="password-requirements">
              <h4>Password Requirements:</h4>
              <ul>
                <li className={password.length >= 8 ? 'valid' : 'invalid'}>
                  ✓ At least 8 characters
                </li>
                <li className={/[A-Z]/.test(password) ? 'valid' : 'invalid'}>
                  ✓ One uppercase letter
                </li>
                <li className={/[a-z]/.test(password) ? 'valid' : 'invalid'}>
                  ✓ One lowercase letter
                </li>
                <li className={/[0-9]/.test(password) ? 'valid' : 'invalid'}>
                  ✓ One number
                </li>
                <li className={/[!@#$%^&*(),.?":{}|<>]/.test(password) ? 'valid' : 'invalid'}>
                  ✓ One special character
                </li>
              </ul>
            </div>
          )}

          {/* Confirm Password Input */}
          <div className="password-input-container">
            <input
              className={`signup-input ${confirmPassword.length > 0 && !passwordsMatch ? 'error' : ''}`}
              type={showConfirmPassword ? "text" : "password"}
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
            <button
              type="button"
              className="password-toggle"
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
            >
              {showConfirmPassword ? "👁️" : "👁️‍🗨️"}
            </button>
          </div>

          {/* Password Match Indicator */}
          {confirmPassword.length > 0 && (
            <div className={`password-match ${passwordsMatch ? 'valid' : 'invalid'}`}>
              {passwordsMatch ? '✓ Passwords match' : '✗ Passwords do not match'}
            </div>
          )}

          <button 
            className="signup-button" 
            type="submit" 
            disabled={loading || !isFormValid}
          >
            {loading ? "Signing Up..." : "Sign Up"}
          </button>
        </form>
        {error && <p className="signup-error">{error}</p>}
        <p className="login-link">Already have an account? <a href="/login">Log in</a></p>
      </div>
    </div>
  );
};

export default Signup;
