const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const mongoose = require("mongoose");
const User = require("../models/User"); // Import your User model
const sendVerificationEmail = require("../config/mailer"); // Import mailer
const SecureDatabase = require("../utils/secureDatabase"); // Import secure database utility

const router = express.Router();

// Sign Up Route with Email Verification (unchanged)
router.post("/signup", async (req, res) => {
  const { name, email, password } = req.body; // No role here

  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // 🔒 SECURITY: Use secure database method to prevent NoSQL injection
    const existingUser = await SecureDatabase.safeFindOne(User, { email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = crypto.randomInt(100000, 999999);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      verificationCode,
      verified: false,
    });

    await newUser.save();
    // Don't send verification email here - wait until after plan selection

    res.status(201).json({ 
      message: "User created successfully. Please check your email for the verification code."
    });
  } catch (error) {
    console.error("Signup Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Add this route to handle plan updates
router.post("/update-plan", async (req, res) => {
  const { email, plan } = req.body;

  if (!email || !plan) {
    return res.status(400).json({ message: "Email and plan are required" });
  }

  try {
    // 🔒 SECURITY: Use secure database method to find user
    const user = await SecureDatabase.safeFindOne(User, { email });
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Validate plan
    const validPlans = ['standard', 'premium'];
    if (!validPlans.includes(plan)) {
      return res.status(400).json({ message: "Invalid plan selected" });
    }

    // Update user's role/plan
    user.role = plan;
    
    // 🔒 SECURITY: Use secure database method to save updated user
    await SecureDatabase.safeSave(user);

    // Send verification email if not already sent
    if (!user.verified && user.verificationCode) {
      await sendVerificationEmail(email, user.verificationCode);
    }

    res.status(200).json({ 
      message: "Plan updated successfully", 
      role: user.role 
    });
  } catch (error) {
    console.error("Update Plan Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Email Verification Route (unchanged)
router.post("/verify", async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res
      .status(400)
      .json({ message: "Email and verification code are required" });
  }

  try {
    // 🔒 SECURITY: Use secure database method to find user
    const user = await SecureDatabase.safeFindOne(User, { email, verificationCode: code });
    if (!user) {
      return res.status(400).json({ message: "Invalid verification code" });
    }

    user.verified = true;
    user.verificationCode = null;
    
    // 🔒 SECURITY: Use secure database method to save updated user
    await SecureDatabase.safeSave(user);

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Login Route 
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // 🔒 SECURITY: Use secure database method to find user
    const user = await SecureDatabase.safeFindOne(User, { email });

    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    if (!user.verified) {
      return res
        .status(403)
        .json({ message: "Please verify your email first" });
    }

    const isMatch = await bcrypt.compare(password.trim(), user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Store user info including role in session
    req.session.user = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role || "user",
    };

    console.log("✅ Storing user in session:", req.session.user);

    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({ message: "Session save failed" });
      }

      console.log("✅ Session successfully saved:", req.session);
      res.status(200).json({
        message: "Login successful",
        user: req.session.user,
      });
    });
  } catch (error) {
    console.error("Login Error:", error.message);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Route to change user plan (for logged-in users)
router.post("/change-plan", async (req, res) => {
  console.log("Change plan request received:", req.body);
  console.log("Session user:", req.session?.user);

  // Check if user is logged in via session
  if (!req.session || !req.session.user) {
    return res.status(401).json({ message: "Please login first" });
  }

  const { newPlan } = req.body;
  const userId = req.session.user.id;

  if (!newPlan) {
    return res.status(400).json({ message: "New plan is required" });
  }

  // Validate plan
  const validPlans = ['standard', 'premium'];
  if (!validPlans.includes(newPlan)) {
    return res.status(400).json({ message: "Invalid plan selected" });
  }

  try {
    // 🔒 SECURITY: Use secure database method to find user by ID
    const user = await SecureDatabase.safeFindById(User, userId);
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Update user's role in database
    user.role = newPlan;
    
    // 🔒 SECURITY: Use secure database method to save updated user
    await SecureDatabase.safeSave(user);

    // Update session with new role
    req.session.user.role = newPlan;
    
    // Save session
    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({ message: "Failed to update session" });
      }

      console.log("Plan updated successfully for user:", user.email, "New plan:", newPlan);
      
      res.status(200).json({ 
        success: true,
        message: "Plan updated successfully", 
        role: newPlan,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: newPlan
        }
      });
    });

  } catch (error) {
    console.error("Change Plan Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// A route to check current plan
router.get("/current-plan", async (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ message: "Not logged in" });
  }

  try {
    // 🔒 SECURITY: Use secure database method to find user by ID
    const user = await SecureDatabase.safeFindById(User, req.session.user.id);
    res.json({ 
      currentPlan: user.role,
      user: {
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get current user from session
router.get('/current-user', (req, res) => {
  console.log('Current user endpoint hit');
  console.log('Session:', req.session);
  console.log('Session user:', req.session.user);
  
  if (!req.session.user) {
    return res.status(401).json({ message: 'Not authenticated' });
  }
  
  res.json({ 
    user: req.session.user,
    sessionID: req.sessionID 
  });
});

// Logout Route
router.post("/logout", async (req, res) => {
  console.log("🔍 Current Session Before Logout:", req.session);

  if (!req.session) {
    console.log("⚠️ No active session found.");
    return res.status(400).json({ message: "No active session" });
  }

  const sessionID = req.sessionID;

  req.session.destroy(async (err) => {
    if (err) {
      console.error("❌ Logout error:", err);
      return res.status(500).json({ message: "Logout failed" });
    }

    try {
      await mongoose.connection.db
        .collection("sessions")
        .deleteOne({ _id: sessionID });

      console.log("✅ Session removed from database!");

      res.clearCookie("connect.sid", {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "strict",
      });

      console.log("✅ Session destroyed successfully!");
      return res.json({ message: "Logout successful" });
    } catch (dbError) {
      console.error("❌ Error deleting session from DB:", dbError);
      return res.status(500).json({ message: "Session removal failed" });
    }
  });
});

module.exports = router;
