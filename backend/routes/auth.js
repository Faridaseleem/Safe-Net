const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const mongoose = require("mongoose");
const User = require("../models/User"); // Import your User model
const sendVerificationEmail = require("../config/mailer"); // Import mailer

const router = express.Router();

// Sign Up Route with Email Verification (unchanged)
router.post("/signup", async (req, res) => {
  const { name, email, password } = req.body; // No role here

  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ email });
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
      // role will default to "standard" from schema
    });

    await newUser.save();
    // Don't send verification email here - wait until after plan selection

    res.status(201).json({ 
      message: "User created successfully. Please select a plan."
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
    // Find user by email
    const user = await User.findOne({ email });
    
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
    await user.save();

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
    const user = await User.findOne({ email, verificationCode: code });
    if (!user) {
      return res.status(400).json({ message: "Invalid verification code" });
    }

    user.verified = true;
    user.verificationCode = null;
    await user.save();

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Login Route - UPDATED to include role in session and response
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const user = await User.findOne({ email });

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
      role: user.role || "user", // Add role here
    };

    console.log("✅ Storing user in session:", req.session.user);

    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({ message: "Session save failed" });
      }

      console.log("✅ Session successfully saved:", req.session);
      // Return user info with role in response
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

// Logout Route (unchanged)
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
