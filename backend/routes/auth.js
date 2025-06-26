const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const mongoose = require("mongoose");
const User = require("../models/User"); // Import your User model
const sendVerificationEmail = require("../config/mailer"); // Import mailer

const router = express.Router();

// Sign Up Route with Email Verification (unchanged)
router.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    if (password.startsWith("$2b$")) {
      return res.status(400).json({ message: "Password is already hashed!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const verificationCode = crypto.randomInt(100000, 999999);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      verificationCode,
      verified: false,
      role: "user", // Default role is user
    });

    await newUser.save();

    await sendVerificationEmail(email, verificationCode);

    res
      .status(201)
      .json({ message: "User created. Verification code sent to email." });
  } catch (error) {
    console.error("Signup Error:", error);
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
