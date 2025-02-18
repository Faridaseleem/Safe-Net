const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const User = require("../models/User"); // Import Mongoose User model
const sendVerificationEmail = require("../config/mailer"); // Import mailer

const router = express.Router();

// Sign Up Route with Email Verification
router.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: "All fields are required" });
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate a 6-digit verification code
        const verificationCode = crypto.randomInt(100000, 999999);

        // Create new user
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            verificationCode,
            verified: false,
        });

        await newUser.save();

        // Send verification email
        await sendVerificationEmail(email, verificationCode);

        res.status(201).json({ message: "User created. Verification code sent to email." });
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

// Email Verification Route
router.post("/verify", async (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({ message: "Email and verification code are required" });
    }

    try {
        // Find user with the provided email and verification code
        const user = await User.findOne({ email, verificationCode: code });
        if (!user) {
            return res.status(400).json({ message: "Invalid verification code" });
        }

        // Mark user as verified
        user.verified = true;
        user.verificationCode = null; // Clear the code after verification
        await user.save();

        res.status(200).json({ message: "Email verified successfully" });
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
});
// New route for plan selection
router.post("/select-plan", async (req, res) => {
    const { email, plan } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        user.plan = plan;
        await user.save();
        res.status(200).json({ message: "Plan selected successfully. Redirecting to login...", redirect: "/login" });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

module.exports = router;