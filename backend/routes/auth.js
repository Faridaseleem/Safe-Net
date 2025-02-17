const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../config/db'); // Import the database connection
const sendVerificationEmail = require("../config/mailer"); // Import mailer
const crypto = require("crypto"); // To generate random verification codes

const router = express.Router();

// Sign Up Route with Email Verification
router.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // Check if user already exists
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ message: 'Database error', error: err });
            if (results.length > 0) return res.status(400).json({ message: 'User already exists' });

            // Hash the password before saving
            const hashedPassword = await bcrypt.hash(password, 10);

            // Generate a 6-digit verification code
            const verificationCode = crypto.randomInt(100000, 999999);

            // Insert user into database with verification code
            const sql = 'INSERT INTO users (name, email, password, verification_code, verified) VALUES (?, ?, ?, ?, ?)';
            db.query(sql, [name, email, hashedPassword, verificationCode, false], async (err, result) => {
                if (err) {
                    return res.status(500).json({ message: 'Error creating user', error: err });
                }

                // Send verification email
                await sendVerificationEmail(email, verificationCode);

                res.status(201).json({ message: 'User created. Verification code sent to email.' });
            });
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Email Verification Route
router.post('/verify', (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({ message: 'Email and verification code are required' });
    }

    // Check if the code is correct
    db.query('SELECT * FROM users WHERE email = ? AND verification_code = ?', [email, code], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error', error: err });
        if (results.length === 0) return res.status(400).json({ message: 'Invalid verification code' });

        // Mark user as verified
        db.query('UPDATE users SET verified = 1 WHERE email = ?', [email], (err, result) => {
            if (err) return res.status(500).json({ message: 'Database error', error: err });
            res.status(200).json({ message: 'Email verified successfully' });
        });
    });
});

module.exports = router;
