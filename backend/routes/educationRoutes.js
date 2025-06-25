const express = require("express");
const router = express.Router();

// --- Mock Data for Blog/News ---
// In a real application, this might come from a 'articles' collection in your MongoDB
const articles = [
    {
        title: "New Phishing Scam Mimics Your Company's IT Help Desk",
        summary: "A sophisticated new campaign is targeting employees with emails that look like internal IT requests. Be wary of any unsolicited emails asking for credentials.",
        link: "#"
    },
    {
        title: "The Rise of 'Smishing': SMS-Based Phishing Attacks",
        summary: "Cybercriminals are increasingly using text messages to trick victims into clicking malicious links. These 'smishing' attacks often create a sense of urgency.",
        link: "#"
    },
    {
        title: "Cybersecurity Tip: Why You Need a Password Manager",
        summary: "Reusing passwords is one of the biggest security risks. A password manager can generate and store unique, strong passwords for every site.",
        link: "#"
    }
];

// --- API Route for the Education Page ---
// @route   GET /api/articles
// @desc    Get a list of cybersecurity articles
// @access  Public
router.get("/articles", (req, res) => {
    console.log("✅ Request received for /api/articles");
    res.json(articles);
});

module.exports = router;