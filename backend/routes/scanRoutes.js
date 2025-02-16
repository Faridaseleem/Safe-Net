const express = require("express");
const axios = require("axios");
const router = express.Router();
require("dotenv").config();

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

// Scan URL Route
router.post("/scan-url", async (req, res) => {
    console.log("Received Request Body:", req.body); // Debugging log

    // Validate request body
    if (!req.body || !req.body.url) {
        console.error("❌ Error: URL is missing from request body.");
        return res.status(400).json({ error: "URL is required." });
    }

    const { url } = req.body;

    try {
        // Step 1: Submit URL to VirusTotal for scanning
        const scanResponse = await axios.post(
            "https://www.virustotal.com/api/v3/urls",
            new URLSearchParams({ url }), // Properly formatted request
            {
                headers: {
                    "x-apikey": VIRUSTOTAL_API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            }
        );

        const analysisId = scanResponse.data.data.id;
        console.log(`🔍 Analysis ID: ${analysisId}`);

        // Step 2: Fetch the scan results
        const resultResponse = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            {
                headers: {
                    "x-apikey": VIRUSTOTAL_API_KEY,
                },
            }
        );

        const analysisResults = resultResponse.data.data.attributes.results;
        console.log("✅ Full Scan Results:", analysisResults);

        // Step 3: Calculate malicious percentage
        let totalSources = Object.keys(analysisResults).length; // Count total antivirus sources
        let detectedCount = 0;

        Object.values(analysisResults).forEach((engine) => {
            if (engine.category === "malicious") {
                detectedCount++;
            }
        });

        let detectionPercentage = ((detectedCount / totalSources) * 100).toFixed(2);

        // Step 4: Generate a user-friendly verdict
        let verdict;
        if (detectionPercentage > 50) {
            verdict = "🔴 High Risk (Likely Malicious)";
        } else if (detectionPercentage > 20) {
            verdict = "🟠 Medium Risk (Potentially Unsafe)";
        } else {
            verdict = "🟢 Low Risk (Likely Safe)";
        }

        // Step 5: Return the structured response
        res.json({
            url: url,
            total_sources: totalSources,
            malicious_detections: detectedCount,
            detection_percentage: `${detectionPercentage}%`,
            verdict: verdict,
        });

    } catch (error) {
        console.error("❌ Error scanning URL:", error.response?.data || error.message);
        res.status(500).json({ error: "Failed to scan URL. Please try again." });
    }
});

module.exports = router;
