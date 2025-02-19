const express = require("express");
const axios = require("axios");
const router = express.Router();
require("dotenv").config();

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

// Helper function to retry fetching results
const fetchAnalysisResults = async (analysisId, retries = 5, delay = 5000) => {
    for (let i = 0; i < retries; i++) {
        try {
            const resultResponse = await axios.get(
                `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
                {
                    headers: { "x-apikey": VIRUSTOTAL_API_KEY },
                }
            );

            const status = resultResponse.data.data.attributes.status;

            // Wait until analysis is complete
            if (status === "completed") {
                return resultResponse.data.data.attributes.results;
            }

            console.log(`🔄 Waiting for scan to complete... (${i + 1}/${retries})`);
        } catch (error) {
            console.error("❌ Error fetching scan results:", error.message);
        }

        // Wait before retrying
        await new Promise((resolve) => setTimeout(resolve, delay));
    }

    throw new Error("Scan results not available after multiple retries.");
};

// Scan URL Route
router.post("/scan-url", async (req, res) => {
    console.log("Received Request Body:", req.body);

    if (!req.body || !req.body.url) {
        console.error("❌ Error: URL is missing from request body.");
        return res.status(400).json({ error: "URL is required." });
    }

    const { url } = req.body;

    try {
        // Submit URL to VirusTotal for scanning
        const scanResponse = await axios.post(
            "https://www.virustotal.com/api/v3/urls",
            new URLSearchParams({ url }),
            {
                headers: {
                    "x-apikey": VIRUSTOTAL_API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            }
        );

        const analysisId = scanResponse.data.data.id;
        console.log(`🔍 Analysis ID: ${analysisId}`);

        // Fetch the scan results with retries
        const analysisResults = await fetchAnalysisResults(analysisId);

        console.log("✅ Full Scan Results:", analysisResults);

        // Calculate malicious percentage
        let totalSources = Object.keys(analysisResults).length || 1; // Avoid division by zero
        let detectedCount = 0;

        Object.values(analysisResults).forEach((engine) => {
            if (engine.category === "malicious") {
                detectedCount++;
            }
        });

        let detectionPercentage = ((detectedCount / totalSources) * 100).toFixed(2);

        // Determine the verdict
        let verdict;
        if (detectionPercentage > 2) {
            verdict = "🔴 High Risk (Likely Malicious)";
        } else if (detectionPercentage > 1) {
            verdict = "🟠 Medium Risk (Potentially Unsafe)";
        } else {
            verdict = "🟢 Low Risk (Likely Safe)";
        }

        // Adding the education link
        const educationLink = "/education"; // Adjust this if necessary

        res.json({
            url: url,
            total_sources: totalSources,
            malicious_detections: detectedCount,
            detection_percentage: `${detectionPercentage}%`,
            verdict: verdict,
            more_info: `If you want to learn more about phishing awareness and protection, visit our education page: ${educationLink}`,
        });

    } catch (error) {
        console.error("❌ Error scanning URL:", error.message);
        res.status(500).json({ error: "Failed to scan URL. Please try again." });
    }
});

module.exports = router;
