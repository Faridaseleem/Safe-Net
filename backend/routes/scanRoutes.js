const express = require("express");
const router = express.Router();
const multer = require("multer");
const { simpleParser } = require("mailparser");
const axios = require("axios");
const FormData = require("form-data");
const BlockedUrl = require("../models/BlockedUrl"); // <-- Import BlockedUrl model
require("dotenv").config();

const upload = multer(); // Multer memory storage (no disk save)
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

// Helper: VirusTotal URL-safe base64 encoding
const base64UrlEncode = (str) =>
  Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

// Helper function to retry fetching URL analysis results
const fetchAnalysisResults = async (analysisId, retries = 15, delay = 7000) => {
  for (let i = 0; i < retries; i++) {
    try {
      const resultResponse = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: { "x-apikey": VIRUSTOTAL_API_KEY },
        }
      );

      const status = resultResponse.data.data.attributes.status;

      if (status === "completed") {
        return resultResponse.data.data.attributes.results;
      }

      console.log(`🔄 Waiting for scan to complete... (${i + 1}/${retries})`);
    } catch (error) {
      console.error("❌ Error fetching scan results:", error.message);
    }

    await new Promise((resolve) => setTimeout(resolve, delay));
  }

  throw new Error("Scan results not available after multiple retries.");
};

// Poll VirusTotal for file scan results by scan ID
async function pollFileScanResult(scanId, retries = 15, delay = 5000) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${scanId}`,
        { headers: { "x-apikey": VIRUSTOTAL_API_KEY } }
      );

      const status = res.data.data.attributes.status;
      if (status === "completed") {
        const stats = res.data.data.attributes.stats;
        const maliciousCount = stats.malicious + stats.suspicious;

        return {
          verdict:
            maliciousCount > 0
              ? `🔴 Malicious (${maliciousCount} detections)`
              : "🟢 Clean",
          stats,
        };
      }
      await new Promise((r) => setTimeout(r, delay));
    } catch (err) {
      console.error("Error polling file scan result:", err.message);
    }
  }
  return { verdict: "Scan result not ready yet." };
}

// Scan a URL via VirusTotal API
async function scanUrlVT(url) {
  try {
    const encodedUrl = base64UrlEncode(url);
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${encodedUrl}`,
      {
        headers: { "x-apikey": VIRUSTOTAL_API_KEY },
      }
    );

    const data = response.data;
    const stats = data.data.attributes.last_analysis_stats;
    const maliciousCount = (stats.malicious || 0) + (stats.suspicious || 0);

    return {
      url,
      total_sources: Object.values(stats).reduce((a, b) => a + b, 0),
      malicious_detections: maliciousCount,
      verdict:
        maliciousCount > 2
          ? "🔴 High Risk (Likely Malicious)"
          : maliciousCount > 0
          ? "🟠 Medium Risk (Potentially Unsafe)"
          : "🟢 Low Risk (Likely Safe)",
    };
  } catch (error) {
    if (error.response && error.response.status === 404) {
      await axios.post(
        "https://www.virustotal.com/api/v3/urls",
        `url=${encodeURIComponent(url)}`,
        {
          headers: {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      );
      return { url, verdict: "Scan submitted, results will be ready soon." };
    }
    return { url, error: error.message || "Unknown error" };
  }
}

// Scan a file attachment via VirusTotal File Scan API
async function scanFileVT(filename, fileBuffer) {
  try {
    const formData = new FormData();
    formData.append("file", fileBuffer, filename);

    const response = await axios.post(
      "https://www.virustotal.com/api/v3/files",
      formData,
      {
        headers: {
          "x-apikey": VIRUSTOTAL_API_KEY,
          ...formData.getHeaders(),
        },
      }
    );

    const scanId = response.data.data.id;
    const finalResult = await pollFileScanResult(scanId);

    return {
      filename,
      scan_id: scanId,
      verdict: finalResult.verdict,
    };
  } catch (error) {
    if (error.response && error.response.status === 409) {
      const existingScanId = error.response.data?.meta?.file_id;
      if (existingScanId) {
        const finalResult = await pollFileScanResult(existingScanId);
        return {
          filename,
          scan_id: existingScanId,
          verdict: finalResult.verdict,
          note: "Used existing scan report due to duplicate file.",
        };
      }
    }
    return { filename, error: error.message || "Unknown error" };
  }
}

// POST /api/scan-url — Scan a single URL with blocked URL check
router.post("/scan-url", async (req, res) => {
  if (!req.body || !req.body.url) {
    console.error("❌ Error: URL is missing from request body.");
    return res.status(400).json({ error: "URL is required." });
  }

  const { url } = req.body;

  try {
    // Check blocked URLs first
    const blocked = await BlockedUrl.findOne({ url });
    if (blocked && blocked.status === "malicious") {
      return res.json({
        url,
        verdict: "🔴 Malicious (Blocked by admin)",
        total_sources: 0,
        malicious_detections: 1,
        more_info: "This URL is blocked as malicious by an admin.",
      });
    }

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

    const analysisResults = await fetchAnalysisResults(analysisId);

    console.log("✅ Full Scan Results:", analysisResults);

    let totalSources = Object.keys(analysisResults).length || 1; // Avoid division by zero
    let detectedCount = 0;

    Object.values(analysisResults).forEach((engine) => {
      if (engine.category === "malicious") {
        detectedCount++;
      }
    });

    let detectionPercentage = ((detectedCount / totalSources) * 100).toFixed(2);

    let verdict;
    if (detectionPercentage > 2) {
      verdict = "🔴 High Risk (Likely Malicious)";
    } else if (detectionPercentage > 1) {
      verdict = "🟠 Medium Risk (Potentially Unsafe)";
    } else {
      verdict = "🟢 Low Risk (Likely Safe)";
    }

    const educationLink = "/education";

    res.json({
      url: url,
      total_sources: totalSources,
      malicious_detections: detectedCount,
      verdict: verdict,
      more_info: `If you want to learn more about phishing awareness and protection, visit our education page: ${educationLink}`,
    });
  } catch (error) {
    console.error("❌ Error scanning URL:", error.message);
    res.status(500).json({ error: "Failed to scan URL. Please try again." });
  }
});

// POST /api/scan-eml-file — Upload .eml, parse and scan URLs + attachments
router.post(
  "/scan-eml-file",
  upload.single("emlFile"),
  async (req, res) => {
    if (!req.file)
      return res.status(400).json({ error: "No file uploaded" });

    try {
      const parsedEmail = await simpleParser(req.file.buffer);

      // Extract URLs
      const urls = [];
      if (parsedEmail.text)
        urls.push(...(parsedEmail.text.match(/https?:\/\/[^\s]+/g) || []));
      if (parsedEmail.html)
        urls.push(...(parsedEmail.html.match(/https?:\/\/[^\s]+/g) || []));
      const uniqueUrls = [...new Set(urls)];

      // Scan URLs concurrently
      const urlScanResults = await Promise.all(uniqueUrls.map(scanUrlVT));

      // Scan attachments concurrently
      const attachments = parsedEmail.attachments || [];
      const attachmentScanResults = [];
      for (const att of attachments) {
        const scanRes = await scanFileVT(att.filename, att.content);
        attachmentScanResults.push(scanRes);
      }

      res.json({
        urlScanResults,
        attachmentScanResults,
      });
    } catch (err) {
      console.error("Error parsing or scanning .eml file:", err);
      res.status(500).json({ error: "Failed to parse or scan .eml file." });
    }
  }
);

module.exports = router;
