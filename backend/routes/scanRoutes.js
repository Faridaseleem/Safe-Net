const express = require("express");
const router = express.Router();
const multer = require("multer");
const { simpleParser } = require("mailparser");
const axios = require("axios");
const FormData = require("form-data");
const BlockedUrl = require("../models/BlockedUrl");
require("dotenv").config();

const upload = multer(); // Multer memory storage (no disk save)
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const IPQS_API_KEY = process.env.IPQS_API_KEY; // Add IPQS API key from .env
const SCAMALYTICS_API_KEY = process.env.SCAMALYTICS_API_KEY;
const SCAMALYTICS_ACCOUNT = process.env.SCAMALYTICS_ACCOUNT || 'mostafaheshamsheref';
 // Add Scamalytics API key from .env

// Helper: VirusTotal URL-safe base64 encoding
const base64UrlEncode = (str) =>
  Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

// Helper function to fetch VirusTotal analysis results
// Helper function to fetch VirusTotal analysis results
async function fetchAnalysisResults(analysisId, maxRetries = 10, waitTime = 5000) {
  console.log(`🔍 Fetching VT analysis results for ID: ${analysisId}`);
  
  for (let retry = 0; retry < maxRetries; retry++) {
    try {
      console.log(`Attempt ${retry + 1}/${maxRetries} to fetch VT results...`);
      
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: { "x-apikey": VIRUSTOTAL_API_KEY } }
      );
      
      const status = response.data.data.attributes.status;
      console.log(`VT analysis status: ${status}`);
      
      if (status === 'completed') {
        console.log(`✅ VT analysis completed! Sources found: ${Object.keys(response.data.data.attributes.results).length}`);
        return response.data.data.attributes.results;
      } else if (retry < maxRetries - 1) {
        console.log(`⏳ Analysis not ready, waiting ${waitTime/1000} seconds...`);
        // Wait longer between retries
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    } catch (error) {
      console.error(`❌ Error fetching analysis results (attempt ${retry + 1}):`, error.message);
      if (retry < maxRetries - 1) {
        // Wait between retries
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
  }
  
  console.warn("⚠️ All retries failed for VT analysis");
  return {}; // Return empty object if all retries failed
}

// Extract IP from a URL
async function extractIpFromUrl(url) {
  try {
    // First get hostname from URL
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    
    // Use DNS lookup to get IP (using a Promise-based wrapper for dns.lookup)
    const dns = require('dns');
    const { promisify } = require('util');
    const lookup = promisify(dns.lookup);
    
    const { address } = await lookup(hostname);
    return address;
  } catch (error) {
    console.error(`Error extracting IP from URL ${url}:`, error.message);
    return null;
  }
}

// Scan with Scamalytics API - Accepts URL or IP
// Scan with Scamalytics API - Accepts URL or IP
async function scanWithScamalytics(input) {
  try {
    let ip = input;
    
    // If input appears to be a URL, extract IP
    if (input.startsWith('http') || input.includes('://')) {
      ip = await extractIpFromUrl(input);
      if (!ip) return { success: false, risk_score: 0, error: "Could not extract IP from URL" };
    }
    
    console.log(`🔍 Scamalytics scanning IP: ${ip}`);
    
    // Use the correct endpoint structure
    const response = await axios.get(
      `https://api12.scamalytics.com/v3/${SCAMALYTICS_ACCOUNT}/`, {
        params: {
          key: SCAMALYTICS_API_KEY,
          ip: ip
        }
      }
    );
    
    // Log complete response for debugging
    console.log("Full Scamalytics response:", JSON.stringify(response.data, null, 2));
    
    // Check if we got valid data - accessing the correct nested structure
    if (response.data && response.data.scamalytics) {
      const scamalyticsData = response.data.scamalytics;
      
      // Extract the specific fields we want
      const score = scamalyticsData.scamalytics_score || 0;
      const risk = scamalyticsData.scamalytics_risk || 'Unknown';
      
      console.log(`✅ Extracted Scamalytics score: ${score}, risk: ${risk}`);
      
      return {
        success: true,
        ip: ip,
        risk_score: score,
        verdict: risk
      };
    } else {
      console.error("Invalid or empty response from Scamalytics API");
      return { success: false, risk_score: 0 };
    }
  } catch (error) {
    console.error(`Error scanning with Scamalytics: ${error.message}`);
    if (error.response) {
      console.error(`Response status: ${error.response.status}`);
      console.error(`Response data:`, error.response.data);
    }
    return { success: false, risk_score: 0 };
  }
}
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
    const totalSources = Object.values(stats).reduce((a, b) => a + b, 0);
    const vtRiskScore = maliciousCount > 0 ? (maliciousCount / totalSources) * 100 : 0;

    return {
      url,
      total_sources: totalSources,
      malicious_detections: maliciousCount,
      risk_score: vtRiskScore,
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

// Scan a URL via IPQS API (new function)
async function scanUrlIPQS(url) {
  try {
    const response = await axios.get(
      `https://www.ipqualityscore.com/api/json/url/${IPQS_API_KEY}/${encodeURIComponent(url)}`,
      {
        params: {
          strictness: 2, // Medium strictness
          fast: "true",
          timeout: 5, // 5 second timeout
        }
      }
    );

    const data = response.data;
    
    // Extract key metrics
    const riskScore = data.risk_score || 0; // 0-100 risk score
    const phishing = data.phishing;
    const malware = data.malware;
    const suspicious = data.suspicious;

    // Create verdict based on IPQS results
    let ipqsVerdict;
    if (riskScore >= 85) {
      ipqsVerdict = "🔴 High Risk (Likely Malicious)";
    } else if (riskScore >= 65) {
      ipqsVerdict = "🟠 Medium Risk (Potentially Unsafe)";
    } else {
      ipqsVerdict = "🟢 Low Risk (Likely Safe)";
    }

    return {
      url,
      risk_score: riskScore,
      is_phishing: phishing,
      is_malware: malware,
      is_suspicious: suspicious,
      verdict: ipqsVerdict,
    };
  } catch (error) {
    console.error("Error scanning URL with IPQS:", error.message);
    return { 
      url, 
      error: error.message || "Unknown error with IPQS scan",
      risk_score: 0 
    };
  }
}
// Scan an email header (sender domain) via IPQS Email Validation API
async function scanEmailHeaderWithIPQS(email) {
  try {
    const response = await axios.get(`https://ipqualityscore.com/api/json/email/${IPQS_API_KEY}/${encodeURIComponent(email)}`, {
      params: {
        timeout: 5,
        fast: "true",
        abuse_strictness: 1,
      }
    });

    const data = response.data;
    return {
      email,
      valid: data.valid,
      recent_abuse: data.recent_abuse,
      reputation_score: data.spam_score,
      is_suspect: !data.valid || data.recent_abuse || data.spam_score > 70,
      verdict: data.spam_score > 85
        ? "🔴 High Risk"
        : data.spam_score > 50
        ? "🟠 Medium Risk"
        : data.spam_score > 20
        ? "🟡 Low Risk"
        : "🟢 Clean"
    };
  } catch (error) {
    console.error("Error scanning email header with IPQS:", error.message);
    return {
      email,
      error: error.message || "IPQS email header scan failed"
    };
  }
}
function mapIPQSEmailVerdict(scanData) {
  if (!scanData) return "N/A";
  if (scanData.fraud_score && scanData.fraud_score > 80)
    return "🔴 High Risk (Likely Malicious)";
  if (
    scanData.deliverability === "low" ||
    scanData.suspect ||
    scanData.spam_trap_score !== "none"
  )
    return "🟠 Medium Risk (Potentially Unsafe)";
  if (scanData.deliverability === "high") return "🟢 Low Risk (Likely Safe)";
  return "⚪ Unknown";
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

// Calculate aggregated risk score from both scanning engines
function calculateAggregatedRiskScore(vtRiskScore, ipqsRiskScore, scamalyticsRiskScore = 0) {
  // Convert all risk scores to a 0-100 scale if needed
  const normalizedVtScore = vtRiskScore;
  const normalizedIpqsScore = ipqsRiskScore;
  const normalizedScamalyticsScore = scamalyticsRiskScore;
  
  // Determine if Scamalytics data is available
  const hasScamalytics = normalizedScamalyticsScore > 0;
  
  // Adjust weights based on available data
  let vtWeight, ipqsWeight, scamalyticsWeight;
  
  if (hasScamalytics) {
    // All three sources available
    vtWeight = 0.3;           // 30% weight to VirusTotal
    ipqsWeight = 0.4;         // 40% weight to IPQS
    scamalyticsWeight = 0.3;  // 30% weight to Scamalytics
  } else {
    // Only VT and IPQS available
    vtWeight = 0.4;   // 40% weight to VirusTotal
    ipqsWeight = 0.6; // 60% weight to IPQS
    scamalyticsWeight = 0;
  }
  
  // Calculate weighted average
  const aggregatedScore = 
    (normalizedVtScore * vtWeight) + 
    (normalizedIpqsScore * ipqsWeight) + 
    (normalizedScamalyticsScore * scamalyticsWeight);
  
  return {
    score: Math.round(aggregatedScore),
    verdict: getVerdictFromScore(aggregatedScore)
  };
}

// Helper to determine verdict based on aggregated score
function getVerdictFromScore(score) {
  if (score >= 80) {
    return "🔴 High Risk (Likely Malicious)";
  } else if (score >= 50) {
    return "🟠 Medium Risk (Potentially Unsafe)";
  } else if (score >= 20) {
    return "🟡 Low Risk (Exercise Caution)";
  } else {
    return "🟢 Very Low Risk (Likely Safe)";
  }
}

// Format date for scan report
function formatDateForReport(date) {
  return new Intl.DateTimeFormat('en-US', {
    month: 'numeric',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    hour12: true
  }).format(date);
}

// Format scan report with risk score instead of malicious detections
function formatScanReport(url, scanTime, successfulAPIs, aggregatedRiskScore, verdict) {
  return `📄 Scan Report
🔗 URL: ${url}

🕒 Scan Time: ${formatDateForReport(scanTime)}

📊 API Sources: ${successfulAPIs}/3

🎯 Risk Score: ${aggregatedRiskScore}/100

⚠️ Final Verdict: ${verdict}

📖 Learn More About Phishing Protection`;
}

// POST /api/scan-url — Scan a single URL with multiple engines
router.post("/scan-url", async (req, res) => {
  if (!req.body || !req.body.url) {
    console.error("❌ Error: URL is missing from request body.");
    return res.status(400).json({ error: "URL is required." });
  }

  const { url } = req.body;
  const scanTime = new Date();

  try {
    // Check blocked URLs first
    const blocked = await BlockedUrl.findOne({ url });
    if (blocked && blocked.status === "malicious") {
      const blockedReport = formatScanReport(
        url, 
        scanTime, 
        0, 
        100, 
        "🔴 Malicious (Blocked by admin)"
      );
      
      return res.json({
        url,
        scan_time: formatDateForReport(scanTime),
        verdict: "🔴 Malicious (Blocked by admin)",
        total_sources: 0,
        aggregated_risk_score: 100,
        more_info: "This URL is blocked as malicious by an admin.",
        scan_report: blockedReport,
      });
    }

    // Run all scans in parallel for efficiency
    const [vtResults, ipqsResults, scamalyticsResults] = await Promise.all([
      // Submit URL to VirusTotal for scanning
      (async () => {
        try {
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
          console.log(`🔍 VT Analysis ID: ${analysisId}`);

          const analysisResults = await fetchAnalysisResults(analysisId);
          console.log("✅ VT Scan Results Received");

          let totalSources = Object.keys(analysisResults).length || 1; // Avoid division by zero
          let detectedCount = 0;

          Object.values(analysisResults).forEach((engine) => {
            if (engine.category === "malicious") {
              detectedCount++;
            }
          });

          let vtRiskScore = ((detectedCount / totalSources) * 100);
          return {
            total_sources: totalSources,
            malicious_detections: detectedCount,
            risk_score: vtRiskScore,
            success: true
          };
        } catch (error) {
          console.error("❌ Error with VirusTotal scan:", error.message);
          return { success: false, error: error.message };
        }
      })(),
      
      // Submit URL to IPQS for scanning
      (async () => {
        try {
          const ipqsResult = await scanUrlIPQS(url);
          console.log("✅ IPQS Scan Results Received");
          return {
            ...ipqsResult,
            success: !ipqsResult.error
          };
        } catch (error) {
          console.error("❌ Error with IPQS scan:", error.message);
          return { success: false, error: error.message };
        }
      })(),
      
      // Scan URL with Scamalytics
      (async () => {
        try {
          const scamalyticsResult = await scanWithScamalytics(url);
          console.log("✅ Scamalytics Scan Results Received");
          return {
            ...scamalyticsResult,
            success: scamalyticsResult.success
          };
        } catch (error) {
          console.error("❌ Error with Scamalytics scan:", error.message);
          return { success: false, error: error.message };
        }
      })()
    ]);
      
    // Calculate aggregated risk score
    const vtRiskScore = vtResults.success ? vtResults.risk_score : 0;
    const ipqsRiskScore = ipqsResults.success ? ipqsResults.risk_score : 0;
    const scamalyticsRiskScore = scamalyticsResults.success ? scamalyticsResults.risk_score : 0;
    
    // Calculate aggregated score with all available data
    const aggregatedResult = calculateAggregatedRiskScore(
      vtRiskScore, 
      ipqsRiskScore,
      scamalyticsRiskScore
    );

    // Update the count of successful APIs for the report
    const successfulAPIs = [
      vtResults.success, 
      ipqsResults.success, 
      scamalyticsResults.success
    ].filter(Boolean).length;

    // Create the scan report with risk score instead of malicious detections
    const scanReport = formatScanReport(
      url,
      scanTime,
      successfulAPIs,
      aggregatedResult.score,
      aggregatedResult.verdict
    );

    const educationLink = "/education";

    res.json({
      url: url,
      scan_time: formatDateForReport(scanTime),
      // VirusTotal results
      vt_results: {
        total_sources: vtResults.total_sources || 0,
        malicious_detections: vtResults.malicious_detections || 0,
        risk_score: vtRiskScore,
      },
      // IPQS results
      ipqs_results: {
        risk_score: ipqsRiskScore,
        is_phishing: ipqsResults.is_phishing,
        is_malware: ipqsResults.is_malware,
        is_suspicious: ipqsResults.is_suspicious,
      },
      // Scamalytics results (if available)
      scamalytics_results: scamalyticsResults.success ? {
        ip: scamalyticsResults.ip,
        risk_score: scamalyticsRiskScore,
        is_proxy: scamalyticsResults.is_proxy,
        is_vpn: scamalyticsResults.is_vpn,
        is_tor: scamalyticsResults.is_tor,
        country_code: scamalyticsResults.country_code
      } : null,
      // Aggregated results
      aggregated_risk_score: aggregatedResult.score,
      verdict: aggregatedResult.verdict,
      more_info: `If you want to learn more about phishing awareness and protection, visit our education page: ${educationLink}`,
      scan_report: scanReport,
    });
  } catch (error) {
    console.error("❌ Error scanning URL:", error.message);
    res.status(500).json({ error: "Failed to scan URL. Please try again." });
  }
});

router.post("/scan-eml-file", upload.single("emlFile"), async (req, res) => {
  if (!req.file)
    return res.status(400).json({ error: "No file uploaded" });

  try {
    const parsedEmail = await simpleParser(req.file.buffer);

    // Extract URLs from text and html
    const urls = [];
    if (parsedEmail.text)
      urls.push(...(parsedEmail.text.match(/https?:\/\/[^\s]+/g) || []));
    if (parsedEmail.html)
      urls.push(...(parsedEmail.html.match(/https?:\/\/[^\s]+/g) || []));
    const uniqueUrls = [...new Set(urls)];

    // Scan URLs concurrently with VirusTotal + IPQS + Scamalytics
    const urlScanResults = await Promise.all(uniqueUrls.map(async (u) => {
      // Run all three scans in parallel
      const [vtRes, ipqsRes, scamalyticsRes] = await Promise.all([
        scanUrlVT(u), 
        scanUrlIPQS(u),
        scanWithScamalytics(u)
      ]);
      
      const vtRisk = vtRes?.risk_score || 0;
      const ipqsRisk = ipqsRes?.risk_score || 0;
      const scamalyticsRisk = scamalyticsRes?.risk_score || 0;
      
      const agg = calculateAggregatedRiskScore(vtRisk, ipqsRisk, scamalyticsRisk);

      return {
        url: u,
        vt_results: vtRes,
        ipqs_results: ipqsRes,
        scamalytics_results: scamalyticsRes.success ? scamalyticsRes : null,
        aggregated_risk_score: agg.score,
        verdict: agg.verdict,
      };
    }));

    // Scan attachments concurrently (VirusTotal only)
    const attachments = parsedEmail.attachments || [];
    const attachmentScanResults = [];
    for (const att of attachments) {
      const scanRes = await scanFileVT(att.filename, att.content);
      attachmentScanResults.push(scanRes);
    }

    // Extract raw headers + sender email
    const rawHeaders = parsedEmail.headerLines.map(h => h.line).join("\r\n");
    const senderEmail = parsedEmail.from?.value?.[0]?.address || "";

    // IPQS Email Header Scan
    let emailHeaderScanResult = null;
    if (senderEmail && rawHeaders) {
      console.log("Sender Email:", senderEmail);
      console.log("Raw Headers:", rawHeaders);

      try {
        const response = await axios.post(
          `https://ipqualityscore.com/api/json/email/${IPQS_API_KEY}/${encodeURIComponent(senderEmail)}`,
          {
            email_header: rawHeaders,
            strictness: 2,
            fast: true
          },
          {
            headers: {
              "Content-Type": "application/json"
            }
          }
        );
        console.log("IPQS Email Header Scan Response:", response.data);
        emailHeaderScanResult = response.data;
      } catch (error) {
        console.error("Error scanning email headers with IPQS:", error.response?.data || error.message);
        emailHeaderScanResult = { error: error.response?.data || error.message };
      }
    }

    res.json({
      emailBody: parsedEmail.text || parsedEmail.html || "",
      urlScanResults,
      attachmentScanResults,
      emailHeaderScanResult
    });

  } catch (err) {
    console.error("Error parsing or scanning .eml file:", err);
    res.status(500).json({ error: "Failed to parse or scan .eml file." });
  }
});

module.exports = router;