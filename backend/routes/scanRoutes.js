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
const IPQS_API_KEY = process.env.IPQS_API_KEY;
const SCAMALYTICS_API_KEY = process.env.SCAMALYTICS_API_KEY;
const SCAMALYTICS_ACCOUNT = process.env.SCAMALYTICS_ACCOUNT || 'mostafaheshamsheref';
const HYBRID_ANALYSIS_API_KEY = process.env.HYBRID_ANALYSIS_API_KEY;

// Helper: VirusTotal URL-safe base64 encoding
const base64UrlEncode = (str) =>
  Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

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

// Submit a file to Hybrid Analysis
async function submitFileToHybridAnalysis(fileBuffer, filename) {
  try {
    console.log(`🔍 Submitting file to Hybrid Analysis: ${filename}`);
    
    const formData = new FormData();
    formData.append('file', fileBuffer, filename);
    formData.append('environment_id', '110'); // Windows 7 64-bit environment
    
    const response = await axios.post(
      'https://www.hybrid-analysis.com/api/v2/submit/file',
      formData,
      {
        headers: {
          'api-key': HYBRID_ANALYSIS_API_KEY,
          'User-Agent': 'Falcon Sandbox',
          ...formData.getHeaders()
        }
      }
    );
    
    if (response.data && response.data.sha256) {
      console.log(`✅ File submitted successfully to Hybrid Analysis, SHA256: ${response.data.sha256}`);
      return {
        success: true,
        sha256: response.data.sha256,
        job_id: response.data.job_id
      };
    } else {
      console.error("❌ Hybrid Analysis submission failed:", response.data);
      return { success: false };
    }
  } catch (error) {
    console.error("❌ Error submitting file to Hybrid Analysis:", error.message);
    if (error.response) {
      console.error("Response status:", error.response.status);
      console.error("Response data:", error.response.data);
    }
    return { success: false, error: error.message };
  }
}

//neww
function calculateEmailHeaderVerdict(heuristicScore, ipqsFraudScore) {
  const finalScore = (heuristicScore + (ipqsFraudScore || 0)) / 2;
  if (finalScore >= 85) return "🔴 High Risk (Likely Malicious)";
  if (finalScore >= 50) return "🟠 Medium Risk (Potentially Unsafe)";
  if (finalScore >= 10) return "🟡 Low Risk (Exercise Caution)";
  return "🟢 Low Risk (Likely Safe)";
}


// Get analysis results from Hybrid Analysis
// Simplified function to get Hybrid Analysis results
async function getHybridAnalysisResults(sha256) {
  try {
    console.log(`🔍 Retrieving Hybrid Analysis results for: ${sha256}`);
    
    const response = await axios.get(
      `https://www.hybrid-analysis.com/api/v2/overview/${sha256}`,
      {
        headers: {
          'api-key': HYBRID_ANALYSIS_API_KEY,
          'User-Agent': 'Falcon Sandbox'
        }
      }
    );
    
    // Log the full response for debugging
    console.log(`Hybrid Analysis API response for ${sha256}:`, JSON.stringify(response.data, null, 2));
    
    if (response.data) {
      // Extract the threat score (0-100)
      const threatScore = response.data.threat_score || 0;
      
      // Determine verdict based on threat score
      let verdict;
      if (threatScore >= 80) {
        verdict = "🔴 High Risk (Likely Malicious)";
      } else if (threatScore >= 50) {
        verdict = "🟠 Medium Risk (Potentially Unsafe)";
      } else if (threatScore >= 20) {
        verdict = "🟡 Low Risk (Exercise Caution)";
      } else {
        verdict = "🟢 Very Low Risk (Likely Safe)";
      }
      
      return {
        success: true,
        sha256: sha256,
        risk_score: threatScore,
        verdict: verdict,
        malware_family: response.data.vx_family || "None detected",
        threat_level: response.data.threat_level || "unknown",
        environment: response.data.environment_description || "",
        analysis_url: `https://www.hybrid-analysis.com/sample/${sha256}`
      };
    } else {
      console.error("Invalid or empty response from Hybrid Analysis API");
      return { success: false, error: "Invalid response" };
    }
  } catch (error) {
    console.error(`❌ Error retrieving Hybrid Analysis results:`, error.message);
    if (error.response) {
      console.error("Response status:", error.response.status);
      console.error("Response data:", error.response.data);
    }
    return { success: false, error: error.message };
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

// Scan a URL via IPQS API
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

// Calculate aggregated risk score from scanning engines
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

// Calculate aggregated risk score for file attachments
function calculateFileRiskScore(vtScore, hybridScore) {
  // If only one scanner provided results, use that score
  if (vtScore > 0 && hybridScore === 0) return vtScore;
  if (hybridScore > 0 && vtScore === 0) return hybridScore;
  if (vtScore === 0 && hybridScore === 0) return 0;
  
  // Calculate weighted average (equal weights for both scanners)
  const aggregatedScore = (vtScore * 0.5) + (hybridScore * 0.5);
  return Math.round(aggregatedScore);
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

function analyzeHeadersHeuristically(headers) {
  const reasons = [];
  let score = 0;

  // Normalize keys
  const normalizedHeaders = {};
  for (const key in headers) {
    normalizedHeaders[key.toLowerCase()] = headers[key];
  }

  if (normalizedHeaders['spf-result'] && !normalizedHeaders['spf-result'].toLowerCase().includes('pass')) {
    score += 20;
    reasons.push('SPF check failed or not present: sender verification may be compromised');
  }
  if (normalizedHeaders['dkim-result'] && !normalizedHeaders['dkim-result'].toLowerCase().includes('pass')) {
    score += 20;
    reasons.push('DKIM check failed or not present: email integrity could not be verified');
  }
  if (normalizedHeaders['dmarc-result'] && !normalizedHeaders['dmarc-result'].toLowerCase().includes('pass')) {
    score += 20;
    reasons.push('DMARC check failed or not present: domain policy enforcement failed');
  }

  if (normalizedHeaders['from'] && normalizedHeaders['return-path']) {
    const fromDomain = extractDomain(normalizedHeaders['from']);
    const returnPathDomain = extractDomain(normalizedHeaders['return-path']);
    if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
      score += 20;
      reasons.push(`Mismatch between 'From' domain (${fromDomain}) and 'Return-Path' domain (${returnPathDomain}): possible spoofing`);
    }
  }

  if (normalizedHeaders['received']) {
    const receivedHeaders = Array.isArray(normalizedHeaders['received']) 
      ? normalizedHeaders['received'] 
      : [normalizedHeaders['received']];
    let suspiciousReceivedCount = 0;
    receivedHeaders.forEach((received, idx) => {
      if (/unknown/i.test(received) || /127\.0\.0\.1/.test(received)) {
        suspiciousReceivedCount++;
        reasons.push(`Suspicious "Received" header at position ${idx + 1}: contains "unknown" host or localhost IP`);
      }
    });
    // Cap received headers suspicious score at 10 points max
    score += Math.min(suspiciousReceivedCount * 5, 10);
  }

  if (!normalizedHeaders['message-id']) {
    score += 5;
    reasons.push('Missing "Message-ID" header: may indicate a forged or improperly formed email');
  } else if (/^\s*<.*@\d+\.\d+\.\d+\.\d+>/.test(normalizedHeaders['message-id'])) {
    score += 5;
    reasons.push('Suspicious "Message-ID" format: appears to use an IP address instead of domain');
  }

  // Cap score at 100 max
  if (score > 100) score = 100;

  return { 
    suspicious: score >= 40,  // threshold remains 40
    score,
    reasons
  };
}

function extractDomain(value) {
  if (!value) return null;

  if (typeof value === 'object' && value.value && Array.isArray(value.value)) {
    const addrObj = value.value.find(v => v.address);
    if (addrObj && addrObj.address) {
      value = addrObj.address;
    } else {
      value = value.value[0].toString();
    }
  } else if (typeof value === 'object' && value.address) {
    value = value.address;
  } else if (Array.isArray(value)) {
    value = value[0];
  }

  value = value.toString().trim().replace(/^<|>$/g, "");
  const match = value.match(/@([\w.-]+)/);
  return match ? match[1].toLowerCase() : null;
}





// === END heuristic email header analysis functions ===

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
        verdict: scamalyticsResults.verdict
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

// POST /api/scan-eml-file — Scan an email file with attachments
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

    // Scan attachments with both VirusTotal and Hybrid Analysis
    const attachments = parsedEmail.attachments || [];
    const attachmentScanResults = [];
    
    for (const att of attachments) {
      console.log(`📎 Scanning attachment: ${att.filename}`);
      
      // Run both scans in parallel
      const [vtScanRes, hybridSubmitRes] = await Promise.all([
        scanFileVT(att.filename, att.content),
        submitFileToHybridAnalysis(att.content, att.filename)
      ]);
      
      // Get VirusTotal risk score (if available)
      let vtRiskScore = 0;
      if (vtScanRes.verdict && vtScanRes.verdict.includes("Malicious")) {
        // Extract number from "🔴 Malicious (X detections)"
        const detections = parseInt(vtScanRes.verdict.match(/(\d+) detections/)?.[1] || "0");
        vtRiskScore = detections > 0 ? Math.min(100, detections * 10) : 0;
      }
      
      // Process Hybrid Analysis results if submission succeeded
      let hybridResults = { success: false, risk_score: 0 };
      if (hybridSubmitRes.success && hybridSubmitRes.sha256) {
        hybridResults = await getHybridAnalysisResults(hybridSubmitRes.sha256);
      }
      
      // Calculate aggregated risk score
      const hybridRiskScore = hybridResults.success ? hybridResults.risk_score : 0;
      const aggregatedScore = calculateFileRiskScore(vtRiskScore, hybridRiskScore);
      const aggregatedVerdict = getVerdictFromScore(aggregatedScore);
      
      attachmentScanResults.push({
        filename: att.filename,
        vt_results: vtScanRes,
        hybrid_analysis_results: hybridResults.success ? hybridResults : null,
        aggregated_risk_score: aggregatedScore,
        verdict: aggregatedVerdict
      });
    }

    // Extract raw headers + sender email
    const rawHeaders = parsedEmail.headerLines.map(h => h.line).join("\r\n");
    const senderEmail = parsedEmail.from?.value?.[0]?.address || "";

    // IPQS Email Header Scan
    let emailHeaderScanResult = null;
    if (senderEmail && rawHeaders) {
      console.log("Sender Email:", senderEmail);
      
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


    // Convert parsedEmail.headers (Map) to a plain object
    const headersObject = {};
    for (const [key, value] of parsedEmail.headers) {
      headersObject[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
    }

    const heuristicResult = analyzeHeadersHeuristically(headersObject);


    // Calculate final verdict
    const headerFinalVerdict = calculateEmailHeaderVerdict(
      heuristicResult.score,
      emailHeaderScanResult?.fraud_score || 0
    );


    // --- End heuristic addition ---

    res.json({
      emailBody: parsedEmail.text || parsedEmail.html || "",
      urlScanResults,
      attachmentScanResults,
      emailHeaderScanResult,
      heuristicResult,
      emailHeaderFinalVerdict: headerFinalVerdict  
    });

  } catch (err) {
    console.error("Error parsing or scanning .eml file:", err);
    res.status(500).json({ error: "Failed to parse or scan .eml file." });
  }
});



module.exports = router;
