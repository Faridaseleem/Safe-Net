const express = require("express");
const router = express.Router();
const multer = require("multer");
const { simpleParser } = require("mailparser");
const axios = require("axios");
const FormData = require("form-data");
const BlockedUrl = require("../models/BlockedUrl");
const whois = require("whois-json");
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

    const data = response.data;
    const threatScore = data.threat_score || 0;
    const family = data.vx_family || '';
    const label = data.verdict || '';
    const threatLevel = data.threat_level || 'unknown';

    // ✅ Get bundled files from correct path
    const bundledFiles = data.relations?.bundled_files || [];

    // 🔍 Log for debugging
    console.log("📦 Bundled Files:", JSON.stringify(bundledFiles, null, 2));

    // Check for any malicious bundled file
    const hasMaliciousBundle = bundledFiles.some(
      f => (f.threat_level || '').toLowerCase() === 'malicious'
    );

    let adjustedScore = threatScore;

    // Adjust score logic even if threat_score is 0
    if (adjustedScore === 0) {
      if (label.toLowerCase().includes("malicious")) adjustedScore = 80;
      else if (label.toLowerCase().includes("suspicious")) adjustedScore = 40;
      else if (family.toLowerCase().includes("eicar")) adjustedScore = 30;
    }

    // ⬆️ Boost score if malicious bundled files found
    if (hasMaliciousBundle && adjustedScore < 70) {
      adjustedScore = 70;
    }

    // Map final verdict
    let verdict;
    if (adjustedScore >= 80) verdict = "🔴 High Risk (Likely Malicious)";
    else if (adjustedScore >= 50) verdict = "🟠 Medium Risk (Potentially Unsafe)";
    else if (adjustedScore >= 20) verdict = "🟡 Low Risk (Exercise Caution)";
    else verdict = "🟢 Very Low Risk (Likely Safe)";

    return {
      success: true,
      sha256,
      risk_score: adjustedScore,
      verdict,
      malware_family: family || "None detected",
      threat_level: threatLevel,
      analysis_url: `https://www.hybrid-analysis.com/sample/${sha256}`,
      bundled_files: bundledFiles.map(f => ({
        filename: f.filename || "unknown",
        threat_level: f.threat_level || "unknown",
        sha256: f.sha256 || ""
      }))
    };
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

// Scan a URL via VirusTotal API with cleanup and error handling
async function scanUrlVT(rawUrl) {
  try {
    // Sanitize the input URL
    const url = rawUrl
      .replace(/["'><)\]]+$/g, '')   // Remove trailing HTML/junk
      .replace(/^[\["'<(]+/g, '')    // Remove leading junk
      .trim();

    // Validate format
    if (!/^https?:\/\/[\w.-]/.test(url)) {
      console.warn(`⚠️ Skipping invalid URL format: ${url}`);
      return { url, error: "Invalid URL format", verdict: "⚠️ Skipped" };
    }

    const encodedUrl = base64UrlEncode(url);

    // Try to fetch existing scan
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${encodedUrl}`,
      {
        headers: { "x-apikey": VIRUSTOTAL_API_KEY },
      }
    );

    const stats = response.data.data.attributes.last_analysis_stats;
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
    // If no scan exists, submit a new one
    if (error.response && error.response.status === 404) {
      try {
        await axios.post(
          "https://www.virustotal.com/api/v3/urls",
          `url=${encodeURIComponent(rawUrl)}`,
          {
            headers: {
              "x-apikey": VIRUSTOTAL_API_KEY,
              "Content-Type": "application/x-www-form-urlencoded",
            },
          }
        );
        return { url: rawUrl, verdict: "Scan submitted, results will be ready soon." };
      } catch (submitError) {
        console.error("❌ Error submitting URL to VT:", submitError.message);
        return { url: rawUrl, error: submitError.message || "Submission failed" };
      }
    }

    console.error("❌ VirusTotal scan error:", error.message);
    return { url: rawUrl, error: error.message || "Unknown error" };
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
    vtWeight = 0.4;           // 30% weight to VirusTotal
    ipqsWeight = 0.4;         // 40% weight to IPQS
    scamalyticsWeight = 0.2;  // 30% weight to Scamalytics
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
  } else if (score >= 30) {
    return "🟠 Medium Risk (Potentially Unsafe)";
  } else if (score >= 10) {
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
function analyzeUrlHeuristically(url) {
  let score = 0;
  const reasons = [];

  if (url.length > 75) {
    score += 10;
    reasons.push("URL is unusually long (over 75 characters)");
  }

  const suspiciousWords = ['login', 'secure', 'update', 'verify', 'account', 'bank', 'confirm', 'webscr'];
  suspiciousWords.forEach(word => {
    if (url.toLowerCase().includes(word)) {
      score += 10;
      reasons.push(`Contains suspicious keyword: "${word}"`);
    }
  });

  if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(url)) {
    score += 20;
    reasons.push("Uses raw IP address instead of domain");
  }

  if (!url.startsWith("https://")) {
    score += 10;
    reasons.push("Does not use HTTPS (insecure)");
  }

  return { score: Math.min(score, 100), reasons };
}

async function analyzeDomainAge(url) {
  try {
    const hostname = new URL(url).hostname;
    const whoisData = await whois(hostname);
    const created = new Date(whoisData.createdDate || whoisData.creationDate || whoisData.created);
    
    if (isNaN(created)) {
      return { score: 10, reason: "Domain creation date unavailable (WHOIS incomplete)" };
    }

    const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays < 90) return { score: 20, reason: "Domain registered less than 3 months ago" };
    if (ageDays < 180) return { score: 10, reason: "Domain registered less than 6 months ago" };
    
    return { score: 0, reason: null };
  } catch (err) {
    console.error("WHOIS failed:", err.message);
    return { score: 10, reason: "WHOIS lookup failed" };
  }
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
function generateEmailScanFinalVerdict({
  headerHeuristicScore,
  headerIPQSFraudScore,
  urlScanResults = [],
  attachmentScanResults = []
}) {
  const sources = [];
  const verdicts = [];

  // Header score (weighted)
  const headerScore = Math.min(
    (headerHeuristicScore * 0.7) + (headerIPQSFraudScore * 0.3),
    100
  );
  const headerVerdict = getVerdictFromScore(headerScore);
  verdicts.push(headerVerdict);
  sources.push(`📬 Header: ${headerVerdict} (${Math.round(headerScore)}/100)`);

  // URLs
  for (const url of urlScanResults) {
    if (url.blocked_by_admin) {
      url.aggregated_risk_score = 100;
      url.verdict = "🔴 Malicious (Blocked by admin)";
      verdicts.push(url.verdict);
      sources.push(`🔗 URL: ${url.url} → ${url.verdict} (100/100) — 🚫 Blocked by admin`);
      continue;
    }

    const vtScore = url.vt_results?.risk_score || 0;
    const ipqsScore = url.ipqs_results?.risk_score || 0;
    const scamalyticsScore = url.scamalytics_results?.risk_score || 0;
    const heuristicScore = url.heuristic_analysis?.score || 0;

    const urlScore = Math.min(
      (vtScore * 0.2) +
      (ipqsScore * 0.4) +
      (scamalyticsScore * 0.1) +
      (heuristicScore * 0.3),
      100
    );

    url.aggregated_risk_score = Math.round(urlScore);
    url.verdict = getVerdictFromScore(urlScore);

    verdicts.push(url.verdict);
    sources.push(`🔗 URL: ${url.url} → ${url.verdict} (${url.aggregated_risk_score}/100)`);
  }


  // Attachments
  for (const file of attachmentScanResults) {
    const vtScore = file.vt_results?.verdict?.includes("Malicious") ? 100 : 0;
    const hybridScore = file.hybrid_analysis_results?.risk_score || 0;

    const attachmentScore = Math.min(
      (vtScore * 0.8) + (hybridScore * 0.2),
      100
    );

    file.aggregated_risk_score = Math.round(attachmentScore);
    file.verdict = getVerdictFromScore(attachmentScore);

    verdicts.push(file.verdict);
    sources.push(`📎 Attachment: ${file.filename} → ${file.verdict} (${file.aggregated_risk_score}/100)`);
  }

  // Determine final verdict from highest severity
  const verdictOrder = ["🔴 High Risk (Likely Malicious)","🔴 Malicious (Blocked by admin)", "🟠 Medium Risk (Potentially Unsafe)", "🟡 Low Risk (Exercise Caution)", "🟢 Clean"];
  const finalVerdict = verdictOrder.find(v => verdicts.includes(v)) || "⚪ Unknown";

  return {
    final_verdict: finalVerdict,
    final_score: "Weighted",
    summary: `${finalVerdict} — Based on:\n` + sources.join("\n"),
    details: {
      header_score: headerScore,
      header_verdict: headerVerdict,
      url_verdicts: urlScanResults.map(u => ({
        url: u.url,
        verdict: u.verdict,
        score: u.aggregated_risk_score
      })),
      attachment_verdicts: attachmentScanResults.map(a => ({
        filename: a.filename,
        verdict: a.verdict,
        score: a.aggregated_risk_score
      }))
    }
  };
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

    // Run all scans in parallel
    const [vtResults, ipqsResults, scamalyticsResults] = await Promise.all([
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

          const totalSources = Object.keys(analysisResults).length || 1;
          let detectedCount = 0;

          Object.values(analysisResults).forEach(engine => {
            if (engine.category === "malicious") detectedCount++;
          });

          const vtRiskScore = (detectedCount / totalSources) * 100;
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

    // ✅ Heuristic Analysis
    const heuristicStatic = analyzeUrlHeuristically(url);
    const heuristicDynamic = await analyzeDomainAge(url);
    const heuristicScore = Math.min(heuristicStatic.score + heuristicDynamic.score, 100);
    const heuristicReasons = [...heuristicStatic.reasons];
    if (heuristicDynamic.reason) heuristicReasons.push(heuristicDynamic.reason);
    const heuristicVerdict = getVerdictFromScore(heuristicScore);

    // Extract scores
    const vtScore = vtResults?.risk_score || 0;
    const ipqsScore = ipqsResults?.risk_score || 0;
    const scamalyticsScore = scamalyticsResults?.risk_score || 0;
    // 🔢 Custom weighted score calculation
    const customScore = Math.min(
      (vtScore * 0.2) +
      (ipqsScore * 0.4) +
      (scamalyticsScore * 0.1) +
      (heuristicScore * 0.3),
      100
    );
    const finalScore = Math.round(customScore);
    const finalVerdict = getVerdictFromScore(finalScore);

    const successfulAPIs = [
      vtResults.success,
      ipqsResults.success,
      scamalyticsResults.success,
    ].filter(Boolean).length ; //  for heuristic

    const scanReport = formatScanReport(
      url,
      scanTime,
      successfulAPIs,
      finalScore,
      finalVerdict
    );

    const educationLink = "/education";

    res.json({
      url,
      scan_time: formatDateForReport(scanTime),
      vt_results: {
        total_sources: vtResults.total_sources || 0,
        malicious_detections: vtResults.malicious_detections || 0,
        risk_score: vtScore,
      },
      ipqs_results: {
        risk_score: ipqsScore,
        is_phishing: ipqsResults.is_phishing,
        is_malware: ipqsResults.is_malware,
        is_suspicious: ipqsResults.is_suspicious,
      },
      scamalytics_results: scamalyticsResults.success ? {
        ip: scamalyticsResults.ip,
        risk_score: scamalyticsScore,
        verdict: scamalyticsResults.verdict
      } : null,
      heuristic_analysis: {
        score: heuristicScore,
        reasons: heuristicReasons,
        verdict: heuristicVerdict
      },
      aggregated_risk_score: finalScore,
      verdict: finalVerdict,
      more_info: `If you want to learn more about phishing awareness and protection, visit our education page: ${educationLink}`,
      scan_report: scanReport,
    });
  } catch (error) {
    console.error("❌ Error scanning URL:", error.message);
    res.status(500).json({ error: "Failed to scan URL. Please try again." });
  }
});
function cleanUrl(rawUrl) {
  if (!rawUrl) return "";

  return rawUrl
    .replace(/<\/?.*?>/g, '')         // ✅ strip HTML tags (new)
    .replace(/["'><)\]]+$/g, '')      // trailing junk
    .replace(/^[\["'<(]+/g, '')       // leading junk
    .trim()
    .toLowerCase();                  // normalize for deduplication
}

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

    const url = new Set();
    const allMatches = (parsedEmail.text || '' + parsedEmail.html || '').match(/https?:\/\/[^\s"'<>]+/g) || [];

    for (const raw of allMatches) {
      const cleaned = cleanUrl(raw);
      if (
        /^https?:\/\/[\w.-]/.test(cleaned) &&
        !cleaned.includes(' ') &&
        !url.has(cleaned)
      ) {
        url.add(cleaned);
      }
    }

    const uniqueUrls = [...url];


    // Scan URLs concurrently with VirusTotal + IPQS + Scamalytics
    const urlScanResults = await Promise.all(uniqueUrls.map(async (u) => {
      const blocked = await BlockedUrl.findOne({ url: u });
      if (blocked?.status === "malicious") {
        return {
          url: u,
          vt_results: null,
          ipqs_results: null,
          scamalytics_results: null,
          heuristic_analysis: null,  // 🔴 Do NOT return a heuristic score here!
          aggregated_risk_score: 100,
          verdict: "🔴 Malicious (Blocked by admin)",
          blocked_by_admin: true
        };
      }


      // Proceed with normal scanning only if NOT blocked
      const [vtRes, ipqsRes, scamalyticsRes] = await Promise.all([
        scanUrlVT(u),
        scanUrlIPQS(u),
        scanWithScamalytics(u)
      ]);

      const vtRisk = vtRes?.risk_score || 0;
      const ipqsRisk = ipqsRes?.risk_score || 0;
      const scamalyticsRisk = scamalyticsRes?.risk_score || 0;

      const heuristicStatic = analyzeUrlHeuristically(u);
      const heuristicDynamic = await analyzeDomainAge(u);
      const heuristicScore = Math.min(heuristicStatic.score + heuristicDynamic.score, 100);
      const heuristicReasons = [...heuristicStatic.reasons];
      if (heuristicDynamic.reason) heuristicReasons.push(heuristicDynamic.reason);
      const heuristicVerdict = getVerdictFromScore(heuristicScore);

      const allScores = [vtRisk, ipqsRisk, scamalyticsRisk, heuristicScore];
      const availableScores = allScores.filter(score => score > 0);
      const finalScore = Math.round(availableScores.reduce((a, b) => a + b, 0) / availableScores.length || 0);
      const finalVerdict = getVerdictFromScore(finalScore);

      return {
        url: u,
        vt_results: vtRes,
        ipqs_results: ipqsRes,
        scamalytics_results: scamalyticsRes.success ? scamalyticsRes : null,
        heuristic_analysis: {
          score: heuristicScore,
          reasons: heuristicReasons,
          verdict: heuristicVerdict
        },
        aggregated_risk_score: finalScore,
        verdict: finalVerdict
      };
    }));

    // Scan attachments
    const attachments = parsedEmail.attachments || [];
    const attachmentScanResults = [];

    for (const att of attachments) {
      const [vtScanRes, hybridSubmitRes] = await Promise.all([
        scanFileVT(att.filename, att.content),
        submitFileToHybridAnalysis(att.content, att.filename)
      ]);

      let vtRiskScore = 0;
      if (vtScanRes.verdict && vtScanRes.verdict.includes("Malicious")) {
        const detections = parseInt(vtScanRes.verdict.match(/(\d+) detections/)?.[1] || "0");
        vtRiskScore = detections > 0 ? Math.min(100, detections * 10) : 0;
      }

      let hybridResults = { success: false, risk_score: 0 };
      if (hybridSubmitRes.success && hybridSubmitRes.sha256) {
        hybridResults = await getHybridAnalysisResults(hybridSubmitRes.sha256);
      }

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

    const rawHeaders = parsedEmail.headerLines.map(h => h.line).join("\r\n");
    const senderEmail = parsedEmail.from?.value?.[0]?.address || "";

    let emailHeaderScanResult = null;
    if (senderEmail && rawHeaders) {
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
        emailHeaderScanResult = response.data;
      } catch (error) {
        console.error("Error scanning email headers with IPQS:", error.response?.data || error.message);
        emailHeaderScanResult = { error: error.response?.data || error.message };
      }
    }

    const headersObject = {};
    for (const [key, value] of parsedEmail.headers) {
      headersObject[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
    }

    const heuristicResult = analyzeHeadersHeuristically(headersObject);
    const headerFinalVerdict = calculateEmailHeaderVerdict(
      heuristicResult.score,
      emailHeaderScanResult?.fraud_score || 0
    );

    const finalVerdictSummary = generateEmailScanFinalVerdict({
      headerHeuristicScore: heuristicResult.score,
      headerIPQSFraudScore: emailHeaderScanResult?.fraud_score || 0,
      urlScanResults,
      attachmentScanResults
    });

    res.json({
      emailBody: parsedEmail.text || parsedEmail.html || "",
      urlScanResults,
      attachmentScanResults,
      emailHeaderScanResult,
      heuristicResult,
      emailHeaderFinalVerdict: finalVerdictSummary.details.header_verdict,
      finalScore: finalVerdictSummary.final_score,
      finalVerdict: finalVerdictSummary.final_verdict,
      finalVerdictExplanation: finalVerdictSummary.summary,
      verdictBreakdown: finalVerdictSummary.details
    });


  } catch (err) {
    console.error("Error parsing or scanning .eml file:", err);
    res.status(500).json({ error: "Failed to parse or scan .eml file." });
  }
});

module.exports = router;
