const express = require("express");
const router = express.Router();
const multer = require("multer");
const { simpleParser } = require("mailparser");
const axios = require("axios");
const FormData = require("form-data");
const BlockedUrl = require("../models/BlockedUrl");
const whois = require("whois-json");
const User = require("../models/User");
const mongoose = require("mongoose");
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
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    } catch (error) {
      console.error(`❌ Error fetching analysis results (attempt ${retry + 1}):`, error.message);
      if (retry < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
  }
  
  console.warn("⚠️ All retries failed for VT analysis");
  return {};
}

// Fixed IP extraction function
async function extractIpFromUrl(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    
    // Check if it's already an IP
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname)) {
      return hostname;
    }
    
    // Use DNS lookup
    const dns = require('dns').promises;
    try {
      const result = await dns.lookup(hostname);
      return result.address;
    } catch (dnsError) {
      console.error(`DNS lookup failed for ${hostname}:`, dnsError.message);
      return null;
    }
    
  } catch (error) {
    console.error(`Error extracting IP from URL ${url}:`, error.message);
    return null;
  }
}

// Fixed Scamalytics function
async function scanWithScamalytics(input) {
  try {
    let ip = input;
    
    // If input is a URL, extract IP
    if (input.startsWith('http') || input.includes('://')) {
      ip = await extractIpFromUrl(input);
      if (!ip) {
        console.log('⚠️ Could not extract IP from URL for Scamalytics');
        return { 
          success: false, 
          risk_score: 0, 
          error: "Could not extract IP from URL" 
        };
      }
    }
    
    console.log(`🔍 Scamalytics scanning IP: ${ip}`);
    
    // Fixed API endpoint
    const apiUrl = `https://api12.scamalytics.com/v3/${SCAMALYTICS_ACCOUNT}/`;
    console.log(`📡 Calling Scamalytics API: ${apiUrl}`);
    
    const response = await axios.get(apiUrl, {
      params: {
        key: SCAMALYTICS_API_KEY,
        ip: ip
      },
      timeout: 10000,
      validateStatus: function (status) {
        return status < 500;
      }
    });
    
    console.log(`📥 Scamalytics Response Status: ${response.status}`);
    console.log(`📥 Scamalytics Response Data:`, JSON.stringify(response.data, null, 2));
    
    // Handle different response structures
    if (response.data) {
      let score = 0;
      let risk = 'Unknown';
      
      // Try different possible response structures
      if (response.data.score !== undefined) {
        score = parseInt(response.data.score) || 0;
      } else if (response.data.scamalytics?.score !== undefined) {
        score = parseInt(response.data.scamalytics.score) || 0;
      } else if (response.data.scamalytics?.scamalytics_score !== undefined) {
        score = parseInt(response.data.scamalytics.scamalytics_score) || 0;
      }
      
      // Determine risk level
      if (score >= 80) risk = 'very high';
      else if (score >= 60) risk = 'high';
      else if (score >= 40) risk = 'medium';
      else if (score >= 20) risk = 'low';
      else risk = 'very low';
      
      console.log(`✅ Scamalytics final score: ${score}, risk: ${risk}`);
      
      return {
        success: true,
        ip: ip,
        risk_score: score,
        verdict: risk
      };
    }
    
    return { 
      success: false, 
      risk_score: 0, 
      error: "Invalid response structure" 
    };
    
  } catch (error) {
    console.error(`❌ Error scanning with Scamalytics:`, error.message);
    if (error.response) {
      console.error(`Response status: ${error.response.status}`);
      console.error(`Response data:`, error.response.data);
    }
    return { 
      success: false, 
      risk_score: 0, 
      error: error.message 
    };
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
      'https://hybrid-analysis.com/api/v2/submit/file',
      formData,
      {
        headers: {
          'api-key': HYBRID_ANALYSIS_API_KEY,
          'User-Agent': 'Falcon Sandbox',
          ...formData.getHeaders()
        },
        timeout: 30000
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
        },
        timeout: 15000
      }
    );

    const data = response.data;
    const threatScore = data.threat_score || 0;
    const family = data.vx_family || '';
    const label = data.verdict || '';
    const threatLevel = data.threat_level || 'unknown';

    const bundledFiles = data.relations?.bundled_files || [];
    console.log("📦 Bundled Files:", JSON.stringify(bundledFiles, null, 2));

    const hasMaliciousBundle = bundledFiles.some(
      f => (f.threat_level || '').toLowerCase() === 'malicious'
    );

    let adjustedScore = threatScore;

    if (adjustedScore === 0) {
      if (label.toLowerCase().includes("malicious")) adjustedScore = 80;
      else if (label.toLowerCase().includes("suspicious")) adjustedScore = 40;
      else if (family.toLowerCase().includes("eicar")) adjustedScore = 30;
    }

    if (hasMaliciousBundle && adjustedScore < 70) {
      adjustedScore = 70;
    }

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

// Fixed VirusTotal URL scanning
async function scanUrlVT(rawUrl, role = "premium") {
  try {
    const url = rawUrl
      .replace(/["'><)\]]+$/g, '')
      .replace(/^[\["'<(]+/g, '')
      .trim();

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
        timeout: 15000
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
      verdict: getVerdictFromScore(vtRiskScore, role),
      success: true
    };

  } catch (error) {
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
            timeout: 15000
          }
        );
        return { url: rawUrl, verdict: "Scan submitted, results will be ready soon.", success: false };
      } catch (submitError) {
        console.error("❌ Error submitting URL to VT:", submitError.message);
        return { url: rawUrl, error: submitError.message || "Submission failed", success: false };
      }
    }

    console.error("❌ VirusTotal scan error:", error.message);
    return { url: rawUrl, error: error.message || "Unknown error", success: false };
  }
}

// Fixed IPQS URL scanning
async function scanUrlIPQS(url) {
  try {
    console.log(`🔍 IPQS scanning URL: ${url}`);
    
    const apiUrl = `https://www.ipqualityscore.com/api/json/url/${IPQS_API_KEY}/${encodeURIComponent(url)}`;
    console.log(`📡 Calling IPQS API...`);
    
    const response = await axios.get(apiUrl, {
      params: {
        strictness: 2,
        fast: "true",
        timeout: 5
      },
      timeout: 1000000,
      validateStatus: function (status) {
        return status < 500;
      }
    });
    
    console.log(`📥 IPQS Response Status: ${response.status}`);
    const data = response.data;
    
    if (!data || data.success === false) {
      console.error('❌ IPQS API returned error:', data?.message || 'Unknown error');
      return {
        url,
        risk_score: 0,
        error: data?.message || 'IPQS API error',
        success: false
      };
    }
    
    const riskScore = parseInt(data.risk_score) || 0;
    
    console.log(`✅ IPQS scan complete. Risk score: ${riskScore}`);
    
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
      is_phishing: data.phishing || false,
      is_malware: data.malware || false,
      is_suspicious: data.suspicious || false,
      verdict: ipqsVerdict,
      success: true
    };
    
  } catch (error) {
    console.error("❌ Error scanning URL with IPQS:", error.message);
    if (error.response) {
      console.error("Response status:", error.response.status);
      console.error("Response data:", error.response.data);
    }
    return { 
      url, 
      error: error.message || "Unknown error with IPQS scan",
      risk_score: 0,
      success: false
    };
  }
}

// Fixed email header scanning with IPQS
async function scanEmailHeaderWithIPQS(email) {
  try {
    console.log(`🔍 IPQS scanning email: ${email}`);
    
    // Use GET request, not POST
    const response = await axios.get(
      `https://ipqualityscore.com/api/json/email/${IPQS_API_KEY}/${encodeURIComponent(email)}`,
      {
        params: {
          timeout: 5,
          fast: "true",
          abuse_strictness: 1
        },
        timeout: 10000
      }
    );
    
    const data = response.data;
    console.log(`✅ IPQS email scan complete. Fraud score: ${data.fraud_score || 0}`);
    
    return {
      email,
      valid: data.valid || false,
      recent_abuse: data.recent_abuse || false,
      fraud_score: data.fraud_score || 0,
      reputation_score: data.spam_score || 0,
      is_suspect: !data.valid || data.recent_abuse || (data.fraud_score > 70),
      verdict: data.fraud_score > 85
        ? "🔴 High Risk"
        : data.fraud_score > 50
        ? "🟠 Medium Risk"
        : data.fraud_score > 20
        ? "🟡 Low Risk"
        : "🟢 Clean",
      success: true
    };
    
  } catch (error) {
    console.error("❌ Error scanning email header with IPQS:", error.message);
    return {
      email,
      error: error.message || "IPQS email header scan failed",
      fraud_score: 0,
      success: false
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
        timeout: 30000
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
  const normalizedVtScore = vtRiskScore || 0;
  const normalizedIpqsScore = ipqsRiskScore || 0;
  const normalizedScamalyticsScore = scamalyticsRiskScore || 0;
  
  const hasScamalytics = normalizedScamalyticsScore > 0;
  
  let vtWeight, ipqsWeight, scamalyticsWeight;
  
  if (hasScamalytics) {
    vtWeight = 0.4;
    ipqsWeight = 0.4;
    scamalyticsWeight = 0.2;
  } else {
    vtWeight = 0.4;
    ipqsWeight = 0.6;
    scamalyticsWeight = 0;
  }
  
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
  if (vtScore > 0 && hybridScore === 0) return vtScore;
  if (hybridScore > 0 && vtScore === 0) return hybridScore;
  if (vtScore === 0 && hybridScore === 0) return 0;
  
  const aggregatedScore = (vtScore * 0.5) + (hybridScore * 0.5);
  return Math.round(aggregatedScore);
}

// Helper to determine verdict based on aggregated score
function getVerdictFromScore(score, role = "premium") {
  if (role === "standard") {
    if (score < 10) {
      return "🟢 Low Risk (Likely Safe)";
    } else if (score < 15) {
      return "🟠 Medium Risk (Potentially Unsafe)";
    } else {
      return "🔴 High Risk (Likely Malicious)";
    }
  }

  if (score >= 50) {
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
    score += Math.min(suspiciousReceivedCount * 5, 10);
  }

  if (!normalizedHeaders['message-id']) {
    score += 5;
    reasons.push('Missing "Message-ID" header: may indicate a forged or improperly formed email');
  } else if (/^\s*<.*@\d+\.\d+\.\d+\.\d+>/.test(normalizedHeaders['message-id'])) {
    score += 5;
    reasons.push('Suspicious "Message-ID" format: appears to use an IP address instead of domain');
  }

  if (score > 100) score = 100;

  return { 
    suspicious: score >= 40,
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
  attachmentScanResults = [],
  userRole = "premium"
}) {
  const sources = [];
  const verdicts = [];

  // Header score (weighted) - only include if there are actual header scores
  if (headerHeuristicScore > 0 || headerIPQSFraudScore > 0) {
    const headerScore = Math.min(
      (headerHeuristicScore * 0.7) + (headerIPQSFraudScore * 0.3),
      100
    );
    const headerVerdict = getVerdictFromScore(headerScore, userRole);
    verdicts.push(headerVerdict);
    sources.push(`📬 Header: ${headerVerdict} (${Math.round(headerScore)}/100)`);
  }

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

    // Dynamically calculate based on available results
    const weights = {
      vt: vtScore > 0 ? 0.2 : 0,
      ipqs: ipqsScore > 0 ? 0.4 : 0,
      scamalytics: scamalyticsScore > 0 ? 0.1 : 0,
      heuristic: heuristicScore > 0 ? 0.3 : 0
    };

    const totalWeight = weights.vt + weights.ipqs + weights.scamalytics + weights.heuristic;
    if (totalWeight > 0) {
      Object.keys(weights).forEach(key => {
        weights[key] = weights[key] / totalWeight;
      });
    }

    const urlScore = Math.round(
      (vtScore * weights.vt) +
      (ipqsScore * weights.ipqs) +
      (scamalyticsScore * weights.scamalytics) +
      (heuristicScore * weights.heuristic)
    );

    url.aggregated_risk_score = Math.round(urlScore);
    url.verdict = getVerdictFromScore(urlScore, userRole);

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
    file.verdict = getVerdictFromScore(attachmentScore, userRole);

    verdicts.push(file.verdict);
    sources.push(`📎 Attachment: ${file.filename} → ${file.verdict} (${file.aggregated_risk_score}/100)`);
  }

  // Determine final verdict from highest severity
  const verdictOrder = ["🔴 High Risk (Likely Malicious)","🔴 Malicious (Blocked by admin)", "🟠 Medium Risk (Potentially Unsafe)", "🟡 Low Risk (Exercise Caution)", "🟢 Very Low Risk (Likely Safe)"];
  const finalVerdict = verdictOrder.find(v => verdicts.includes(v)) || "⚪ Unknown";

  const finalVerdictSummary = {
    final_verdict: finalVerdict,
    final_score: "Weighted",
    summary: `${finalVerdict} — Based on:\n` + sources.join("\n"),
    details: {
      header_score: (headerHeuristicScore > 0 || headerIPQSFraudScore > 0) ? Math.min((headerHeuristicScore * 0.7) + (headerIPQSFraudScore * 0.3), 100) : 0,
      header_verdict: (headerHeuristicScore > 0 || headerIPQSFraudScore > 0) ? getVerdictFromScore(Math.min((headerHeuristicScore * 0.7) + (headerIPQSFraudScore * 0.3), 100), userRole) : "N/A",
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

  console.log(`🎯 Final verdict for ${userRole} user: ${finalVerdictSummary.final_verdict}`);
  console.log(`📊 Verdict summary: ${finalVerdictSummary.summary}`);

  return finalVerdictSummary;
}

// Middleware to check user role and enforce scan limits
async function enforceScanLimit(req, res, next) {
  let userId = req.session?.user?.id || req.body.userId;
  if (!userId) return next();
  const user = await User.findById(userId);
  if (!user) return res.status(403).json({ error: "User not found" });
  if (user.role === "premium" || user.role === "admin") return next();

  const ScanLog = mongoose.connection.collection("scanlogs");
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const tomorrow = new Date(today);
  tomorrow.setDate(today.getDate() + 1);
  const count = await ScanLog.countDocuments({
    userId: user._id.toString(),
    createdAt: { $gte: today, $lt: tomorrow }
  });
  if (count >= 10) {
    return res.status(429).json({ error: "Scan limit reached (10 per day for standard users)" });
  }
  await ScanLog.insertOne({ userId: user._id.toString(), createdAt: new Date() });
  next();
}

// Fixed POST /api/scan-url endpoint with better error handling
router.post("/scan-url", enforceScanLimit, async (req, res) => {
  if (!req.body || !req.body.url) {
    return res.status(400).json({ error: "URL is required." });
  }

  const { url } = req.body;
  const scanTime = new Date();
  
  console.log(`\n🚀 Starting URL scan for: ${url}`);
  console.log(`👤 User role: ${await getUserRole(req)}`);

  try {
    // Check blocked URLs first
    const blocked = await BlockedUrl.findOne({ url });
    if (blocked && blocked.status === "malicious") {
      console.log(`🚫 URL is blocked by admin: ${url}`);
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

    // Role-based scan logic
    let userRole = await getUserRole(req);
    let vtResults = { success: false };
    let ipqsResults = { success: false };
    let scamalyticsResults = { success: false };
    
    if (userRole === "premium" || userRole === "admin") {
      console.log(`🎯 Premium user - running all scanners...`);
      
      // Run all scans in parallel with individual error handling
      const scanPromises = [
        // VirusTotal scan
        (async () => {
          try {
            console.log(`📡 Starting VirusTotal scan...`);
            const scanResponse = await axios.post(
              "https://www.virustotal.com/api/v3/urls",
              new URLSearchParams({ url }),
              {
                headers: {
                  "x-apikey": VIRUSTOTAL_API_KEY,
                  "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout: 15000
              }
            );
            
            const analysisId = scanResponse.data.data.id;
            console.log(`✅ VT scan submitted, analysis ID: ${analysisId}`);
            
            const analysisResults = await fetchAnalysisResults(analysisId);
            const totalSources = Object.keys(analysisResults).length || 1;
            let detectedCount = 0;
            
            Object.values(analysisResults).forEach(engine => {
              if (engine.category === "malicious" || engine.category === "suspicious") {
                detectedCount++;
              }
            });
            const vtRiskScore = Math.round((detectedCount / totalSources) * 100);
            console.log(`✅ VT scan complete. Score: ${vtRiskScore}`);
            
            return {
              total_sources: totalSources,
              malicious_detections: detectedCount,
              risk_score: vtRiskScore,
              success: true
            };
          } catch (error) {
            console.error(`❌ VirusTotal scan failed:`, error.message);
            return { success: false, error: error.message, risk_score: 0 };
          }
        })(),
        
        // IPQS scan
        scanUrlIPQS(url),
        
        // Scamalytics scan
        scanWithScamalytics(url)
      ];
      
      [vtResults, ipqsResults, scamalyticsResults] = await Promise.all(scanPromises);
      
    } else {
      // Standard users: VirusTotal only
      console.log(`📊 Standard user - running VirusTotal only...`);
      
      try {
        const scanResponse = await axios.post(
          "https://www.virustotal.com/api/v3/urls",
          new URLSearchParams({ url }),
          {
            headers: {
              "x-apikey": VIRUSTOTAL_API_KEY,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout: 15000
          }
        );
        
        const analysisId = scanResponse.data.data.id;
        const analysisResults = await fetchAnalysisResults(analysisId);
        const totalSources = Object.keys(analysisResults).length || 1;
        let detectedCount = 0;
        
        Object.values(analysisResults).forEach(engine => {
          if (engine.category === "malicious" || engine.category === "suspicious") {
            detectedCount++;
          }
        });
        
        const vtRiskScore = Math.round((detectedCount / totalSources) * 100);
        
        vtResults = {
          total_sources: totalSources,
          malicious_detections: detectedCount,
          risk_score: vtRiskScore,
          success: true
        };
      } catch (error) {
        console.error(`❌ VirusTotal scan failed:`, error.message);
        vtResults = { success: false, error: error.message, risk_score: 0 };
      }
    }

    // Heuristic Analysis (only used for premium users)
    let heuristicScore = 0;
    let heuristicReasons = [];
    let heuristicVerdict = "N/A";

    if (userRole === "premium" || userRole === "admin") {
      const heuristicStatic = analyzeUrlHeuristically(url);
      const heuristicDynamic = await analyzeDomainAge(url);
      heuristicScore = Math.min(heuristicStatic.score + heuristicDynamic.score, 100);
      heuristicReasons = [...heuristicStatic.reasons];
      if (heuristicDynamic.reason) heuristicReasons.push(heuristicDynamic.reason);
      heuristicVerdict = getVerdictFromScore(heuristicScore, userRole);
    }

    // Extract scores with fallbacks
    const vtScore = vtResults?.risk_score || 0;
    const ipqsScore = ipqsResults?.risk_score || 0;
    const scamalyticsScore = scamalyticsResults?.risk_score || 0;
    
    let customScore;

    if (userRole === "premium" || userRole === "admin") {
      // Premium: all sources
      const weights = {
        vt: vtResults.success ? 0.2 : 0,
        ipqs: ipqsResults.success ? 0.4 : 0,
        scamalytics: scamalyticsResults.success ? 0.1 : 0,
        heuristic: 0.3
      };

      const totalWeight = weights.vt + weights.ipqs + weights.scamalytics + weights.heuristic;
      if (totalWeight > 0) {
        Object.keys(weights).forEach(key => {
          weights[key] = weights[key] / totalWeight;
        });
      }

      customScore = Math.min(
        (vtScore * weights.vt) +
        (ipqsScore * weights.ipqs) +
        (scamalyticsScore * weights.scamalytics) +
        (heuristicScore * weights.heuristic),
        100
      );
    } else {
      // ✅ For standard users, only use VT score
      customScore = vtScore;
    }

    
    const finalScore = Math.round(customScore);
    //userRole = "standard"; // 🔧 Force standard role for testing
    //console.log("🧪 Score Check:", finalScore);    // should print the final score like 19

    const finalVerdict = getVerdictFromScore(finalScore, userRole);


    const successfulAPIs = [
      vtResults.success,
      userRole === "premium" || userRole === "admin" ? ipqsResults?.success : false,
      userRole === "premium" || userRole === "admin" ? scamalyticsResults?.success : false,
      //true // heuristic always succeeds
    ].filter(Boolean).length;

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
      vt_results: vtResults.success ? {
        total_sources: vtResults.total_sources || 0,
        malicious_detections: vtResults.malicious_detections || 0,
        risk_score: vtScore,
      } : null,
      ipqs_results: (userRole === "premium" || userRole === "admin") && ipqsResults.success ? {
        risk_score: ipqsScore,
        is_phishing: ipqsResults?.is_phishing,
        is_malware: ipqsResults?.is_malware,
        is_suspicious: ipqsResults?.is_suspicious,
      } : null,
      scamalytics_results: (userRole === "premium" || userRole === "admin") && scamalyticsResults?.success ? {
        ip: scamalyticsResults.ip,
        risk_score: scamalyticsScore,
        verdict: scamalyticsResults.verdict
      } : null,
      heuristic_analysis: (userRole === "premium" || userRole === "admin") ? {
        score: heuristicScore,
        reasons: heuristicReasons,
        verdict: heuristicVerdict
      } : null,
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
    .replace(/<\/?.*?>/g, '')
    .replace(/["'><)\]]+$/g, '')
    .replace(/^[\["'<(]+/g, '')
    .trim()
    .toLowerCase();
}

// POST /api/scan-eml-file — Scan an email file with attachments
router.post("/scan-eml-file", enforceScanLimit, upload.single("emlFile"), async (req, res) => {
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

    // Scan URLs concurrently
    const userRole = await getUserRole(req);
    console.log(`🔍 Email scan - User role: ${userRole}`);
    
    const urlScanResults = await Promise.all(uniqueUrls.map(async (u) => {
      const blocked = await BlockedUrl.findOne({ url: u });
      if (blocked?.status === "malicious") {
        return {
          url: u,
          vt_results: null,
          ipqs_results: null,
          scamalytics_results: null,
          heuristic_analysis: null,
          aggregated_risk_score: 100,
          verdict: "🔴 Malicious (Blocked by admin)",
          blocked_by_admin: true
        };
      }
      
      let vtRes = { success: false };
      let ipqsRes = { success: false };
      let scamalyticsRes = { success: false };
      
      if (userRole === "premium" || userRole === "admin") {
        console.log(`🎯 Premium user - running all scans for URL: ${u}`);
        // Premium users: run all scans
        [vtRes, ipqsRes, scamalyticsRes] = await Promise.all([
          scanUrlVT(u),
          scanUrlIPQS(u),
          scanWithScamalytics(u)
        ]);
      } else {
        console.log(`📊 Standard user - running VirusTotal only for URL: ${u}`);
        // Standard users: VirusTotal only
        vtRes = await scanUrlVT(u, userRole);
      }
      
      const vtRisk = vtRes?.risk_score || 0;
      const ipqsRisk = ipqsRes?.risk_score || 0;
      const scamalyticsRisk = scamalyticsRes?.risk_score || 0;
      
      let heuristicScore = 0;
      let heuristicReasons = [];
      let heuristicVerdict = "N/A";
      
      // Only run heuristic analysis for premium users
      if (userRole === "premium" || userRole === "admin") {
        const heuristicStatic = analyzeUrlHeuristically(u);
        const heuristicDynamic = await analyzeDomainAge(u);
        heuristicScore = Math.min(heuristicStatic.score + heuristicDynamic.score, 100);
        heuristicReasons = [...heuristicStatic.reasons];
        if (heuristicDynamic.reason) heuristicReasons.push(heuristicDynamic.reason);
        heuristicVerdict = getVerdictFromScore(heuristicScore, userRole);
      }
      
      let finalScore;
      if (userRole === "premium" || userRole === "admin") {
        // Premium: weighted scoring with all sources
        const weights = {
          vt: vtRes.success ? 0.2 : 0,
          ipqs: ipqsRes.success ? 0.4 : 0,
          scamalytics: scamalyticsRes.success ? 0.1 : 0,
          heuristic: 0.3
        };

        const totalWeight = weights.vt + weights.ipqs + weights.scamalytics + weights.heuristic;
        if (totalWeight > 0) {
          Object.keys(weights).forEach(key => weights[key] = weights[key] / totalWeight);
        }

        finalScore = Math.round(
          (vtRisk * weights.vt) +
          (ipqsRisk * weights.ipqs) +
          (scamalyticsRisk * weights.scamalytics) +
          (heuristicScore * weights.heuristic)
        );
      } else {
        // Standard users: VirusTotal score only
        finalScore = vtRisk;
      }
      
      const finalVerdict = getVerdictFromScore(finalScore, userRole);
      
      return {
        url: u,
        vt_results: vtRes.success ? vtRes : null,
        ipqs_results: (userRole === "premium" || userRole === "admin") && ipqsRes.success ? ipqsRes : null,
        scamalytics_results: (userRole === "premium" || userRole === "admin") && scamalyticsRes.success ? scamalyticsRes : null,
        heuristic_analysis: (userRole === "premium" || userRole === "admin") ? {
          score: heuristicScore,
          reasons: heuristicReasons,
          verdict: heuristicVerdict
        } : null,
        aggregated_risk_score: finalScore,
        verdict: finalVerdict
      };
    }));

    // Scan attachments
    const attachments = parsedEmail.attachments || [];
    const attachmentScanResults = [];

    for (const att of attachments) {
      let vtScanRes = { success: false };
      let hybridSubmitRes = { success: false };
      
      if (userRole === "premium" || userRole === "admin") {
        console.log(`🎯 Premium user - running VT + Hybrid Analysis for attachment: ${att.filename}`);
        // Premium users: run both VT and Hybrid Analysis
        [vtScanRes, hybridSubmitRes] = await Promise.all([
          scanFileVT(att.filename, att.content),
          submitFileToHybridAnalysis(att.content, att.filename)
        ]);
      } else {
        console.log(`📊 Standard user - running VirusTotal only for attachment: ${att.filename}`);
        // Standard users: VirusTotal only
        vtScanRes = await scanFileVT(att.filename, att.content);
      }

      let vtRiskScore = 0;
      if (vtScanRes.verdict && vtScanRes.verdict.includes("Malicious")) {
        const detections = parseInt(vtScanRes.verdict.match(/(\d+) detections/)?.[1] || "0");
        vtRiskScore = detections > 0 ? Math.min(100, detections * 10) : 0;
      }

      let hybridResults = { success: false, risk_score: 0 };
      if (userRole === "premium" || userRole === "admin") {
        if (hybridSubmitRes.success && hybridSubmitRes.sha256) {
          hybridResults = await getHybridAnalysisResults(hybridSubmitRes.sha256);
        }
      }

      const hybridRiskScore = hybridResults.success ? hybridResults.risk_score : 0;
      const aggregatedScore = userRole === "premium" || userRole === "admin" 
        ? calculateFileRiskScore(vtRiskScore, hybridRiskScore)
        : vtRiskScore; // Standard users: VT score only
      const aggregatedVerdict = getVerdictFromScore(aggregatedScore, userRole);

      attachmentScanResults.push({
        filename: att.filename,
        vt_results: vtScanRes,
        hybrid_analysis_results: (userRole === "premium" || userRole === "admin") && hybridResults.success ? hybridResults : null,
        aggregated_risk_score: aggregatedScore,
        verdict: aggregatedVerdict
      });
    }

    const rawHeaders = parsedEmail.headerLines.map(h => h.line).join("\r\n");
    const senderEmail = parsedEmail.from?.value?.[0]?.address || "";

    let emailHeaderScanResult = null;
    let heuristicResult = null;
    
    if (userRole === "premium" || userRole === "admin") {
      console.log(`🎯 Premium user - running header analysis`);
      // Premium users: run header analysis
      if (senderEmail) {
        emailHeaderScanResult = await scanEmailHeaderWithIPQS(senderEmail);
      }

      const headersObject = {};
      for (const [key, value] of parsedEmail.headers) {
        headersObject[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
      }

      heuristicResult = analyzeHeadersHeuristically(headersObject);
    } else {
      console.log(`📊 Standard user - skipping header analysis`);
    }

    const headerFinalVerdict = userRole === "premium" || userRole === "admin"
      ? calculateEmailHeaderVerdict(
          heuristicResult?.score || 0,
          emailHeaderScanResult?.fraud_score || 0
        )
      : "N/A";

    const finalVerdictSummary = generateEmailScanFinalVerdict({
      headerHeuristicScore: (userRole === "premium" || userRole === "admin") ? (heuristicResult?.score || 0) : 0,
      headerIPQSFraudScore: (userRole === "premium" || userRole === "admin") ? (emailHeaderScanResult?.fraud_score || 0) : 0,
      urlScanResults,
      attachmentScanResults,
      userRole
    });

    console.log(`🎯 Final verdict for ${userRole} user: ${finalVerdictSummary.final_verdict}`);
    console.log(`📊 Verdict summary: ${finalVerdictSummary.summary}`);

    res.json({
      emailBody: parsedEmail.text || parsedEmail.html || "",
      urlScanResults: urlScanResults.map(result => ({
        ...result,
        heuristic_analysis: (userRole === "premium" || userRole === "admin") ? result.heuristic_analysis : null,
        ipqs_results: (userRole === "premium" || userRole === "admin") ? result.ipqs_results : null,
        scamalytics_results: (userRole === "premium" || userRole === "admin") ? result.scamalytics_results : null
      })),
      attachmentScanResults,
      emailHeaderScanResult: (userRole === "premium" || userRole === "admin") ? emailHeaderScanResult : null,
      heuristicResult: (userRole === "premium" || userRole === "admin") ? heuristicResult : null,
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

// Helper: Get user role from session or request
async function getUserRole(req) {
  if (req.session && req.session.user) {
    console.log(`🔍 User role from session: ${req.session.user.role}`);
    return req.session.user.role;
  }
  // Optionally, allow passing userId in body for API clients
  if (req.body && req.body.userId) {
    const user = await User.findById(req.body.userId);
    console.log(`🔍 User role from userId: ${user?.role || "standard"}`);
    return user?.role || "standard";
  }
  console.log(`🔍 No user found, defaulting to standard`);
  return "standard";
}

module.exports = router;