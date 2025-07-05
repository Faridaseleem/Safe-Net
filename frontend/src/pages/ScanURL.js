import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import "./ScanURL.css";
import logo from "../assets/logo.png";
import html2canvas from "html2canvas";
import axios from 'axios';
import { useEffect } from 'react';
import { useUser } from "../contexts/UserContext";
import ScanCounter from "../components/ScanCounter";

const Scan = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const reportRef = useRef(null);
  const navigate = useNavigate();
  const { user } = useUser();
  
  // State to track which details are expanded
  const [showVTDetails, setShowVTDetails] = useState(false);
  const [showIPQSDetails, setShowIPQSDetails] = useState(false);
  const [showScamalyticsDetails, setShowScamalyticsDetails] = useState(false); // Renamed to Scamalytics
  const [showHeuristicDetails, setShowHeuristicDetails] = useState(false);
  const toggleHeuristicDetails = () => setShowHeuristicDetails(!showHeuristicDetails);


  const handleScan = async () => {
    if (!url) return alert("Please enter a URL to scan.");
    setLoading(true);
    setResult(null);
    
    // Reset expanded states when starting a new scan
    setShowVTDetails(false);
    setShowIPQSDetails(false);
    setShowScamalyticsDetails(false); // Reset Scamalytics state

    try {
      const response = await fetch("https://localhost:5000/api/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        credentials: "include"
      });

      if (response.status === 429) {
        setResult({ error: "You have reached your daily scan limit (10 per day for standard users). Please try again tomorrow or upgrade your plan." });
        setLoading(false);
        return;
      }

      const data = await response.json();
      setResult({ ...data, timestamp: data.scan_time || new Date().toLocaleString() });
      
      // Refresh scan count after successful scan
      await refreshScanCount();
    } catch (error) {
      console.error("Error scanning URL:", error);
      setResult({ error: "Failed to scan URL. Please try again." });
    }

    setLoading(false);
  };

 const downloadReport = async () => {
  if (!reportRef.current) {
    console.error("❌ Scan report element not found!");
    return;
  }

  // Backup previous visibility states
  const prevVT = showVTDetails;
  const prevIPQS = showIPQSDetails;
  const prevScamalytics = showScamalyticsDetails;
  const prevHeuristic = showHeuristicDetails; // 👈 Heuristic

  // Show all details for full screenshot
  setShowVTDetails(true);
  setShowIPQSDetails(true);
  setShowScamalyticsDetails(true);
  setShowHeuristicDetails(true); // 👈 Heuristic

  // Ensure state updates are reflected in the DOM
  await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));

  if (document.fonts) {
    await document.fonts.ready;
  }

  await new Promise((resolve) => setTimeout(resolve, 800));

  html2canvas(reportRef.current, {
    backgroundColor: "#1b1f3b",
    scale: 2,
    useCORS: true,
  })
    .then((canvas) => {
      const link = document.createElement("a");
      link.href = canvas.toDataURL("image/png");
      link.download = "Scan_Report.png";
      link.click();
    })
    .catch((error) => {
      console.error("❌ html2canvas error:", error);
    })
    .finally(() => {
      // Restore previous states
      setShowVTDetails(prevVT);
      setShowIPQSDetails(prevIPQS);
      setShowScamalyticsDetails(prevScamalytics);
      setShowHeuristicDetails(prevHeuristic); // 👈 Heuristic
    });
};



  // Calculate number of successful API scans (updated to include Scamalytics)
  const getSuccessfulAPIs = (result) => {
    if (!result) return 0;
    
    let count = 0;
    if (result.vt_results && !result.vt_results.error) count++;
    if (result.ipqs_results && !result.ipqs_results.error) count++;
    if (result.scamalytics_results) count++; // Check for Scamalytics results
    
    // If we have successful_apis direct from backend, use that instead
    return result.successful_apis || count;
  };

  return (
    <div className="scan-container">
      <h2>Scan a URL</h2>
      <p className="scan-tagline">
        "🔍 Stay Safe, Surf Smart! Scan Your URL Now to Detect Phishing & Threats Instantly! 🛡️"
      </p>
      
      {/* Scan Counter for Standard Users */}
      <ScanCounter />
      
      <input
        type="text"
        placeholder="Enter URL to scan..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        disabled={loading || (result && result.error && result.error.includes('daily scan limit'))}
        className="scan-input"
      />
      <button
        className="scan-btn"
        onClick={handleScan}
        disabled={loading || !url || (result && result.error && result.error.includes('daily scan limit'))}
      >
        {loading ? "Scanning..." : "Scan Now"}
      </button>

      {result && !result.error && (
        <div ref={reportRef} className="scan-result">
          <h3>📄 Scan Report</h3>
          <p><strong>🔗 URL:</strong> {result.url}</p>
          <p><strong>🕒 Scan Time:</strong> {result.timestamp}</p>
          {/* Only show VirusTotal for standard users */}
          {user && user.role === 'standard' ? (
            <>
              <p><strong>API Source:</strong> VirusTotal</p>
              <p><strong>Risk Score:</strong> {result.vt_results ? Math.round(result.vt_results.risk_score) : 'N/A'}/100</p>
              <p><strong>Malicious Detections:</strong> {result.vt_results ? result.vt_results.malicious_detections : 'N/A'}</p>
              <p><strong>⚠️ Final Verdict:</strong> {result.vt_results ? result.vt_results.verdict || result.verdict : result.verdict}</p>
              {/* Show VirusTotal details only */}
              {result.vt_results && (
                <button 
                  className={`details-toggle ${showVTDetails ? 'active' : ''}`}
                  onClick={() => setShowVTDetails(!showVTDetails)}
                >
                  {showVTDetails ? '🔼 Hide VirusTotal Details' : '🔽 Show VirusTotal Details'}
                </button>
              )}
              {showVTDetails && result.vt_results && (
                <div className="api-details vt-details">
                  <h4>VirusTotal Results</h4>
                  <p><strong>Total Sources:</strong> {result.vt_results.total_sources}</p>
                  <p><strong>Malicious Detections:</strong> {result.vt_results.malicious_detections}</p>
                  <p><strong>Risk Score:</strong> {Math.round(result.vt_results.risk_score)}/100</p>
                </div>
              )}
            </>
          ) : (
            <>
              <p><strong>📊 API Sources:</strong> {getSuccessfulAPIs(result)}/3</p>
              <p><strong>🎯 Risk Score:</strong> {result.aggregated_risk_score}/100</p>
              <p><strong>⚠️ Final Verdict:</strong> {result.verdict}</p>
              {/* Detailed results buttons and details for premium/admin */}
              <div className="details-buttons">
                {result.vt_results && (
                  <button 
                    className={`details-toggle ${showVTDetails ? 'active' : ''}`}
                    onClick={() => setShowVTDetails(!showVTDetails)}
                  >
                    {showVTDetails ? '🔼 Hide VirusTotal Details' : '🔽 Show VirusTotal Details'}
                  </button>
                )}
                {result.ipqs_results && (
                  <button 
                    className={`details-toggle ${showIPQSDetails ? 'active' : ''}`}
                    onClick={() => setShowIPQSDetails(!showIPQSDetails)}
                  >
                    {showIPQSDetails ? '🔼 Hide IPQS Details' : '🔽 Show IPQS Details'}
                  </button>
                )}
                {result.scamalytics_results && (
                  <button 
                    className={`details-toggle ${showScamalyticsDetails ? 'active' : ''}`}
                    onClick={() => setShowScamalyticsDetails(!showScamalyticsDetails)}
                  >
                    {showScamalyticsDetails ? '🔼 Hide Scamalytics Details' : '🔽 Show Scamalytics Details'}
                  </button>
                )}
                {result.heuristic_analysis && (
                  <button 
                    className={`details-toggle ${showHeuristicDetails ? 'active' : ''}`}
                    onClick={() => setShowHeuristicDetails(!showHeuristicDetails)}
                  >
                    {showHeuristicDetails ? '🔼 Hide Heuristic Details' : '🔽 Show Heuristic Details'}
                  </button>
                )}
              </div>
              {/* Collapsible details for premium/admin */}
              {showVTDetails && result.vt_results && (
                <div className="api-details vt-details">
                  <h4>VirusTotal Results</h4>
                  <p><strong>Total Sources:</strong> {result.vt_results.total_sources}</p>
                  <p><strong>Malicious Detections:</strong> {result.vt_results.malicious_detections}</p>
                  <p><strong>Risk Score:</strong> {Math.round(result.vt_results.risk_score)}/100</p>
                </div>
              )}
              {showIPQSDetails && result.ipqs_results && (
                <div className="api-details ipqs-details">
                  <h4>IPQS Results</h4>
                  <p><strong>Risk Score:</strong> {result.ipqs_results.risk_score}/100</p>
                  <p><strong>Phishing:</strong> {result.ipqs_results.is_phishing ? "Yes" : "No"}</p>
                  <p><strong>Malware:</strong> {result.ipqs_results.is_malware ? "Yes" : "No"}</p>
                  <p><strong>Suspicious:</strong> {result.ipqs_results.is_suspicious ? "Yes" : "No"}</p>
                </div>
              )}
              {showScamalyticsDetails && result.scamalytics_results && (
                <div className="api-details scamalytics-details">
                  <h4>Scamalytics Results</h4>
                  <p><strong>IP:</strong> {result.scamalytics_results.ip}</p>
                  <p><strong>Risk Score:</strong> {result.scamalytics_results.risk_score}/100</p>
                  <p><strong>Verdict:</strong> {result.scamalytics_results.verdict}</p>
                </div>
              )}
              {showHeuristicDetails && result.heuristic_analysis && (
                <div className="api-details heuristic-details">
                  <h4>Heuristic Analysis</h4>
                  <p><strong>Score:</strong> {result.heuristic_analysis.score}/100</p>
                  <ul>
                    {result.heuristic_analysis.reasons.map((reason, idx) => (
                      <li key={idx}>{reason}</li>
                    ))}
                  </ul>
                  <p><strong>Verdict:</strong> {result.heuristic_analysis.verdict}</p>
                </div>
              )}
            </>
          )}

          {/* Learn More Button for Education Page */}
          <button className="learn-more-btn" onClick={() => navigate("/education")}>
            📖 Learn More About Phishing Protection
          </button>

          <button className="download-btn" onClick={downloadReport} disabled={!result}>
            📥 Download Report (Image)
          </button>
        </div>
      )}

      {result && result.error && (
        <div className="scan-error">{result.error}</div>
      )}
    </div>
  );
};

export default Scan;