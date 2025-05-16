import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import "./ScanURL.css";
import logo from "../assets/logo.png";
import html2canvas from "html2canvas";

const Scan = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const reportRef = useRef(null);
  const navigate = useNavigate();
  
  // State to track which details are expanded
  const [showVTDetails, setShowVTDetails] = useState(false);
  const [showIPQSDetails, setShowIPQSDetails] = useState(false);

  const handleScan = async () => {
    if (!url) return alert("Please enter a URL to scan.");
    setLoading(true);
    setResult(null);
    
    // Reset expanded states when starting a new scan
    setShowVTDetails(false);
    setShowIPQSDetails(false);

    try {
      const response = await fetch("http://localhost:5000/api/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();
      setResult({ ...data, timestamp: data.scan_time || new Date().toLocaleString() });
    } catch (error) {
      console.error("Error scanning URL:", error);
      setResult({ error: "Failed to scan URL. Please try again." });
    }

    setLoading(false);
  };

  const downloadReport = () => {
    if (!reportRef.current) {
      console.error("❌ Scan report element not found!");
      return;
    }

    // Hide details before capturing if they're open
    const vtWasOpen = showVTDetails;
    const ipqsWasOpen = showIPQSDetails;
    
    // Close details for clean screenshot
    setShowVTDetails(false);
    setShowIPQSDetails(false);
    
    // Wait for state update to reflect in DOM
    setTimeout(() => {
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
          
          // Restore previous state
          setShowVTDetails(vtWasOpen);
          setShowIPQSDetails(ipqsWasOpen);
        })
        .catch((error) => {
          console.error("❌ html2canvas error:", error);
          // Restore previous state
          setShowVTDetails(vtWasOpen);
          setShowIPQSDetails(ipqsWasOpen);
        });
    }, 100);
  };

  // Calculate number of successful API scans
  const getSuccessfulAPIs = (result) => {
    if (!result) return 0;
    
    let count = 0;
    if (result.vt_results && !result.vt_results.error) count++;
    if (result.ipqs_results && !result.ipqs_results.error) count++;
    return count;
  };

  return (
    <div className="scan-container">
      <h2>Scan a URL</h2>
      <p className="scan-tagline">
        "🔍 Stay Safe, Surf Smart! Scan Your URL Now to Detect Phishing & Threats Instantly! 🛡️"
      </p>
      <input
        type="text"
        placeholder="Enter URL..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />
      <button onClick={handleScan} disabled={loading}>
        {loading ? "Scanning..." : "Scan Now"}
      </button>

      {result && !result.error && (
        <div ref={reportRef} className="scan-result">
          <h3>📄 Scan Report</h3>
          <p><strong>🔗 URL:</strong> {result.url}</p>
          <p><strong>🕒 Scan Time:</strong> {result.timestamp}</p>
          <p><strong>📊 API Sources:</strong> {getSuccessfulAPIs(result)}/2</p>
          <p><strong>🎯 Risk Score:</strong> {result.aggregated_risk_score}/100</p>
          <p><strong>⚠️ Final Verdict:</strong> {result.verdict}</p>

          {/* Detailed results buttons */}
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
          </div>

          {/* Collapsible VirusTotal details */}
          {showVTDetails && result.vt_results && (
            <div className="api-details vt-details">
              <h4>VirusTotal Results</h4>
              <p><strong>Total Sources:</strong> {result.vt_results.total_sources}</p>
              <p><strong>Malicious Detections:</strong> {result.vt_results.malicious_detections}</p>
              <p><strong>Risk Score:</strong> {Math.round(result.vt_results.risk_score)}/100</p>
            </div>
          )}
          
          {/* Collapsible IPQS details */}
          {showIPQSDetails && result.ipqs_results && (
            <div className="api-details ipqs-details">
              <h4>IPQS Results</h4>
              <p><strong>Risk Score:</strong> {result.ipqs_results.risk_score}/100</p>
              <p><strong>Phishing:</strong> {result.ipqs_results.is_phishing ? "Yes" : "No"}</p>
              <p><strong>Malware:</strong> {result.ipqs_results.is_malware ? "Yes" : "No"}</p>
              <p><strong>Suspicious:</strong> {result.ipqs_results.is_suspicious ? "Yes" : "No"}</p>
            </div>
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
        <div className="scan-error">
          <h3>❌ Error</h3>
          <p>{result.error}</p>
        </div>
      )}
    </div>
  );
};

export default Scan;