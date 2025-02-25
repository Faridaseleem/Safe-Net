import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom"; // Import for navigation
import "./ScanURL.css";
import logo from "../assets/logo.png";
import html2canvas from "html2canvas";

const Scan = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const reportRef = useRef(null);
  const navigate = useNavigate(); // Hook for navigation

  const handleScan = async () => {
    if (!url) return alert("Please enter a URL to scan.");
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch("http://localhost:5000/api/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();
      setResult({ ...data, timestamp: new Date().toLocaleString() });
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
      });
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

      {result && (
        <div ref={reportRef} className="scan-result">
          <h3>📄 Scan Report</h3>
          <p><strong>🔗 URL:</strong> {result.url}</p>
          <p><strong>🕒 Scan Time:</strong> {result.timestamp}</p>
          <p><strong>📊 Total Sources Checked:</strong> {result.total_sources}</p>
          <p><strong>🚨 Malicious Detections:</strong> {result.malicious_detections}</p>
          {/*<p><strong>📈 Detection Percentage:</strong> {result.detection_percentage}</p>*/}
          <p><strong>⚠️ Final Verdict:</strong> {result.verdict}</p> <br></br>

          {/* Learn More Button for Education Page */}
          <button className="learn-more-btn" onClick={() => navigate("/education")}>
            📖 Learn More About Phishing Protection
          </button>

          <button className="download-btn" onClick={downloadReport} disabled={!result}>
            📥 Download Report (Image)
          </button>
        </div>
      )}
    </div>
  );
};

export default Scan;
