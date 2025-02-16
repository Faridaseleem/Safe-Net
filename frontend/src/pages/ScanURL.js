import React, { useState } from "react";
import "./ScanURL.css";
import logo from "../assets/logo.png";

const Scan = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

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
      setResult(data);
    } catch (error) {
      console.error("Error scanning URL:", error);
      setResult({ error: "Failed to scan URL. Please try again." });
    }

    setLoading(false);
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
        <div className="scan-result">
          <h3>Scan Result</h3>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

export default Scan;
