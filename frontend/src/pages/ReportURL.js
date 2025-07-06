import React, { useState } from "react";
import { useUser } from "../contexts/UserContext";
import "./ReportURL.css";

const ReportURL = () => {
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(false);

  const { user } = useUser(); 
  
  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!url) {
      setMessage({ type: "error", text: "Please enter a URL to report." });
      return;
    }

    setLoading(true);
    setMessage(null);

    try {
      const res = await fetch("https://localhost:5000/api/report-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          reportedBy: user?.email || "anonymous",  
        }),
          credentials: "include" 
        });

      const data = await res.json();

      if (res.ok) {
        setMessage({ type: "success", text: "URL reported successfully. Thank you!" });
        setUrl("");
      } else {
        setMessage({ type: "error", text: data.error || "Failed to report URL." });
      }
    } catch (err) {
      setMessage({ type: "error", text: "Network error. Please try again." });
    }

    setLoading(false);
  };

  return (
    <div className="report-container">
      <h2>Report a Malicious URL</h2>
      <form onSubmit={handleSubmit} className="report-form">
        <input
          type="text"
          placeholder="Enter suspicious URL..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={loading}
        />
        <button type="submit" disabled={loading}>
          {loading ? "Reporting..." : "Report URL"}
        </button>
      </form>

      {message && (
        <p className={`message ${message.type === "error" ? "error" : "success"}`}>
          {message.text}
        </p>
      )}
    </div>
  );
};

export default ReportURL;
