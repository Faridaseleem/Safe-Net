import React, { useState, useRef } from "react";
import html2canvas from "html2canvas";

const ScanEmail = () => {
  const [emailBody, setEmailBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState("");
  const [scanResults, setScanResults] = useState(null);
  const reportRef = useRef(null);

  // This function is no longer needed for URL extraction on frontend
  // since backend handles URLs + attachments scanning.
  // But you can keep it to preview email body from raw .eml text.
  const parseEML = (raw) => {
    const parts = raw.split(/\r?\n\r?\n/);
    if (parts.length < 2) return { headers: "", body: raw };
    return { headers: parts[0], body: parts.slice(1).join("\n\n") };
  };

  // Handle .eml file upload and send it to backend for scanning
  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".eml")) {
      alert("Please upload a valid .eml file.");
      e.target.value = "";
      return;
    }

    setLoading(true);
    setScanResults(null);
    setEmailBody("");
    setFileName("");

    // Use FormData to upload the full .eml file to your backend
    const formData = new FormData();
    formData.append("emlFile", file);

    fetch("http://localhost:5000/api/scan-eml-file", {
      method: "POST",
      body: formData,
    })
      .then((res) => {
        if (!res.ok) throw new Error("Failed to scan .eml file");
        return res.json();
      })
      .then((data) => {
        // Show email body preview from backend parsed text if available
        if (data.emailBody) setEmailBody(data.emailBody);

        // Set combined scan results for URLs and attachments
        setScanResults(data);
        setFileName(file.name);
        setLoading(false);
      })
      .catch((err) => {
        alert("Error scanning file: " + err.message);
        setLoading(false);
      });
  };

  // Download scan report as PNG image
  const downloadReport = () => {
    if (!reportRef.current) {
      console.error("Scan report element not found!");
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
        link.download = "Email_Scan_Report.png";
        link.click();
      })
      .catch((error) => {
        console.error("html2canvas error:", error);
      });
  };

  return (
    <div className="scan-container" style={{ maxWidth: 800, margin: "auto", padding: 20 }}>
      <h2>Scan .eml Email File for URLs and Attachments</h2>
      <input
        type="file"
        accept=".eml"
        onChange={handleFileUpload}
        aria-label="Upload .eml email file"
        disabled={loading}
        style={{ marginBottom: 12 }}
      />

      {fileName && (
        <p>
          <strong>Uploaded file:</strong> {fileName}
        </p>
      )}

      {loading && (
        <p aria-live="assertive" style={{ color: "#f0ad4e" }}>
          Scanning URLs and Attachments via VirusTotal...
        </p>
      )}

      {emailBody && (
        <section
          className="email-preview"
          style={{
            marginTop: 20,
            whiteSpace: "pre-wrap",
            backgroundColor: "#2a2e4a",
            padding: 15,
            borderRadius: 8,
            maxHeight: 200,
            overflowY: "auto",
            border: "1px solid #444",
          }}
          aria-label="Email body preview"
        >
          <h4>Email Body Preview:</h4>
          <p>{emailBody}</p>
        </section>
      )}

      {scanResults && (
        <section
          ref={reportRef}
          className="scan-result"
          tabIndex={-1}
          style={{ marginTop: 30, backgroundColor: "#121629", padding: 20, borderRadius: 8 }}
          aria-live="polite"
          aria-atomic="true"
        >
          <h3>🛡️ VirusTotal Scan Results</h3>

          {/* URL Scan Results */}
          {scanResults.urlScanResults && scanResults.urlScanResults.length > 0 ? (
            <>
              <h4>URL Scan Results:</h4>
              <ul>
                {scanResults.urlScanResults.map((res, idx) => (
                  <li key={idx} style={{ marginBottom: 16 }}>
                    <strong>{res.url}</strong>:{" "}
                    {res.error ? (
                      <span style={{ color: "#e74c3c" }}>Error: {res.error}</span>
                    ) : (
                      <>
                        <div>Total Sources Checked: {res.total_sources}</div>
                        <div>Malicious Detections: {res.malicious_detections}</div>
                        <div>Verdict: {res.verdict}</div>
                        {res.more_info && (
                          <div>
                            <a
                              href={res.more_info}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ color: "#3498db" }}
                            >
                              Learn More
                            </a>
                          </div>
                        )}
                      </>
                    )}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p>No URLs found or scanned.</p>
          )}

          {/* Attachment Scan Results */}
          {scanResults.attachmentScanResults && scanResults.attachmentScanResults.length > 0 ? (
            <>
              <h4>Attachment Scan Results:</h4>
              <ul>
                {scanResults.attachmentScanResults.map((att, idx) => (
                  <li key={idx} style={{ marginBottom: 12 }}>
                    <strong>{att.filename}</strong>:{" "}
                    {att.error ? (
                      <span style={{ color: "red" }}>Error: {att.error}</span>
                    ) : (
                      <span>{att.verdict || "Scan submitted, check VirusTotal dashboard for results."}</span>
                    )}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p>No attachments found or scanned.</p>
          )}
        </section>
      )}

      {scanResults && (
        <button
          onClick={downloadReport}
          disabled={loading}
          style={{
            marginTop: 15,
            padding: "10px 20px",
            borderRadius: 8,
            cursor: loading ? "not-allowed" : "pointer",
            backgroundColor: loading ? "#777" : "#007bff",
            color: "#fff",
            border: "none",
          }}
          aria-disabled={loading}
        >
          📥 Download Report (Image)
        </button>
      )}
    </div>
  );
};

export default ScanEmail;
