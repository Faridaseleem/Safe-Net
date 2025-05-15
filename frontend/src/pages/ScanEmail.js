import React, { useState, useRef } from "react";
import html2canvas from "html2canvas";
import { useNavigate } from "react-router-dom";

const ScanEmail = () => {
  const navigate = useNavigate();
  const [emailBody, setEmailBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState("");
  const [scanResults, setScanResults] = useState(null);
  const reportRef = useRef(null);

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
        if (data.emailBody) setEmailBody(data.emailBody);
        setScanResults(data);
        setFileName(file.name);
        setLoading(false);
      })
      .catch((err) => {
        alert("Error scanning file: " + err.message);
        setLoading(false);
      });
  };

  const downloadReport = () => {
    if (!reportRef.current) {
      console.error("Scan report element not found!");
      return;
    }

    html2canvas(reportRef.current, {
      backgroundColor: "#121629",
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

  const formatScanTime = () => {
    const now = new Date();
    return now.toLocaleString();
  };

  const totalAttachments = scanResults?.attachmentScanResults?.length || 0;
  const totalURLs = scanResults?.urlScanResults?.length || 0;
  const totalMalicious =
    (scanResults?.urlScanResults?.reduce(
      (sum, u) => sum + (u.malicious_detections || 0),
      0
    ) || 0) +
    (scanResults?.attachmentScanResults?.reduce(
      (sum, a) => sum + (a.malicious_detections || 0),
      0
    ) || 0);

  const finalVerdict = (() => {
    const urlVerdicts = scanResults?.urlScanResults?.map((u) => u.verdict) || [];
    const attVerdicts =
      scanResults?.attachmentScanResults?.map((a) => a.verdict) || [];
    const allVerdicts = [...urlVerdicts, ...attVerdicts];
    if (
      allVerdicts.some(
        (v) =>
          v &&
          (v.toLowerCase().includes("high risk") ||
            v.toLowerCase().includes("malicious"))
      )
    ) {
      return "🔴 High Risk (Likely Malicious)";
    }
    if (
      allVerdicts.some(
        (v) =>
          v &&
          (v.toLowerCase().includes("clean") ||
            v.toLowerCase().includes("no threat"))
      )
    ) {
      return "🟢 Clean";
    }
    return "⚪ Unknown";
  })();

  return (
    <div className="scan-container">
      <h2 className="scan-title">Scan an Email</h2>
      <p className="scan-tagline" aria-live="polite">
        📧 Scan your email to detect phishing and malicious content!
      </p>

      <div className="file-upload-wrapper">
        <input
          type="file"
          accept=".eml"
          onChange={handleFileUpload}
          aria-label="Upload .eml email file"
          disabled={loading}
          className="file-input"
        />
        <button disabled={loading || !fileName} className="scan-btn">
          {loading ? "Scanning..." : "Scan Now"}
        </button>
      </div>

      {fileName && <p className="uploaded-file">Selected file: {fileName}</p>}

      {emailBody && (
        <section className="email-preview" aria-label="Email body preview">
          <h4>Email Body Preview:</h4>
          <p>{emailBody}</p>
        </section>
      )}

      {scanResults && (
        <div className="scan-result-wrapper">
          <section
            ref={reportRef}
            className="scan-result"
            tabIndex={-1}
            aria-live="polite"
            aria-atomic="true"
          >
            <h3>📄 Scan Report</h3>
            <div><strong>🕒 Scan Time:</strong> {formatScanTime()}</div>
            <div><strong>📊 Total Attachments:</strong>{totalAttachments}</div>
            <div>
              <strong>🔗 URLs:</strong>{" "}
              {totalURLs > 0 ? (
                <ul className="summary-url-list">
                  {scanResults.urlScanResults.map((url, i) => (
                    <li key={i}>{url.url}</li>
                  ))}
                </ul>
              ) : (
                "None"
              )}
            </div>
            <div><strong>⚠️ Final Verdict: </strong>{finalVerdict}</div>

            <hr style={{ margin: "15px 0", borderColor: "#4b538b" }} />

            {totalURLs > 0 ? (
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
                        </>
                      )}
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p>No URLs found or scanned.</p>
            )}

            {scanResults.attachmentScanResults &&
            scanResults.attachmentScanResults.length > 0 ? (
              <>
                <h4>Attachment Scan Results:</h4>
                <ul>
                  {scanResults.attachmentScanResults.map((att, idx) => (
                    <li key={idx} style={{ marginBottom: 12 }}>
                      <strong>{att.filename}</strong>:{" "}
                      {att.error ? (
                        <span style={{ color: "red" }}>Error: {att.error}</span>
                      ) : (
                        <span>
                          {att.verdict ||
                            "Scan submitted, check VirusTotal dashboard for results."}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p>No attachments found or scanned.</p>
            )}

            {/* Learn More button AFTER attachments */}
            <button
              type="button"
              className="action-btn"
              onClick={() => navigate("/education")}
              aria-label="Learn More About Phishing Protection"
            >
              📖 Learn More About Phishing Protection
            </button>
          </section>

          <button
            onClick={downloadReport}
            disabled={loading}
            className="download-btn"
            aria-disabled={loading}
          >
            📥 Download Report (Image)
          </button>
        </div>
      )}
    </div>
  );
};

export default ScanEmail;
