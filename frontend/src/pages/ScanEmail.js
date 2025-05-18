import React, { useState, useRef } from "react";
import html2canvas from "html2canvas";
import { useNavigate } from "react-router-dom";

const ScanEmail = () => {
  const navigate = useNavigate();
  const [emailBody, setEmailBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState("");
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const reportRef = useRef(null);

  // URL detail toggles
  const [showVTDetails, setShowVTDetails] = useState(false);
  const [showIPQSDetails, setShowIPQSDetails] = useState(false);
  const [showScamalyticsDetails, setShowScamalyticsDetails] = useState(false);
  const [showHeaderDetails, setShowHeaderDetails] = useState(false);
  
  // NEW: Attachment detail toggles - using separate objects to track per attachment
  const [showAttachmentVTDetails, setShowAttachmentVTDetails] = useState({});
  const [showAttachmentHybridDetails, setShowAttachmentHybridDetails] = useState({});

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
    setError(null);
    setShowVTDetails(false);
    setShowIPQSDetails(false);
    setShowScamalyticsDetails(false);
    setShowHeaderDetails(false);
    setShowAttachmentVTDetails({});
    setShowAttachmentHybridDetails({});

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
        setEmailBody(data.emailBody || "");
        setScanResults(data);
        setFileName(file.name);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  };

  const downloadReport = () => {
    if (!reportRef.current) return;

    // Save current states
    const prevVT = showVTDetails;
    const prevIPQS = showIPQSDetails;
    const prevScamalytics = showScamalyticsDetails;
    const prevHeader = showHeaderDetails;
    const prevAttVT = {...showAttachmentVTDetails};
    const prevAttHybrid = {...showAttachmentHybridDetails};
    
    // Hide all details for clean screenshot
    setShowVTDetails(false);
    setShowIPQSDetails(false);
    setShowScamalyticsDetails(false);
    setShowHeaderDetails(false);
    setShowAttachmentVTDetails({});
    setShowAttachmentHybridDetails({});

    setTimeout(() => {
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

          // Restore states
          setShowVTDetails(prevVT);
          setShowIPQSDetails(prevIPQS);
          setShowScamalyticsDetails(prevScamalytics);
          setShowHeaderDetails(prevHeader);
          setShowAttachmentVTDetails(prevAttVT);
          setShowAttachmentHybridDetails(prevAttHybrid);
        })
        .catch((err) => {
          console.error("html2canvas error:", err);
          // Restore states on error too
          setShowVTDetails(prevVT);
          setShowIPQSDetails(prevIPQS);
          setShowScamalyticsDetails(prevScamalytics);
          setShowHeaderDetails(prevHeader);
          setShowAttachmentVTDetails(prevAttVT);
          setShowAttachmentHybridDetails(prevAttHybrid);
        });
    }, 100);
  };

  // Toggle handlers for attachment details
  const toggleAttachmentVTDetails = (idx) => {
    setShowAttachmentVTDetails(prev => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };
  
  const toggleAttachmentHybridDetails = (idx) => {
    setShowAttachmentHybridDetails(prev => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  // Improved final verdict prioritizing highest risk found
  const finalVerdict = (() => {
    const urlVerdicts = scanResults?.urlScanResults?.map((u) => u.verdict) || [];
    const attVerdicts = scanResults?.attachmentScanResults?.map((a) => a.verdict) || [];
    const allVerdicts = [...urlVerdicts, ...attVerdicts].filter(Boolean).map(v => v.toLowerCase());

    if (allVerdicts.some(v => v.includes("high risk") || v.includes("malicious"))) {
      return "🔴 High Risk (Likely Malicious)";
    }
    if (allVerdicts.some(v => v.includes("medium risk"))) {
      return "🟠 Medium Risk (Potentially Unsafe)";
    }
    if (allVerdicts.some(v => v.includes("low risk"))) {
      return "🟡 Low Risk (Exercise Caution)";
    }
    if (allVerdicts.some(v => v.includes("clean") || v.includes("no threat"))) {
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
      {error && <p style={{ color: "red" }}>{error}</p>}

      {emailBody && (
        <section className="email-preview" aria-label="Email body preview">
          <h4>Email Body Preview:</h4>
          <pre style={{ whiteSpace: "pre-wrap" }}>{emailBody}</pre>
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
            <div>
              <strong>🕒 Scan Time:</strong> {new Date().toLocaleString()}
            </div>
            <div>
              <strong>📊 Total Attachments:</strong> {scanResults.attachmentScanResults?.length || 0}
            </div>
            <div>
              <strong>🔗 URLs:</strong>
              {scanResults.urlScanResults?.length > 0 ? (
                <ul className="summary-url-list">
                  {scanResults.urlScanResults.map((urlObj) => (
                    <li key={urlObj.url}>{urlObj.url}</li>
                  ))}
                </ul>
              ) : (
                " None"
              )}
            </div>

            {/* Email Header Scan Section */}
            {scanResults.emailHeaderScanResult && (
              <>
                <button
                  className={`details-toggle ${showHeaderDetails ? "active" : ""}`}
                  onClick={() => setShowHeaderDetails(!showHeaderDetails)}
                >
                  {showHeaderDetails ? "🔼 Hide Header Scan" : "🔽 Show Header Scan"}
                </button>
                {showHeaderDetails && (
                  <div className="api-details header-details">
                    <h4>Email Header Scan Results</h4>
                    <p><strong>Sender:</strong> {scanResults.emailHeaderScanResult.sanitized_email || "Unknown"}</p>
                    <p><strong>Deliverability:</strong> {scanResults.emailHeaderScanResult.deliverability || "N/A"}</p>
                    <p><strong>Spam Trap Score:</strong> {scanResults.emailHeaderScanResult.spam_trap_score || "N/A"}</p>
                    <p><strong>Suspicious:</strong> {scanResults.emailHeaderScanResult.suspect ? "Yes" : "No"}</p>
                    <p><strong>Fraud Score:</strong> {scanResults.emailHeaderScanResult.fraud_score ?? "N/A"}</p>
                    <p><strong>Verdict:</strong> {scanResults.emailHeaderScanResult.mapped_verdict || "N/A"}</p>
                  </div>
                )}
              </>
            )}

            <div>
              <strong>⚠️ Final Verdict: </strong> {finalVerdict}
            </div>

            <hr style={{ margin: "15px 0", borderColor: "#4b538b" }} />

            <h4>URL Scan Results:</h4>
            <ul>
              {scanResults.urlScanResults.map((res, idx) => (
                <li key={idx} style={{ marginBottom: 16 }}>
                  <strong>{res.url}</strong>:<br />
                  <div>Aggregated Verdict: {res.verdict}</div>
                  <div>Aggregated Risk Score: {res.aggregated_risk_score}</div>

                  <div className="details-buttons">
                    {res.vt_results && (
                      <button
                        className={`details-toggle ${showVTDetails ? "active" : ""}`}
                        onClick={() => setShowVTDetails(!showVTDetails)}
                      >
                        {showVTDetails ? "🔼 Hide VirusTotal Details" : "🔽 Show VirusTotal Details"}
                      </button>
                    )}

                    {res.ipqs_results && (
                      <button
                        className={`details-toggle ${showIPQSDetails ? "active" : ""}`}
                        onClick={() => setShowIPQSDetails(!showIPQSDetails)}
                      >
                        {showIPQSDetails ? "🔼 Hide IPQS Details" : "🔽 Show IPQS Details"}
                      </button>
                    )}
                    
                    {res.scamalytics_results && (
                      <button
                        className={`details-toggle ${showScamalyticsDetails ? "active" : ""}`}
                        onClick={() => setShowScamalyticsDetails(!showScamalyticsDetails)}
                      >
                        {showScamalyticsDetails ? "🔼 Hide Scamalytics Details" : "🔽 Show Scamalytics Details"}
                      </button>
                    )}
                  </div>

                  {showVTDetails && res.vt_results && (
                    <div className="api-details vt-details">
                      <h4>VirusTotal Results</h4>
                      <p><strong>Total Sources:</strong> {res.vt_results.total_sources}</p>
                      <p><strong>Malicious Detections:</strong> {res.vt_results.malicious_detections}</p>
                      <p><strong>Risk Score:</strong> {Math.round(res.vt_results.risk_score)}/100</p>
                    </div>
                  )}

                  {showIPQSDetails && res.ipqs_results && (
                    <div className="api-details ipqs-details">
                      <h4>IPQS Results</h4>
                      <p><strong>Risk Score:</strong> {res.ipqs_results.risk_score}/100</p>
                      <p><strong>Phishing:</strong> {res.ipqs_results.is_phishing ? "Yes" : "No"}</p>
                      <p><strong>Malware:</strong> {res.ipqs_results.is_malware ? "Yes" : "No"}</p>
                      <p><strong>Suspicious:</strong> {res.ipqs_results.is_suspicious ? "Yes" : "No"}</p>
                      <p><strong>Verdict:</strong> {res.ipqs_results.verdict}</p>
                    </div>
                  )}
                  
                  {showScamalyticsDetails && res.scamalytics_results && (
                    <div className="api-details scamalytics-details">
                      <h4>Scamalytics Results</h4>
                      <p><strong>IP Address:</strong> {res.scamalytics_results.ip}</p>
                      <p><strong>Risk Score:</strong> {res.scamalytics_results.risk_score}/100</p>
                      <p><strong>Verdict:</strong> {res.scamalytics_results.verdict}</p>
                    </div>
                  )}
                </li>
              ))}
            </ul>

            <h4>Attachment Scan Results:</h4>
            {scanResults.attachmentScanResults?.length === 0 && (
              <p>No attachments found or scanned.</p>
            )}
            <ul className="attachment-results-list">
              {scanResults.attachmentScanResults?.map((att, idx) => (
                <li key={idx} className="attachment-item">
                  <div className="attachment-header">
                    <strong>{att.filename}</strong>
                    {att.error ? (
                      <span style={{ color: "red" }}>Error: {att.error}</span>
                    ) : (
                      <div className="attachment-summary">
                        <div><strong>Verdict:</strong> {att.verdict || "Pending"}</div>
                        {att.aggregated_risk_score !== undefined && (
                          <div><strong>Risk Score:</strong> {att.aggregated_risk_score}/100</div>
                        )}
                      </div>
                    )}
                  </div>

                  {!att.error && (
                    <div className="details-buttons">
                      {/* VirusTotal Details Button */}
                      {att.vt_results && (
                        <button
                          className={`details-toggle ${showAttachmentVTDetails[idx] ? "active" : ""}`}
                          onClick={() => toggleAttachmentVTDetails(idx)}
                        >
                          {showAttachmentVTDetails[idx] ? "🔼 Hide VirusTotal Details" : "🔽 Show VirusTotal Details"}
                        </button>
                      )}
                      
                      {/* Hybrid Analysis Details Button */}
                      {att.hybrid_analysis_results && (
                        <button
                          className={`details-toggle ${showAttachmentHybridDetails[idx] ? "active" : ""}`}
                          onClick={() => toggleAttachmentHybridDetails(idx)}
                        >
                          {showAttachmentHybridDetails[idx] ? "🔼 Hide Hybrid Analysis Details" : "🔽 Show Hybrid Analysis Details"}
                        </button>
                      )}
                    </div>
                  )}

                  {/* VirusTotal Details Panel */}
                  {showAttachmentVTDetails[idx] && att.vt_results && (
                    <div className="api-details vt-details">
                      <h4>VirusTotal Results</h4>
                      <p><strong>Verdict:</strong> {att.vt_results.verdict}</p>
                      {att.vt_results.scan_id && (
                        <p><strong>Scan ID:</strong> {att.vt_results.scan_id}</p>
                      )}
                      {att.vt_results.note && (
                        <p><strong>Note:</strong> {att.vt_results.note}</p>
                      )}
                    </div>
                  )}
                  
                  {/* Hybrid Analysis Details Panel */}
                  {showAttachmentHybridDetails[idx] && att.hybrid_analysis_results && (
                    <div className="api-details hybrid-details">
                      <h4>Hybrid Analysis Results</h4>
                      <p><strong>Risk Score:</strong> {att.hybrid_analysis_results.risk_score}/100</p>
                      <p><strong>Verdict:</strong> {att.hybrid_analysis_results.verdict}</p>
                      
                      {att.hybrid_analysis_results.malware_family !== "None detected" && (
                        <p><strong>Malware Family:</strong> {att.hybrid_analysis_results.malware_family}</p>
                      )}
                      
                      {att.hybrid_analysis_results.threat_level && (
                        <p><strong>Threat Level:</strong> {att.hybrid_analysis_results.threat_level}</p>
                      )}
                      
                      {att.hybrid_analysis_results.analysis_url && (
                        <p>
                          <a 
                            href={att.hybrid_analysis_results.analysis_url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="analysis-link"
                          >
                            View Full Analysis Report
                          </a>
                        </p>
                      )}
                    </div>
                  )}
                </li>
              ))}
            </ul>

            <button
              type="button"
              className="learn-more-btn"
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