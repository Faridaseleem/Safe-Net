import React, { useState, useRef } from "react";
import html2canvas from "html2canvas";
import axios from 'axios';
import { useEffect } from 'react';
import { useNavigate } from "react-router-dom";
import { useUser } from "../contexts/UserContext";
import ScanCounter from "../components/ScanCounter";

const ScanEmail = () => {
  const navigate = useNavigate();
  const [emailBody, setEmailBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState("");
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const reportRef = useRef(null);
  const { user } = useUser();

  // URL detail toggles
  const [showVTDetails, setShowVTDetails] = useState(false);
  const [showIPQSDetails, setShowIPQSDetails] = useState(false);
  const [showScamalyticsDetails, setShowScamalyticsDetails] = useState(false);
  const [showHeaderDetails, setShowHeaderDetails] = useState(false);
  
  // Attachment detail toggles - track per attachment
  const [showAttachmentVTDetails, setShowAttachmentVTDetails] = useState({});
  const [showAttachmentHybridDetails, setShowAttachmentHybridDetails] = useState({});

  // Heuristic scan toggle
  const [showHeuristicDetails, setShowHeuristicDetails] = useState(false);
  const [showUrlHeuristicDetails, setShowUrlHeuristicDetails] = useState({});
  const toggleUrlHeuristicDetails = (idx) => {
    setShowUrlHeuristicDetails((prev) => ({
      ...prev,
      [idx]: !prev[idx],
    }));
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".eml")) {
      setUploadError("⚠️ Please upload a valid .eml file.");
      e.target.value = "";
      return;
    }

    // Clear error if valid
    setUploadError("");


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
    setShowHeuristicDetails(false);

    const formData = new FormData();
    formData.append("emlFile", file);

    fetch("https://localhost:5000/api/scan-eml-file", {
      method: "POST",
      body: formData,
      credentials: "include"
    })
      .then((res) => {
        if (res.status === 429) {
          setError("You have reached your daily scan limit (10 per day for standard users). Please try again tomorrow or upgrade your plan.");
          setLoading(false);
          setScanResults(null);
          setFileName("");
          return Promise.reject(new Error("quota"));
        }
        if (!res.ok) throw new Error("Failed to scan .eml file");
        return res.json();
      })
      .then((data) => {
        setEmailBody(data.emailBody || "");
        setScanResults(data);
        setFileName(file.name);
        setLoading(false);
        // Refresh scan count after successful scan
        refreshScanCount();
      })
      .catch((err) => {
        if (err.message === "quota") return;
        setError(err.message);
        setLoading(false);
      });
  };

const downloadReport = async () => {
  if (!reportRef.current) return;

  // Backup previous states
  const prevVT = showVTDetails;
  const prevIPQS = showIPQSDetails;
  const prevScamalytics = showScamalyticsDetails;
  const prevHeader = showHeaderDetails;
  const prevAttVT = { ...showAttachmentVTDetails };
  const prevAttHybrid = { ...showAttachmentHybridDetails };
  const prevHeuristic = showHeuristicDetails;

  // Dynamically show all attachments by index
  const attachmentResults = scanResults?.attachmentScanResults || [];
  const vtDetailState = {};
  const hybridDetailState = {};

  attachmentResults.forEach((_, idx) => {
    vtDetailState[idx] = true;
    hybridDetailState[idx] = true;
  });

  // Show all detail sections
  setShowVTDetails(true);
  setShowIPQSDetails(true);
  setShowScamalyticsDetails(true);
  setShowHeaderDetails(true);
  setShowAttachmentVTDetails(vtDetailState);
  setShowAttachmentHybridDetails(hybridDetailState);
  setShowHeuristicDetails(true);

  // Wait for DOM updates
  await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  if (document.fonts) await document.fonts.ready;
  await new Promise((resolve) => setTimeout(resolve, 1000)); // wait for full paint

  // Capture screenshot
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

      // Restore previous states
      setShowVTDetails(prevVT);
      setShowIPQSDetails(prevIPQS);
      setShowScamalyticsDetails(prevScamalytics);
      setShowHeaderDetails(prevHeader);
      setShowAttachmentVTDetails(prevAttVT);
      setShowAttachmentHybridDetails(prevAttHybrid);
      setShowHeuristicDetails(prevHeuristic);
    })
    .catch((err) => {
      console.error("html2canvas error:", err);
      // Restore on error too
      setShowVTDetails(prevVT);
      setShowIPQSDetails(prevIPQS);
      setShowScamalyticsDetails(prevScamalytics);
      setShowHeaderDetails(prevHeader);
      setShowAttachmentVTDetails(prevAttVT);
      setShowAttachmentHybridDetails(prevAttHybrid);
      setShowHeuristicDetails(prevHeuristic);
    });
};


  const toggleAttachmentVTDetails = (idx) => {
    setShowAttachmentVTDetails((prev) => ({
      ...prev,
      [idx]: !prev[idx],
    }));
  };

  const toggleAttachmentHybridDetails = (idx) => {
    setShowAttachmentHybridDetails((prev) => ({
      ...prev,
      [idx]: !prev[idx],
    }));
  };

  const toggleHeuristicDetails = () => {
    setShowHeuristicDetails(!showHeuristicDetails);
  };

  const finalVerdict = scanResults?.finalVerdict || "⚪ Unknown";
  const finalVerdictExplanation = scanResults?.finalVerdictExplanation || "";

  return (
    <div className="scan-container">
      <h2 className="scan-title">Scan an Email</h2>
      <p className="scan-tagline" aria-live="polite">
        📧 Scan your email to detect phishing and malicious content!
      </p>

      {/* Scan Counter for Standard Users */}
      <ScanCounter />

      <div className="file-upload-wrapper">
        <input
          type="file"
          accept=".eml"
          onChange={handleFileUpload}
          aria-label="Upload .eml email file"
          disabled={loading || error?.includes('daily scan limit')}
          className="file-input"
        />
        
        <button disabled={loading || !fileName || error?.includes('daily scan limit')} className="scan-btn">
          {loading ? "Scanning..." : "Scan Now"}
        </button>
      </div>
      {uploadError && <p className="upload-error">{uploadError}</p>}

      {fileName && <p className="uploaded-file">Selected file: {fileName}</p>}
      {error && <p className="scan-error">{error}</p>}

      {emailBody && (
        <section className="email-preview" aria-label="Email body preview">
          <h4>Email Body Preview:</h4>
          <div
            className="email-body-preview"
            style={{
              fontFamily: "'Orbitron', sans-serif",
              fontSize: "0.75rem !important",
              lineHeight: "1.2",
              whiteSpace: "pre-wrap",
              padding: "10px",
              backgroundColor: "rgb(27 31 59 / 42%)",
              borderRadius: "8px",
              border: "1px solid #4b538b",
              maxHeight: "300px",
              overflowY: "auto",
              marginTop: "10px"
            }}
          >
      {emailBody.split(/\r?\n/).map((line, idx) => (
        <p key={idx} className="email-line">{line || <br />}</p>
      ))}

          </div>
        </section>
      )}


      {scanResults && (
        user && user.role === 'standard' ? (
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

            {/* Final Verdict - Moved above Why? section */}
            <div style={{ marginTop: "1rem", marginBottom: "0.5rem" }}>
              <h4 style={{ marginBottom: "0.5rem", color: "#F8F8F2" }}>Final Verdict:</h4>
              <p style={{ fontSize: "1.2rem", fontWeight: "600", color: "#F8F8F2" }}>
                {finalVerdict}
              </p>
            </div>

            {finalVerdictExplanation && (
              <div className="verdict-explanation" style={{ marginTop: "0.5rem", fontSize: "0.85rem", color: "#ccc" }}>
                <strong style={{ fontSize: "1.2rem", fontWeight: "600", color: "#F8F8F2" }}>Why?</strong><br />
                <pre style={{ whiteSpace: "pre-wrap", fontFamily: "monospace" }}>
                  {finalVerdictExplanation}
                </pre>
              </div>
            )}

            {/* Email Header Analysis - Side by Side */}
            {(scanResults.emailHeaderScanResult || scanResults.heuristicResult) && (
              <>
                <hr style={{ margin: "15px 0", borderColor: "#4b538b" }} />
                
                {/* Final Header Verdict */}
                {scanResults.emailHeaderFinalVerdict && (
                  <div style={{ marginBottom: "15px" }}>
                    <h4>Final Header Verdict:</h4>
                    <p style={{ fontSize: "1.1rem", fontWeight: "600", color: "#F8F8F2" }}>
                      {scanResults.emailHeaderFinalVerdict}
                    </p>
                  </div>
                )}

                {/* Buttons */}
                <div style={{ display: "flex", gap: "20px", flexWrap: "wrap", marginBottom: "15px" }}>
                  {scanResults.emailHeaderScanResult && (
                    <button
                      className={`details-toggle ${showHeaderDetails ? "active" : ""}`}
                      onClick={() => setShowHeaderDetails(!showHeaderDetails)}
                    >
                      {showHeaderDetails ? "🔼 Hide Header Scan" : "🔽 Show Header Scan"}
                    </button>
                  )}

                  {scanResults.heuristicResult && (
                    <button
                      className={`details-toggle ${showHeuristicDetails ? "active" : ""}`}
                      onClick={toggleHeuristicDetails}
                    >
                      {showHeuristicDetails ? "🔼 Hide Heuristic Scan" : "🔽 Show Heuristic Scan"}
                    </button>
                  )}
                </div>

                {/* Details Sections */}
                <div style={{ display: "flex", gap: "20px", flexWrap: "wrap" }}>
                  {/* Email Header Scan Results */}
                  {scanResults.emailHeaderScanResult && showHeaderDetails && (
                    <div style={{ flex: "1", minWidth: "300px" }}>
                      <div className="api-details header-details">
                        <p>
                          <strong>Sender:</strong>{" "}
                          {scanResults.emailHeaderScanResult.sanitized_email || "Unknown"}
                        </p>
                        <p>
                          <strong>Data Leak:</strong>{" "}
                          {scanResults.emailHeaderScanResult.leaked ? "Yes" : "No"}
                        </p>
                        <p>
                          <strong>Domain Age:</strong>{" "}
                          {scanResults.emailHeaderScanResult.domain_age?.human || "N/A"}
                        </p>
                        <p>
                          <strong>Fraud Score:</strong>{" "}
                          {scanResults.emailHeaderScanResult.fraud_score ?? "N/A"}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Heuristic Scan */}
                  {scanResults.heuristicResult && showHeuristicDetails && (
                    <div style={{ flex: "1", minWidth: "300px" }}>
                      <div className="api-details heuristic-details">
                        <h4>Heuristic Scan Results</h4>
                        <p>
                          <strong>Suspicious:</strong>{" "}
                          {scanResults.heuristicResult.suspicious ? "Yes" : "No"}
                        </p>
                        <p>
                          <strong>Score:</strong> {scanResults.heuristicResult.score}
                        </p>
                        <p>
                          <strong>Reasons:</strong>
                        </p>
                        <ul style={{ listStyleType: "none", paddingLeft: "0" }}>
                          {scanResults.heuristicResult.reasons.map((reason, idx) => {
                            const [reasonTitle, ...descParts] = reason.split(":");
                            const description = descParts.join(":").trim();
                            return (
                              <li
                                key={idx}
                                style={{
                                  marginBottom: "0.5em",
                                  background: "rgba(255, 255, 255, 0.05)",
                                  padding: "0.4em 0.6em",
                                  borderRadius: "0.25em"
                                }}
                              >
                                <strong style={{ color: "#F8F8F2" }}>{reasonTitle}:</strong>{" "}
                                <span style={{ color: "#D6D6D6" }}>{description}</span>
                              </li>
                            );
                          })}
                        </ul>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}

            {/* URL Scan Results */}
            <hr style={{ margin: "15px 0", borderColor: "#4b538b" }} />
            <h4>URL Scan Results (VirusTotal Only):</h4>
            <ul>
              {scanResults.urlScanResults.map((res, idx) => (
                <li key={idx} style={{ marginBottom: 16 }}>
                  <strong>{res.url}</strong>:<br />
                  <div>Verdict: {res.verdict}</div>
                  <div>Risk Score: {res.aggregated_risk_score}/100</div>

                  <div className="details-buttons">
                    {res.vt_results && (
                      <button
                        className={`details-toggle ${showVTDetails ? "active" : ""}`}
                        onClick={() => setShowVTDetails(!showVTDetails)}
                      >
                        {showVTDetails ? "🔼 Hide VirusTotal Details" : "🔽 Show VirusTotal Details"}
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
                </li>
              ))}
            </ul>

            <h4>Attachment Scan Results (VirusTotal Only):</h4>
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
                      {att.vt_results && (
                        <button
                          className={`details-toggle ${showAttachmentVTDetails[idx] ? "active" : ""}`}
                          onClick={() => toggleAttachmentVTDetails(idx)}
                        >
                          {showAttachmentVTDetails[idx] ? "🔼 Hide VirusTotal Details" : "🔽 Show VirusTotal Details"}
                        </button>
                      )}
                    </div>
                  )}

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
            <button
              onClick={downloadReport}
              disabled={loading}
              className="download-btn"
              aria-disabled={loading}
            >
              📥 Download Report (Image)
            </button>
          </section>
        ) : (
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

            {/* Final Verdict - Moved above Why? section */}
            <div style={{ marginTop: "1rem", marginBottom: "0.5rem" }}>
              <h4 style={{ marginBottom: "0.5rem", color: "#F8F8F2" }}>Final Verdict:</h4>
              <p style={{ fontSize: "1.2rem", fontWeight: "600", color: "#F8F8F2" }}>
                {finalVerdict}
              </p>
            </div>

            {finalVerdictExplanation && (
              <div className="verdict-explanation" style={{ marginTop: "0.5rem", fontSize: "0.85rem", color: "#ccc" }}>
                <strong style={{ fontSize: "1.2rem", fontWeight: "600", color: "#F8F8F2" }}>Why?</strong><br />
                <pre style={{ whiteSpace: "pre-wrap", fontFamily: "monospace" }}>
                  {finalVerdictExplanation}
                </pre>
              </div>
            )}

            {/* Email Header Analysis - Side by Side */}
            {(scanResults.emailHeaderScanResult || scanResults.heuristicResult) && (
              <>
                <hr style={{ margin: "15px 0", borderColor: "#4b538b" }} />
                
                {/* Final Header Verdict */}
                {scanResults.emailHeaderFinalVerdict && (
                  <div style={{ marginBottom: "15px" }}>
                    <h4>Final Header Verdict:</h4>
                    <p style={{ fontSize: "1.1rem", fontWeight: "600", color: "#F8F8F2" }}>
                      {scanResults.emailHeaderFinalVerdict}
                    </p>
                  </div>
                )}

                {/* Buttons */}
                <div style={{ display: "flex", gap: "20px", flexWrap: "wrap", marginBottom: "15px" }}>
                  {scanResults.emailHeaderScanResult && (
                    <button
                      className={`details-toggle ${showHeaderDetails ? "active" : ""}`}
                      onClick={() => setShowHeaderDetails(!showHeaderDetails)}
                    >
                      {showHeaderDetails ? "🔼 Hide Header Scan" : "🔽 Show Header Scan"}
                    </button>
                  )}

                  {scanResults.heuristicResult && (
                    <button
                      className={`details-toggle ${showHeuristicDetails ? "active" : ""}`}
                      onClick={toggleHeuristicDetails}
                    >
                      {showHeuristicDetails ? "🔼 Hide Heuristic Scan" : "🔽 Show Heuristic Scan"}
                    </button>
                  )}
                </div>

                {/* Details Sections */}
                <div style={{ display: "flex", gap: "20px", flexWrap: "wrap" }}>
                  {/* Email Header Scan Results */}
                  {scanResults.emailHeaderScanResult && showHeaderDetails && (
                    <div style={{ flex: "1", minWidth: "300px" }}>
                      <div className="api-details header-details">
                        <p>
                          <strong>Sender:</strong>{" "}
                          {scanResults.emailHeaderScanResult.sanitized_email || "Unknown"}
                        </p>
                        <p>
                          <strong>Data Leak:</strong>{" "}
                          {scanResults.emailHeaderScanResult.leaked ? "Yes" : "No"}
                        </p>
                        <p>
                          <strong>Domain Age:</strong>{" "}
                          {scanResults.emailHeaderScanResult.domain_age?.human || "N/A"}
                        </p>
                        <p>
                          <strong>Fraud Score:</strong>{" "}
                          {scanResults.emailHeaderScanResult.fraud_score ?? "N/A"}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Heuristic Scan */}
                  {scanResults.heuristicResult && showHeuristicDetails && (
                    <div style={{ flex: "1", minWidth: "300px" }}>
                      <div className="api-details heuristic-details">
                        <h4>Heuristic Scan Results</h4>
                        <p>
                          <strong>Suspicious:</strong>{" "}
                          {scanResults.heuristicResult.suspicious ? "Yes" : "No"}
                        </p>
                        <p>
                          <strong>Score:</strong> {scanResults.heuristicResult.score}
                        </p>
                        <p>
                          <strong>Reasons:</strong>
                        </p>
                        <ul style={{ listStyleType: "none", paddingLeft: "0" }}>
                          {scanResults.heuristicResult.reasons.map((reason, idx) => {
                            const [reasonTitle, ...descParts] = reason.split(":");
                            const description = descParts.join(":").trim();
                            return (
                              <li
                                key={idx}
                                style={{
                                  marginBottom: "0.5em",
                                  background: "rgba(255, 255, 255, 0.05)",
                                  padding: "0.4em 0.6em",
                                  borderRadius: "0.25em"
                                }}
                              >
                                <strong style={{ color: "#F8F8F2" }}>{reasonTitle}:</strong>{" "}
                                <span style={{ color: "#D6D6D6" }}>{description}</span>
                              </li>
                            );
                          })}
                        </ul>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}

            {/* URL Scan Results */}
            <hr style={{ margin: "15px 0", borderColor: "#4b538b" }} />
            <h4>URL Scan Results:</h4>
            <ul>
              {scanResults.urlScanResults.map((res, idx) => (
                <li key={idx} style={{ marginBottom: 16 }}>
                  <strong>{res.url}</strong>:<br />
                  {res.heuristic_analysis?.reasons?.includes("URL is blocked by admin") ? (
                    <>
                      <div>Aggregated Verdict: 🔴 Malicious (Blocked by admin)</div>
                      <div>Aggregated Risk Score: 100</div>
                    </>
                  ) : (
                    <>
                      <div>Aggregated Verdict: {res.verdict}</div>
                      <div>Aggregated Risk Score: {res.aggregated_risk_score}</div>
                    </>
                  )}


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
                    {res.heuristic_analysis && (
                    <button
                      className={`details-toggle ${showUrlHeuristicDetails[idx] ? "active" : ""}`}
                      onClick={() => toggleUrlHeuristicDetails(idx)}
                    >
                      {showUrlHeuristicDetails[idx] ? "🔼 Hide Heuristic Details" : "🔽 Show Heuristic Details"}
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
                  {showUrlHeuristicDetails[idx] && res.heuristic_analysis && (
                    <div className="api-details heuristic-details">
                      <h4>Heuristic Analysis</h4>
                      <p><strong>Score:</strong> {res.heuristic_analysis.score}/100</p>
                      <p><strong>Verdict:</strong> {res.heuristic_analysis.verdict}</p>
                      <p><strong>Reasons:</strong></p>
                      <ul style={{ listStyleType: "none", paddingLeft: 0 }}>
                        {res.heuristic_analysis.reasons.map((reason, rIdx) => {
                          const [title, ...descParts] = reason.split(":");
                          return (
                            <li key={rIdx} style={{ background: "#2c2f4a", margin: "4px 0", padding: "6px", borderRadius: "4px" }}>
                              <strong style={{ color: "#F8F8F2" }}>{title}:</strong>{" "}
                              <span style={{ color: "#D6D6D6" }}>{descParts.join(":").trim()}</span>
                            </li>
                          );
                        })}
                      </ul>
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
                      {att.vt_results && (
                        <button
                          className={`details-toggle ${showAttachmentVTDetails[idx] ? "active" : ""}`}
                          onClick={() => toggleAttachmentVTDetails(idx)}
                        >
                          {showAttachmentVTDetails[idx] ? "🔼 Hide VirusTotal Details" : "🔽 Show VirusTotal Details"}
                        </button>
                      )}

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

                    {/* ✅ Bundled Files Section */}
                    {att.hybrid_analysis_results.bundled_files?.length > 0 && (
                      <div className="bundled-files">
                        <h5>🧩 Bundled Files Detected:</h5>
                        <ul>
                          {att.hybrid_analysis_results.bundled_files.map((file, i) => (
                            <li key={i}>
                              <strong>{file.filename}</strong> — 
                              <span style={{ marginLeft: "5px", color: file.threat_level === "malicious" ? "red" : "orange" }}>
                                {file.threat_level}
                              </span>
                              {file.sha256 && (
                                <span style={{ marginLeft: "10px", fontSize: "0.9em", color: "#888" }}>
                                  SHA256: {file.sha256}
                                </span>
                              )}
                            </li>
                          ))}
                        </ul>
                      </div>
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
            <button
              onClick={downloadReport}
              disabled={loading}
              className="download-btn"
              aria-disabled={loading}
            >
              📥 Download Report (Image)
            </button>
          </section>
        )
      )}
    </div>
  );
};

export default ScanEmail;
