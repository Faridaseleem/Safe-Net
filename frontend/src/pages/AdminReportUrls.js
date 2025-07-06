import React, { useEffect, useState } from "react";
import "./AdminReportURLs.css";

const AdminReportURLs = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchReports = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("https://localhost:5000/api/admin/reported-urls", {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to fetch reports");
      const data = await res.json();
      setReports(data);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  const updateDecision = async (id, decision) => {
    try {
      const res = await fetch(
        `https://localhost:5000/api/admin/reported-urls/${id}/decision`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ decision }),
        }
      );
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || "Failed to update decision");
      }
      await fetchReports(); 
    } catch (err) {
      alert(err.message);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  if (loading) return <p>Loading reports...</p>;
  if (error) return <p className="error">Error: {error}</p>;

  return (
    <div className="admin-report-container">
      <h2>Admin - Manage Reported URLs</h2>
      {reports.length === 0 ? (
        <p>No reports available.</p>
      ) : (
        <table className="admin-report-table">
          <thead>
            <tr>
              <th>URL</th>
              <th>Reported By</th>
              <th>Status</th>
              <th>Reported At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {reports.map(({ _id, url, reportedBy, status, reportedAt }) => (
              <tr key={_id}>
                <td>
                  <a href={url} target="_blank" rel="noreferrer">
                    {url}
                  </a>
                </td>
                <td>{reportedBy || "anonymous"}</td>
                <td className={`status ${status}`}>{status}</td>
                <td>{new Date(reportedAt).toLocaleString()}</td>
                <td>
                  {status !== "malicious" && (
                    <button
                      onClick={() => updateDecision(_id, "malicious")}
                      className="btn btn-danger"
                    >
                      Mark Malicious
                    </button>
                  )}
                  {status !== "safe" && (
                    <button
                      onClick={() => updateDecision(_id, "safe")}
                      className="btn btn-safe"
                    >
                      Mark Safe
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default AdminReportURLs;
