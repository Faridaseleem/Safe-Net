import React, { useEffect, useState } from "react";

const AdminReportUrls = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchReports = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("https://localhost:5000/api/admin/reported-urls");
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
      const res = await fetch(`https://localhost:5000/api/admin/reported-urls/${id}/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision }),
      });
      if (!res.ok) throw new Error("Failed to update decision");
      await fetchReports();
    } catch (err) {
      alert(err.message);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  if (loading) return <p>Loading reports...</p>;
  if (error) return <p style={{ color: "red" }}>Error: {error}</p>;

  return (
    <div style={{ padding: 20 }}>
      <h2>Admin: Manage Reported URLs</h2>
      {reports.length === 0 && <p>No reports found.</p>}
      <table border="1" cellPadding={8} style={{ width: "100%", borderCollapse: "collapse" }}>
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
              <td><a href={url} target="_blank" rel="noreferrer">{url}</a></td>
              <td>{reportedBy || "anonymous"}</td>
              <td>{status}</td>
              <td>{new Date(reportedAt).toLocaleString()}</td>
              <td>
                {status !== "malicious" && (
                  <button onClick={() => updateDecision(_id, "malicious")}>Mark Malicious</button>
                )}
                {status !== "safe" && (
                  <button onClick={() => updateDecision(_id, "safe")} style={{ marginLeft: 8 }}>
                    Mark Safe
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default AdminReportUrls;
