const express = require("express");
const router = express.Router();
const BlockedUrl = require("../models/BlockedUrl");

// User reports a URL
router.post("/report-url", async (req, res) => {
  const { url, reportedBy } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required." });

  try {
    // Upsert: create new or keep existing pending report
    let blocked = await BlockedUrl.findOne({ url });
    if (blocked) {
      if (blocked.status === "malicious") {
        return res.status(409).json({ error: "URL already blocked as malicious." });
      }
      if (blocked.status === "pending") {
        return res.json({ message: "URL already reported and pending review." });
      }
      if (blocked.status === "safe") {
        // If marked safe but user reports malicious again, set back to pending
        blocked.status = "pending";
        blocked.reportedBy = reportedBy || blocked.reportedBy;
        blocked.reportedAt = Date.now();
        await blocked.save();
        return res.json({ message: "URL reported again for re-review." });
      }
    } else {
      // New report
      blocked = new BlockedUrl({ url, reportedBy });
      await blocked.save();
      return res.json({ message: "URL reported successfully." });
    }
  } catch (err) {
    console.error("Error reporting URL:", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// Admin: get all reported URLs
router.get("/admin/reported-urls", async (req, res) => {
  try {
    const reports = await BlockedUrl.find().sort({ reportedAt: -1 });
    res.json(reports);
  } catch (err) {
    console.error("Error fetching reported URLs:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

// Admin: decide if URL is malicious or safe
router.post("/admin/reported-urls/:id/decision", async (req, res) => {
  const { id } = req.params;
  const { decision } = req.body; // expected: "malicious" or "safe"

  if (!["malicious", "safe"].includes(decision)) {
    return res.status(400).json({ error: "Invalid decision value." });
  }

  try {
    const report = await BlockedUrl.findById(id);
    if (!report) return res.status(404).json({ error: "Report not found." });

    report.status = decision;
    await report.save();

    res.json({ message: `Report marked as ${decision}.` });
  } catch (err) {
    console.error("Error updating decision:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

module.exports = router;
