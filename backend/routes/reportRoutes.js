const express = require("express");
const router = express.Router();
const BlockedUrl = require("../models/BlockedUrl");
const SecureDatabase = require("../utils/secureDatabase"); // Import secure database utility

// User reports a URL
router.post("/report-url", async (req, res) => {
  try {
    const { url, reportedBy } = req.body;

    if (!url) {
      return res.status(400).json({ message: "URL is required" });
    }

    // 🔒 SECURITY: Use secure database method to check if URL already exists
    let blocked = await SecureDatabase.safeFindOne(BlockedUrl, { url });
    
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
        await SecureDatabase.safeSave(blocked);
        return res.json({ message: "URL reported again for re-review." });
      }
    } else {
      // New report
      const newBlockedUrl = new BlockedUrl({
        url,
        reportedBy,
        status: "pending",
      });

      // 🔒 SECURITY: Use secure database method to save new blocked URL
      await SecureDatabase.safeSave(newBlockedUrl);

      res.status(201).json({ 
        message: "URL reported successfully",
        id: newBlockedUrl._id 
      });
    }
  } catch (error) {
    console.error("Report URL Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Admin: get all reported URLs
router.get("/admin/reported-urls", async (req, res) => {
  try {
    // 🔒 SECURITY: Use secure database method to get all reported URLs
    const reports = await SecureDatabase.safeFind(BlockedUrl, {}, { 
      sort: { reportedAt: -1 },
      limit: 100 // Limit results to prevent DoS
    });
    
    res.json(reports);
  } catch (error) {
    console.error("Get Reported URLs Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Admin: decide if URL is malicious or safe
router.post("/admin/reported-urls/:id/decision", async (req, res) => {
  try {
    const { id } = req.params;
    const { decision } = req.body; // expected: "malicious" or "safe"

    if (!decision || !["pending", "malicious", "safe"].includes(decision)) {
      return res.status(400).json({ message: "Valid decision is required" });
    }

    // 🔒 SECURITY: Use secure database method to find URL by ID
    const report = await SecureDatabase.safeFindById(BlockedUrl, id);
    
    if (!report) {
      return res.status(404).json({ message: "Report not found" });
    }

    report.status = decision;
    
    // 🔒 SECURITY: Use secure database method to save updated report
    await SecureDatabase.safeSave(report);

    res.json({ message: "Decision updated successfully", report });
  } catch (error) {
    console.error("Update Decision Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

module.exports = router;
