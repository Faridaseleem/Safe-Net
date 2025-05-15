const mongoose = require("mongoose");

const BlockedUrlSchema = new mongoose.Schema({
  url: { type: String, required: true, unique: true },
  reportedBy: { type: String }, // user id or username who reported (optional)
  status: {
    type: String,
    enum: ["pending", "malicious", "safe"],
    default: "pending",
  },
  reportedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("BlockedUrl", BlockedUrlSchema);
