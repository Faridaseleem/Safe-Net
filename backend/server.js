const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const scanRoutes = require("./routes/scanRoutes");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// Routes
app.use("/api", scanRoutes);

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server is running on http://localhost:${PORT}`);
});
