const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const scanRoutes = require("./routes/scanRoutes");
const authRoutes = require('./routes/auth');

dotenv.config();



const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// Routes
app.use("/api", scanRoutes);
app.use('/api/auth', authRoutes);

// Start server
app.listen(PORT, () => {
    console.log(`✅ Server is running on http://localhost:${PORT}`);
});

app.get("/", (req, res) => {
    res.send("Server is running!");
  });
  
  app.use((req, res) => {
    res.status(404).send("404 Not Found - Invalid Route");
  });
  




