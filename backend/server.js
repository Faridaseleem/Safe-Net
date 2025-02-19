const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const connectDB = require("./config/db"); // Import MongoDB connection
const scanRoutes = require("./routes/scanRoutes");
const authRoutes = require("./routes/auth");
const session = require("express-session");
const MongoStore = require("connect-mongo");

dotenv.config();

// Connect to MongoDB
connectDB();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors({
    origin: "http://localhost:3000", // Update based on your frontend URL
    credentials: true
}));

// ✅ Add session middleware
app.use(
    session({
        secret: process.env.SESSION_SECRET || "your_secret_key",  // Use a strong secret key
        resave: false,
        saveUninitialized: false,
        store: MongoStore.create({
            mongoUrl: process.env.MONGO_URI || "mongodb://localhost:27017/safe-net", // Update if needed
            collectionName: "sessions"
        }),
        cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 } // 1 day
    })
);

// Routes
app.use("/api", scanRoutes); // Updated route for better structure
app.use("/api/auth", authRoutes);

// Root Route
app.get("/", (req, res) => {
    res.send("✅ Server is running and connected to MongoDB!");
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ error: "404 Not Found - Invalid Route" });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
