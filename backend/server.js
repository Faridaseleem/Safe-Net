const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const scanRoutes = require("./routes/scanRoutes");
const authRoutes = require("./routes/auth");
const reportRoutes = require("./routes/reportRoutes"); // <-- Import reportRoutes
const chatbotRoutes = require("./routes/chatbotRoutes"); // <-- Import chatbotRoutes
const session = require("express-session");
const MongoStore = require("connect-mongo");
const askAIRoutes = require("./routes/askAIRoutes"); // Adjust the path as necessary. 

dotenv.config();
connectDB();

const app = express();
const PORT = process.env.PORT || 5000;

// CORS setup with credentials
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
      stringify: false,
      autoRemove: "interval",
      autoRemoveInterval: 1,
    }),
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "Lax",
      maxAge: 10 * 60 * 1000,
    },
  })
);

// Debug route for session info
app.get("/session-status", (req, res) => {
  res.json({ session: req.session });
});

app.use((req, res, next) => {
  console.log("🔍 Current Session:", req.session);
  next();
});

// Routes

app.use("/api", askAIRoutes);
app.use("/api", scanRoutes);
app.use("/api/auth", authRoutes);
app.use("/api", reportRoutes); // <-- Register report routes
app.use("/api/chatbot", chatbotRoutes); // <-- Register chatbot routes

app.get("/", (req, res) => {
  res.send("✅ Server is running and connected to MongoDB!");
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "404 Not Found - Invalid Route" });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
