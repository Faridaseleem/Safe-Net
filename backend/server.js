const fs = require("fs");
const https = require("https");
const path = require("path");
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const scanRoutes = require("./routes/scanRoutes");
const authRoutes = require("./routes/auth");
const reportRoutes = require("./routes/reportRoutes");
const chatbotRoutes = require("./routes/chatbotRoutes");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const askAIRoutes = require("./routes/askAIRoutes");
const telegramBotRoutes = require("./routes/telegramBotRoutes");

dotenv.config();
connectDB();

const app = express();
const PORT = 443;
const HOST = "localhost";

// ✅ Fix Windows file paths using path.resolve
const sslOptions = {
  key: fs.readFileSync(path.resolve(__dirname, "../localhost-key.pem")),
  cert: fs.readFileSync(path.resolve(__dirname, "../localhost.pem")),
};

// CORS setup
app.use(
  cors({
    origin: "https://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());

// ✅ Secure session config
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
      secure: true,
      httpOnly: true,
      sameSite: "Lax",
      maxAge: 10 * 60 * 1000,
    },
  })
);

// Debug route
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
app.use("/api", reportRoutes);
app.use("/api/chatbot", chatbotRoutes);
app.use("/api/telegram", telegramBotRoutes);

// Root route
app.get("/", (req, res) => {
  res.send("✅ Secure HTTPS Server is running with MongoDB!");
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "404 Not Found - Invalid Route" });
});

// ✅ Start HTTPS server
https.createServer(sslOptions, app).listen(PORT, HOST, () => {
  console.log(`🔐 HTTPS Server running at https://${HOST}:${PORT}`);
});
