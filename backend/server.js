const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const scanRoutes = require("./routes/scanRoutes");
const authRoutes = require("./routes/auth");
const reportRoutes = require("./routes/reportRoutes");
const chatbotRoutes = require("./routes/askAIRoutes");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const askAIRoutes = require("./routes/askAIRoutes");
const telegramBotRoutes = require("./routes/telegramBotRoutes");
const educationRoutes = require("./routes/educationRoutes");
const logRoutes = require("./routes/logRoutes");
const securityMiddleware = require("./middleware/security");
const nosqlInjectionProtection = require("./middleware/nosqlInjectionProtection");

const https = require("https");
const fs = require("fs");

// ✅ Allow self-signed certs in development
if (process.env.NODE_ENV !== "production") {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

dotenv.config();
connectDB();

const app = express();
const PORT = process.env.PORT || 443;

// ✅ Load HTTPS certificate and key
const sslOptions = {
  key: fs.readFileSync("../localhost-key.pem"),
  cert: fs.readFileSync("../localhost.pem"),
};

// ✅ CORS config
app.use(
  cors({
    origin: "https://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());

// ✅ Trust proxy if behind something like Nginx or a tunnel
app.set("trust proxy", 1);

// ✅ Sessions
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
      maxAge: 30 * 60 * 1000,
    },
  })
);
app.use((req, res, next) => {
  console.log("🧪 Session inside middleware BEFORE security:", req.session?.user);
  next();
});

// 🔒 SECURITY MIDDLEWARE: Add comprehensive security protection
// SECURITY MEASURE: General security middleware (rate limiting, pattern detection)
app.use(securityMiddleware);

// SECURITY MEASURE: NoSQL injection protection middleware
// This middleware sanitizes all request data to prevent NoSQL injection attacks
app.use(nosqlInjectionProtection);

// 🔍 Session Debugging
app.get("/session-status", (req, res) => {
  res.json({ session: req.session });
});
app.use((req, res, next) => {
  console.log("🔍 Current Session:", req.session);
  next();
});

// ✅ Register routes
app.use("/api", askAIRoutes);
app.use("/api", scanRoutes);
app.use("/api", reportRoutes);
app.use("/api", educationRoutes);
app.use("/api/auth", authRoutes);
app.use("/api/chatbot", chatbotRoutes);
app.use("/api/telegram", telegramBotRoutes);
app.use("/api/log", logRoutes);

// ✅ Default route
app.get("/", (req, res) => {
  res.send("✅ HTTPS Server is running and connected to MongoDB!");
});

// ✅ 404 fallback
app.use((req, res) => {
  res.status(404).json({ error: "404 Not Found - Invalid Route" });
});

// ✅ Start HTTPS Server
https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`🔒 HTTPS Server running at https://localhost:${PORT}`);
});
