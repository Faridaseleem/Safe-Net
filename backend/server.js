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
const educationRoutes = require("./routes/educationRoutes");

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
      maxAge: 10 * 60 * 1000,
    },
  })
);

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
