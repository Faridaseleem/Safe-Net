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
const educationRoutes = require("./routes/educationRoutes"); // <<-- 1. ADD THIS LINE

dotenv.config();
connectDB();

const app = express();
const PORT = process.env.PORT || 5000;

// ✅ Allow frontend access (make sure this matches your frontend port!)
app.use(
  cors({
    origin: "http://localhost:3000", // or the domain of your frontend (e.g. chrome-extension://...)
    credentials: true,
  })
);

app.use(express.json());

// ✅ Setup session middleware
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

// 🔍 Debug session
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
app.use("/api", educationRoutes); // <<-- 2. ADD THIS LINE
app.use("/api/auth", authRoutes);
app.use("/api/chatbot", chatbotRoutes);
app.use("/api/telegram", telegramBotRoutes);

// ✅ Default route
app.get("/", (req, res) => {
  res.send("✅ Server is running and connected to MongoDB!");
});

// ✅ 404 fallback
app.use((req, res) => {
  res.status(404).json({ error: "404 Not Found - Invalid Route" });
});

// ✅ Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});