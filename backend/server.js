const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const scanRoutes = require("./routes/scanRoutes");
const authRoutes = require("./routes/auth");
const session = require("express-session");
const MongoStore = require("connect-mongo");


dotenv.config();
connectDB();

const app = express();
const PORT = process.env.PORT || 5000;

// ✅ Fix CORS for Sessions
app.use(cors({
    origin: "http://localhost:3000",
    credentials: true  // Ensure cookies & session persistence
}));

app.use(express.json());


app.use(
    session({
        secret: process.env.SESSION_SECRET,  
        resave: false,
        saveUninitialized: false,
        
        store: MongoStore.create({
            mongoUrl: process.env.MONGO_URI,
            collectionName: "sessions",
            stringify: false,  // ✅ Ensure proper object storage
            autoRemove: "interval",
            autoRemoveInterval: 1 // Remove expired sessions every 1 minutes
        }),
        cookie: { 
            secure: process.env.NODE_ENV === "production", // Only true in production
            httpOnly: true, 
            sameSite: 'Lax',  
            maxAge: 10 * 60 * 1000 // 10 minutes
            
        }
    })
);



// ✅ Debug Route: Check Session
app.get("/session-status", (req, res) => {
    res.json({ session: req.session });
});

app.use((req, res, next) => {
    console.log("🔍 Current Session:", req.session);
    next();
});


// Routes
app.use("/api", scanRoutes);
app.use("/api/auth", authRoutes);




app.get("/", (req, res) => {
    res.send("✅ Server is running and connected to MongoDB!");
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ error: "404 Not Found - Invalid Route" });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
