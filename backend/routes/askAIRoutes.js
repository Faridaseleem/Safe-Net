const express = require("express");
const axios = require("axios");
const router = express.Router();
require("dotenv").config();

router.post("/ask-ai", async (req, res) => {
  const { question, conversationHistory } = req.body;

  console.log("📥 Incoming question:", question);

  if (!question) {
    return res.status(400).json({ error: "Question is required." });
  }

  try {
    const API_KEY = process.env.GEMINI_API_KEY;
    const geminiEndpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${API_KEY}`;

    // System prompt (persistent role)
    const systemInstructions = `You are a helpful cybersecurity expert assistant. 
    Only answer questions related to cybersecurity, information security, or related fields. 
    If a question is outside that scope, politely decline.`;

    // Combine with conversation history and question
    let conversationContext = "";
    if (conversationHistory && conversationHistory.length > 0) {
      conversationContext = conversationHistory.map(msg => {
        const speaker = msg.role === 'user' ? 'User' : 'Assistant';
        return `${speaker}: ${msg.content}`;
      }).join('\n') + '\n\n';
    }

    // Payload without system role
    const payload = {
      contents: [
        {
          parts: [
            {
              text: `${systemInstructions}\n\n${conversationContext}${question}`
            }
          ]
        }
      ],
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 1000
      }
    };

    const headers = { "Content-Type": "application/json" };

    // API request
    const response = await axios.post(geminiEndpoint, payload, { headers });

    // Log actual response
    console.log("🤖 Gemini raw response:", response.data);

    const answer = response.data.candidates?.[0]?.content?.parts?.[0]?.text || "No answer provided";

    return res.json({ message: answer });

  } catch (error) {
    console.error("❌ Error in Ask AI route");
    console.error("🔴 Full error object:", error);

    if (error.response) {
      console.error("🔴 Error status:", error.response.status);
      console.error("🔴 Error data:", error.response.data);
      return res.status(500).json({
        error: "Failed to get answer from AI (response error).",
        status: error.response.status,
        details: error.response.data
      });
    } else if (error.request) {
      console.error("🔴 No response received from Gemini API.");
      console.error(error.request);
      return res.status(500).json({
        error: "No response from Gemini API.",
        details: error.message
      });
    } else {
      console.error("🔴 Error setting up the request:", error.message);
      return res.status(500).json({
        error: "Unexpected error during AI request setup.",
        details: error.message
      });
    }
  }
});

module.exports = router;