const express = require("express");
const axios = require("axios");
const router = express.Router();
require("dotenv").config();

router.post("/ask-ai", async (req, res) => {
  const { question, conversationHistory } = req.body;
  if (!question) {
    return res.status(400).json({ error: "Question is required." });
  }

  try {
    const API_KEY = process.env.GEMINI_API_KEY;
    const geminiEndpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${API_KEY}`;

    // Build conversation context
    let conversationContext = "";
    if (conversationHistory && conversationHistory.length > 0) {
      conversationContext = "Previous conversation:\n";
      conversationHistory.forEach(msg => {
        conversationContext += `${msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.content}\n`;
      });
      conversationContext += "\n";
    }

    // System prompt with conversation context
    const systemPrompt = `You are a helpful cybersecurity expert assistant. Your role is to ONLY answer questions related to cybersecurity, information security, and related topics.

IMPORTANT INSTRUCTIONS:
- If a question is about cybersecurity topics (network security, encryption, vulnerabilities, ethical hacking, malware, security protocols, data protection, etc.), provide a helpful and detailed answer.
- If a question is NOT about cybersecurity, politely decline with a response like: "I appreciate your question, but I'm specifically designed to help with cybersecurity-related topics. I can assist you with questions about network security, encryption, vulnerabilities, ethical hacking, malware protection, security best practices, and other information security topics. Is there anything cybersecurity-related I can help you with?"
- Remember the conversation context and provide coherent follow-up answers.

${conversationContext}Current User Question: ${question}`;

    const payload = {
      contents: [
        {
          parts: [
            {
              text: systemPrompt
            }
          ]
        }
      ],
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 1000,
      }
    };

    const headers = {
      "Content-Type": "application/json",
    };

    const response = await axios.post(geminiEndpoint, payload, { headers });
    
    // Extract the response text from Gemini's response structure
    const answer = response.data.candidates?.[0]?.content?.parts?.[0]?.text || "No answer provided";

    return res.json({ answer });
  } catch (error) {
    console.error("Error in Ask AI route:", error.response?.data || error.message);
    return res.status(500).json({ 
      error: "Failed to get answer from AI.",
      details: error.response?.data?.error?.message || error.message 
    });
  }
});

module.exports = router;