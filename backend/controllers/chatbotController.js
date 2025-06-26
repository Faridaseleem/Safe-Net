// controllers/chatbotController.js
const axios = require('axios');

exports.handleInteraction = async (req, res) => {
  console.log("Chatbot interaction received:", req.body);

  try {
    const { type, question, conversationHistory, userId } = req.body;

    if (type === 'choose_service') {
      const availableServices = [
        { name: 'Scan URL', endpoint: '/api/scan/url' },
        { name: 'Scan Email', endpoint: '/api/scan/email' },
        { name: 'Report URL', endpoint: '/api/report/url' },
        { name: 'Education', endpoint: '/api/education/phishing' }
      ];

      return res.json({
        message: "Please choose a service:",
        services: availableServices
      });

    } else if (type === 'ask_ai') {
      // ✅ Forward userId to /ask-ai
      const aiResponse = await axios.post(
        'http://localhost:5000/api/ask-ai',
        { question, conversationHistory, userId: user?._id },
        { headers: { 'Content-Type': 'application/json' } }
      );

      return res.json({ message: aiResponse.data.answer });

    } else {
      return res.status(400).json({ error: "Invalid interaction type provided." });
    }

  } catch (err) {
    console.error("❌ Chatbot error:", err.response?.data || err.message);
    res.status(500).json({
      error: "An error occurred processing your request.",
      details: err.response?.data?.error || err.message
    });
  }
};