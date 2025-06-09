// controllers/chatbotController.js
exports.handleInteraction = async (req, res) => {
    console.log("Chatbot interaction received:", req.body);
    try {
      // Expected request body: { type: "choose_service" or "ask_ai" }
      const { type } = req.body;
      
      if (type === 'choose_service') {
        // Return available services
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
        // Placeholder response for AI functionality
        return res.json({
          message: "AI functionality is under development. Please check back soon!"
        });
      } else {
        return res.status(400).json({
          error: "Invalid interaction type provided."
        });
      }
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "An error occurred processing your request." });
    }
  };
  