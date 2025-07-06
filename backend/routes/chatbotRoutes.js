const express = require('express');
const router = express.Router();
const chatbotController = require('../controllers/chatbotController');



// Endpoint to handle chatbot interactions
router.post('/interact', chatbotController.handleInteraction);

module.exports = router;
