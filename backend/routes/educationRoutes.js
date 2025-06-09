// backend/routes/educationRoutes.js
const express = require('express');
const router = express.Router();
const educationController = require('../controllers/educationController');

router.get('/phishing', educationController.getPhishingEducation);

module.exports = router;
