// backend/controllers/educationController.js
exports.getPhishingEducation = (req, res) => {
  res.json({
    title: "Phishing Awareness",
    content: "Phishing is a type of cyberattack that uses disguised emails, messages, or websites to trick users into revealing sensitive information such as passwords or financial data. Always verify the sender, avoid clicking suspicious links, and report any suspected phishing attempts."
  });
};
