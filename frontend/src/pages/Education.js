import React from "react";
import "./Education.css"; // Ensure this CSS file exists

const Education = () => {
  return (
    <div className="education-container">
      <h1 className="education-title">Phishing Awareness & Online Safety</h1>
      <p className="education-intro">
        Stay safe online by following these essential cybersecurity tips!
      </p>
      <div className="education-content">
        <ul>
          <li>✅ Always check the URL before clicking on a link.</li>
          <li>🔒 Look for HTTPS in the website URL to ensure a secure connection.</li>
          <li>⚠️ Beware of emails asking for sensitive information or urging immediate action.</li>
          <li>🔑 Use strong, unique passwords for different accounts.</li>
          <li>📲 Enable two-factor authentication (2FA) for added security.</li>
          <li>📩 Verify the sender’s email address before opening attachments.</li>
          <li>🛡️ Keep your software and antivirus updated.</li>
          <li>📂 Avoid downloading files from unknown sources.</li>
          <li>🚨 Report any suspicious emails or messages to your IT department.</li>
        </ul>
      </div>
    </div>
  );
};

export default Education;
