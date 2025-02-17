const nodemailer = require("nodemailer");

// Create transporter using your email service
const transporter = nodemailer.createTransport({
  service: "gmail", // Use Gmail as the email provider
  auth: {
    user: "safenet012@gmail.com", // Replace with your email
    pass: "aicu orbg crtc fzty",    // Replace with your Gmail app password
  },
  tls: {
    rejectUnauthorized: false,  // This disables SSL/TLS certificate validation (useful for local testing)
  },
});

// Function to send verification email
const sendVerificationEmail = async (email, code) => {
  const mailOptions = {
    from: '"Safe-Net" <safenet012@gmail.com>', // Sender address
    to: email, // Recipient address
    subject: "Email Verification Code", // Email subject
    text: `Your verification code is: ${code}`, // Plain text body
    html: `<p>Your verification code is: <b>${code}</b></p>`, // HTML body content
  };

  try {
    await transporter.sendMail(mailOptions); // Send email
    console.log("Verification email sent to:", email); // Log success message
  } catch (error) {
    console.error("Error sending email:", error); // Log error message
  }
};

module.exports = sendVerificationEmail;
