const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "safenet012@gmail.com",
    pass: "aicu orbg crtc fzty",
  },
  tls: {
    rejectUnauthorized: false,
  },
});

const sendVerificationEmail = async (email, code) => {
  const mailOptions = {
    from: '"Safe-Net Security" <safenet012@gmail.com>',
    to: email,
    subject: "🔐 Verify Your Email - Safe-Net",
    text: `Hello,

Thank you for registering with Safe-Net.

Your verification code is: ${code}

Please enter this code in the app to complete your registration.

If you did not request this code, you can safely ignore this message.

Stay protected,
The Safe-Net Team`,
    html: `
      <div style="font-family: 'Segoe UI', sans-serif; background-color: #111827; padding: 30px; border-radius: 12px; color: #E5E7EB; max-width: 500px; margin: auto; box-shadow: 0 0 20px rgba(0, 255, 255, 0.2);">
        <h2 style="color: #8f9dff; text-align: center; margin-bottom: 20px;">🔐 Email Verification</h2>
        <p style="font-size: 16px; line-height: 1.5;">Hello,</p>
        <p style="font-size: 16px; line-height: 1.5;">Thank you for creating an account with <strong style="color: #8f9dff;">Safe-Net</strong>.</p>
        <p style="font-size: 16px; margin-top: 15px;">Please enter the following verification code in the app:</p>
        <div style="font-size: 28px; font-weight: bold; color: #8f9dff; background: rgba(0, 255, 255, 0.1); padding: 15px; border-radius: 8px; text-align: center; letter-spacing: 3px; margin: 20px auto;">${code}</div>
        <p style="font-size: 14px; color: #9CA3AF;">If you didn’t request this code, you can ignore this email safely.</p>
        <p style="margin-top: 30px;">Stay protected,<br/><strong style="color: #8f9dff;">— The Safe-Net Team</strong></p>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("✅ Verification email sent to:", email);
  } catch (error) {
    console.error("❌ Error sending email:", error);
  }
};

module.exports = sendVerificationEmail;
