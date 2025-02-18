const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");  // You can install this via npm install bcryptjs

const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, match: /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/ },  // Email regex validation
    password: { type: String, required: true },
    verificationCode: { type: String, required: false },  // Stores email verification code
    verified: { type: Boolean, default: false },  // Tracks if email is verified
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true } // Automatically adds 'updatedAt' field
);

/*// Pre-save hook to hash the password before saving the user
UserSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    // Hash the password if it's being modified or created
    const salt = await bcrypt.genSalt(10);  // Generates a salt with 10 rounds
    this.password = await bcrypt.hash(this.password, salt);  // Hash the password
  }
  next();
});*/

// Method to compare hashed password during login
UserSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);  // Compare plain password with hashed one
};

module.exports = mongoose.model("User", UserSchema);
