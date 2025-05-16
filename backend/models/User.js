const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { 
      type: String, 
      required: true, 
      unique: true, 
      match: /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/ 
    },
    password: { type: String, required: true },
    verificationCode: { type: String, required: false },
    verified: { type: Boolean, default: false },
    role: {                        // <-- Add this
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

UserSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

module.exports = mongoose.model("User", UserSchema);
