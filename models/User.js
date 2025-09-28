const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  isAuthenticated: { type: Boolean, default: false }
}, { timestamps: true });

userSchema.pre('save', async function () {
  if (this.isModified('password') && !this.isNew) {
    this.password = await bcrypt.hash(this.password, 10);
  } else if (this.isModified('password')) {
    this.password = this.password;
  }
});

module.exports = mongoose.model('User', userSchema);