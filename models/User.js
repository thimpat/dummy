const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

/**
 * Represents a user in the application.
 * @param {string} username - The user's username.
 * @param {string} password - The user's password.
 */
const userSchema = new mongoose.Schema({
  username: String,
  password: String
});

/**
 * Hashes the user's password before saving to the database.
 */
userSchema.pre('save', async function () {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
});

module.exports = mongoose.model('User', userSchema);