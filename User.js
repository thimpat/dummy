const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

/**
 * Represents a user in the application.
 * @param {string} username The username of the user.
 * @param {string} password The password of the user.
 */
const userSchema = new mongoose.Schema({
  username: String,
  password: String
});

/**
 * Hashes the user's password before saving it to the database.
 *
 * @param {function} next The next middleware function.
 * @returns {Promise<void>}
 */
userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

module.exports = mongoose.model('User', userSchema);