const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

/**
 * User schema for storing user information.
 * @type {mongoose.Schema}
 */
const userSchema = new mongoose.Schema({
  username: String,
  password: String
});

/**
 * Pre-save hook to hash the password before saving the user.
 * @returns {Promise<void>}
 */
userSchema.pre('save', async function () {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
});

/**
 * Model for the User collection.
 * @type {mongoose.Model}
 */
module.exports = mongoose.model('User', userSchema);