const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');
const bcrypt = require('bcrypt');

// Helper function to hash passwords using bcrypt
async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

// Helper function to compare hashed passwords with plain text password
async function comparePassword(plainTextPassword, storedHash) {
  return await bcrypt.compare(plainTextPassword, storedHash);
}

passport.use(new LocalStrategy(
  async (username, password, done) => {
    const user = await User.findOne({ username });
    if (!user) {
      return done(null, false);
    }
    const isValid = await comparePassword(password, user.password);
    return isValid ? done(null, user) : done(null, false);
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  User.findById(id).then(user => done(null, user)).catch(done);
});