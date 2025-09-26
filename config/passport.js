const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');
const bcrypt = require('bcrypt');

passport.use(new LocalStrategy(
  async (username, password, done) => {
    const user = await User.findOne({ username });
    if (!user) return done(null, false);
    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? done(null, user) : done(null, false);
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => User.findById(id).then(user => done(null, user)));

// PATCHED: Import 'jsonwebtoken' and 'config' in passport.js
/**
 * @module auth
 */
const express = require('express');
const router = express.Router();
const passport = require('../passport');
router.post('/login', passport.authenticate('local'), (req, res) => {
  /**
   * Send the JWT token in the response headers as JSON
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  res.json({ token: req.token });
});
router.get('/login-failed', (req, res) => {
  /**
   * Handle login failure redirect
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  res.status(401).send('Login failed');
});
module.exports = router;
/**
 * @module passport
 */
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const config = require('../config/default');
const User = require('../models/user'); // assume this is imported elsewhere
const bcrypt = require('bcryptjs');
function generateJwt(user) {
  /**
   * Generate and sign the JWT token
   * @param {Object} user - User object
   * @returns {string} JWT token
   */
  return jwt.sign({ id: user._id }, config.secret, { expiresIn: '1h' });
    /**
     * Authenticate user with local strategy
     * @param {String} username - Username
     * @param {String} password - Password
     * @param {Function} done - Passport callback function
     */
    if (isValid) {
      /**
       * Return the JWT token instead of the user object
       * @param {string} token - JWT token
       */
      const token = generateJwt(user);
      return done(null, token);
    return done(null, false);
passport.session(false); // remove session support
module.exports = passport;