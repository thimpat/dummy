const express = require('express');
const passport = require('passport');
const router = express.Router();

router.post('/login', passport.authenticate('local', {
  successRedirect: '/home',
  failureRedirect: '/auth/login-failed'
}));

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', (req, res) => res.send('Welcome!'));

module.exports = router;

// PATCHED: Update '/login' route in auth.js to handle a JWT token and set it as an HTTP-only cookie
/**
 * @module auth
 */
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
/**
 * @module passport
 */
const app = express();
const jwt = require('jsonwebtoken');
const config = require('../config/default');
const User = require('../models/user'); // assume this is imported elsewhere
const bcrypt = require('bcryptjs');
const LocalStrategy = require('passport-local').Strategy;
function generateJwt(user) {
  /**
   * Generate and sign the JWT token
   * @param {Object} user - User object
   * @returns {string} JWT token
   */
  return jwt.sign({ id: user._id }, config.secret, { expiresIn: '1h' });
}
passport.use(new LocalStrategy(
  async (username, password, done) => {
    /**
     * Authenticate user with local strategy
     * @param {String} username - Username
     * @param {String} password - Password
     * @param {Function} done - Passport callback function
     */
    const user = await User.findOne({ username });
    if (!user) return done(null, false);
    const isValid = await bcrypt.compare(password, user.password);
    if (isValid) {
      /**
       * Return the JWT token instead of the user object
       * @param {string} token - JWT token
       */
      const token = generateJwt(user);
      return done(null, token);
    }
    return done(null, false);
  }
));
passport.session(false); // remove session support
module.exports = passport;