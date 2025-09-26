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

// PATCHED: Import and create a new JWT-based authentication strategy in passport.js
/**
 * Add JWT support to replace session-based login
 *
 * @file auth.js
 */
const express = require('express');
const jsonwebtoken = require('jsonwebtoken');
const router = express.Router();
// Create a new Express middleware that verifies the incoming JWT token:
/**
 * Verify JWT token middleware
 *
 * @param {request} req - The request object
 * @param {response} res - The response object
 * @param {next} next - The next function in the middleware chain
 */
const verifyJWT = passport.authenticate('jwt-login');
router.post('/login', verifyJWT, (req, res) => {
  /**
   * Handle successful login and generate JWT token
   *
   * @param {request} req - The request object
   * @param {response} res - The response object
   */
  const payload = {
    user: req.user // Assuming passport.serializeUser() and passport.deserializeUser() are still in use
  };
  const token = jsonwebtoken.sign(payload, process.env.SECRET_KEY);
  res.send({ token });
});
module.exports = router;
/**
 * Passport configuration for JWT-based authentication
 *
 * @file passport.js
 */
const jwtOptions = {
  /**
   * Secret key used to sign and verify JWT tokens
   */
  secretOrKey: process.env.SECRET_KEY,
};
const jwtLogin = new require('passport-jwt').Strategy(jwtOptions, (jwtPayload, done) => {
  // Verify the incoming token and if valid, call `done(null, user)`
});
/**
 * Use the JWT-based authentication strategy
 *
 * @param {passport} passport - The Passport instance
 */
passport.use(jwtLogin);
module.exports = passport;