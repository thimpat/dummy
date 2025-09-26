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

// PATCHED: Update passport.js file (optional)
/**
 * @module auth
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const userModel = require('../models/User'); // Assuming User model exists
const router = express.Router();
/**
 * Define the secret key and token options
 */
const JWT_SECRET = 'your_secret_key';
const jwtOptions = {
  /**
   * @property {string} secretOrKey The secret key used to sign and verify JWT tokens
   * @property {function} jwtFromRequest A function that extracts the JWT token from the request
   */
  secretOrKey: JWT_SECRET,
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
};
/**
 * Create and setup the JWT strategy for Passport
 *
 * @param {function} done The callback function to handle authentication results
 */
passport.use(new JWTStrategy(jwtOptions, async (payload, done) => {
  try {
    /**
     * @param {Object} user The user object retrieved from the database
     * @returns {void}
     */
    const user = await userModel.findById(payload.id);
    if (user) {
      return done(null, user);
    } else {
      return done(null, false);
  } catch (err) {
    return done(err, false);
}));
/**
 * Add a new route for token authentication
 *
 * @param {Object} req The request object
 * @param {Object} res The response object
 */
router.post('/login', (req, res) => {
  passport.authenticate('jwt', { session: false }, async (err, user, info) => {
    if (err) return res.status(500).send({ message: err.message });
    /**
     * @param {Object} user The authenticated user object
     * @returns {void}
     */
    if (!user || !info) return res.status(401).send({ message: 'Invalid username or password.' });
    /**
     * Create a JWT token with the user's information and send it back as a response
     *
     * @param {Object} payload The payload object containing the user's ID
     * @returns {string} The signed JWT token
     */
    const payload = { id: user._id };
    const token = jwt.sign(payload, JWT_SECRET);
    res.send({ token });
  })(req, res);
});
/**
 * Remove the existing local authentication route and replace it with the new one for JWT authentication
 *
 * @param {Object} req The request object
 * @param {Object} res The response object
 */
router.delete('/login', (req, res) => {
  console.log('Old login route removed. Replaced by JWT authentication.');
});