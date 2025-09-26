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

// PATCHED: Create a function to generate JWT access tokens in passport.js
/**
 * @file auth.js
 * @description Handles JWT-based authentication and verification
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
/**
 * @function verifyAccessToken
 * @description Verifies the JWT token in the request headers
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {void}
 */
router.get('/home', (req, res) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const verified = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = verified;
    res.send('Welcome!');
  } catch (error) {
    return res.status(401).send('Invalid token or expired session.');
});
/**
 * @function login
 * @description Handles the login request and returns a JWT token
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @return {void}
 */
router.post('/login', (req, res) => {
  passport.authenticate('local', async (err, user, info) => {
    if (err) return res.status(401).send(info.message);
    if (!user) return res.status(401).send(info.message);
    const accessToken = generateAccessToken(user);
    req.login(user, { session: false }, (error) => {
      if (error) return res.status(500).send('Error logging in');
      res.json({ user, accessToken });
    });
  })(req, res);
});
/**
 * @function generateAccessToken
 * @description Generates a JWT token for the given user
 * @param {Object} user - The user object
 * @return {string}
 */
const generateAccessToken = (user) => {
  return jwt.sign({ id: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1d' });
};