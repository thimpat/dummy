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

// PATCHED: Create a new function in auth.js for handling authenticated login responses with JWTs
/**
 * @namespace
 * @description Passport.js configuration for JWT-based authentication
 */
const jwt = require('jsonwebtoken');
const User = require('../models/user');
/**
 * @classdesc
 * @extends {Strategy}
 * @name JWTStrategy
 * @description Passport.js strategy for JWT-based authentication
 * @param {Object} options - Options for the JWT strategy
 * @param {(payload: Object, done: (err, user) => void) => void} verify - Callback to verify the payload and authenticate the user
 */
const JWTStrategy = require('passport-jwt').Strategy;
/**
 * @constant
 * @name SECRET_KEY
 * @description Secret key for generating and verifying tokens
 */
const SECRET_KEY = 'your_secret_key'; // Replace with a secure secret key
/**
 * @namespace
 * @description Passport.js configuration options for JWT-based authentication
 */
const jwtOptions = {
  /**
   * @property {ExtractJwt}
   * @name jwtFromRequest
   * @description Extract the JWT token from the request
   */
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'),
  /**
   * @property {string}
   * @name secretOrKey
   * @description Secret key for generating and verifying tokens
   */
  secretOrKey: SECRET_KEY,
};
/**
 * @function
 * @name authenticate
 * @description Authenticate the user using the JWT strategy
 * @param {(req, res, next) => void} done - Callback to handle authentication
 */
passport.use(new JWTStrategy(jwtOptions, (payload, done) => {
  User.findById(payload.id, (err, user) => {
    if (err || !user) return done(err, false);
    return done(null, user);
  });
/**
 * @namespace
 * @description Express.js router for handling login requests with JWTs
 */
const router = require('express').Router();
/**
 * @function
 * @name login
 * @description Handle authenticated login responses with JWTs
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 */
router.post('/login', passport.authenticate('jwt'), (req, res) => {
  const token = jwt.sign({ id: req.user.id }, SECRET_KEY);
  res.json({ token });
});