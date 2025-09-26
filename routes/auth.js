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

// PATCHED: Modify Auth.js file to handle JWT authentication
/**
 * @description The Passport.js configuration file.
 */
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
/**
 * @description The JSON Web Token (JWT) strategy for authentication.
 *
 * @param {object} opts Options for the JWT strategy.
 * @param {function} done A callback function to handle the user data.
 */
const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('JWT');
opts.secretOrKey = 'your_secret_key'; // Replace with your secret key
/**
 * @description Define the Passport.js strategy for JWT authentication.
 *
 * @param {object} jwt_payload The decoded JWT payload.
 * @param {function} done A callback function to handle the user data.
 */
passport.use(new JWTStrategy(opts, (jwt_payload, done) => {
  User.findById(jwt_payload.id, (err, user) => {
    if (err) return done(err, false);
    if (user) return done(null, user);
    return done(null, false);
  });
/**
 * @description The authentication middleware for handling JWT tokens.
 */
const auth = require('./middleware/authenticate'); // Assuming a new middleware 'authenticate' has been created for checking and verifying JWT tokens
/**
 * @description The login endpoint to handle JWT token generation.
 *
 * @param {object} req The HTTP request object.
 * @param {object} res The HTTP response object.
 */
router.post('/login', (req, res) => {
  User.findOne({ username: req.body.username }, (err, user) => {
    if (err) return res.status(500).send(err);
    if (!user) return res.status(404).send('User not found.');
    const token = jwt.sign({ id: user._id }, opts.secretOrKey, {
      expiresInMinutes: 120 // Expiration time for the JWT (120 minutes)
    });
    res.send(token);
  });
});
/**
 * @description The protected route middleware to verify JWT tokens.
 *
 * @param {object} req The HTTP request object.
 * @param {object} res The HTTP response object.
 * @param {function} next A callback function to handle the request.
 */
router.use('/', auth, (req, res, next) => {
  // Protected routes will go here.
});
/**
 * @description The authentication middleware for verifying JWT tokens.
 *
 * @param {object} req The HTTP request object.
 * @param {object} res The HTTP response object.
 * @param {function} next A callback function to handle the request.
 */
const jwt = require('jsonwebtoken');
module.exports = (req, res, next) => {
  const token = req.header('Authorization').split(' ')[1];
  if (!token) return res.status(401).send('Access denied.');
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid token.');
  }
};