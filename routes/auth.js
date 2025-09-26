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

// PATCHED: Update auth.js file to generate a token upon successful login
/**
 * Passport configuration for JSON Web Token (JWT) authentication.
 */
const jwt = require('jsonwebtoken');
const User = require('../models/user');
/**
 * Secret key for JWT signing.
 */
const secretKey = 'your-secret-key';
/**
 * Generates a JSON Web Token (JWT) for the given user.
 *
 * @param {User} user The authenticated user.
 * @returns {string} The generated JWT token.
 */
function generateToken(user) {
  return jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
}
/**
 * Passport strategy for verifying JSON Web Tokens (JWTs).
 *
 * @param {Object} token The JWT token to verify.
 * @param {Function} done A callback function to call when the verification is complete.
 */
passport.use((req, res, next) => {
  passport.Strategy({
    name: 'jwt',
    verify: function(token, done) {
      try {
        const decoded = jwt.verify(token, secretKey);
        User.findById(decoded.id, (err, user) => {
          if (err) return done(err);
          if (!user) return done(null, false);
          return done(null, user);
        });
      } catch (err) {
        return done(err);
      }
    },
  });
});
/**
 * Serializes the given user to a JSON Web Token (JWT).
 *
 * @param {User} user The user to serialize.
 * @param {Function} done A callback function to call when the serialization is complete.
 */
passport.serializeUser((user, done) => {
  const token = generateToken(user);
  done(null, token);
});
/**
 * Deserializes a JSON Web Token (JWT) back into a user.
 *
 * @param {string} token The JWT token to deserialize.
 * @param {Function} done A callback function to call when the deserialization is complete.
 */
passport.deserializeUser((token, done) => {
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return done(err);
    User.findById(decoded.id, (err, user) => {
      if (err) return done(err);
      done(null, user);
    });
  });
});