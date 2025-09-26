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

// PATCHED: Modify passport.js file to include JWT strategy and remove LocalStrategy
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
          return done(null, user);
        });
      } catch (err) {
        return done(err);
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