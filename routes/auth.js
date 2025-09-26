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

// PATCHED: Modify the login route in auth.js
/**
 * passport.js
 */

const passport = require('passport');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Define a JWT strategy
/**
 * Constructor for the JWTStrategy.
 *
 * @param {Object} options - Configuration options for the JWT strategy.
 * @returns {passport.Strategy} The constructed JWT strategy.
 */
const JWTStrategy = new passport.Strategy({
  passwordReqire: false // Tell Passport to not validate the incoming password
}, async (username, done) => {
  /**
   * Find a user by username and generate a JWT token if found.
   *
   * @param {string} username - The username of the user to find.
   * @param {(err, user) => void} done - A callback function that will be called
   *                                        with the result of the operation.
   */
  const user = await User.findOne({ username });
  if (!user) return done(null, false);

  // Generate a JWT token
  /**
   * Sign a payload as a JSON Web Token.
   *
   * @param {Object} payload - The data to be signed.
   * @param {string} secretKey - The secret key used for signing.
   * @param {(err, token) => void} options - Configuration options for the sign operation.
   */
  const payload = { id: user._id };
  const options = { expiresIn: '1h' }; // Token expiration time (in this case, 1 hour)
  const token = jwt.sign(payload, 'secretKey', options);

  return done(null, { user, token });
});

// Add JWT strategy to Passport
passport.use(JWTStrategy);

/**
 * passport.js
 */

passport.serializeUser((user, done) => {
  /**
   * Serialize the user data into a JSON Web Token.
   *
   * @param {(err, user) => void} done - A callback function that will be called
   *                                        with the result of the operation.
   */
  const token = jwt.sign({ id: user._id }, 'secretKey');
  done(null, token);
});

passport.deserializeUser((token, done) => {
  try {
    /**
     * Verify a JSON Web Token and return the decoded payload.
     *
     * @param {string} token - The JSON Web Token to verify.
     * @param {(err, payload) => void} secretKey - The secret key used for verification.
     */
    const decoded = jwt.verify(token, 'secretKey');
    User.findById(decoded.id).then(user => done(null, user));
  } catch (err) {
    // Handle errors (e.g., invalid token)
    done(err);
  }
});
/**
 * auth.js
 */

const express = require('express');
const passport = require('passport');
const router = express.Router();

router.post('/login', passport.authenticate('jwt')); // Use 'jwt' strategy instead of 'local'

// ... (existing code)