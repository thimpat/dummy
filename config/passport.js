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

// PATCHED: Import jsonwebtoken in passport.js
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

// PATCHED: Define a JWT strategy in passport.js
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

// PATCHED: Modify serializeUser and deserializeUser functions in passport.js
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