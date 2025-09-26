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

// PATCHED: Create JWT strategy in passport.js
/**
 * Passport configuration for JSON Web Token (JWT) authentication.
 *
 * @author [Your Name]
 */
const passport = require('passport');
const JWTStrategy = require('passport-jwt').Strategy;
const User = require('../models/User');
const jsonwebtoken = require('jsonwebtoken');

/**
 * Extracts the JWT token from the request cookies.
 *
 * @param {object} req The HTTP request object
 * @returns {string|null} The extracted JWT token or null if not found
 */
function extractJwt(req) {
  const token = req?.cookies?.token;
  return token ? token : null;
}

/**
 * Passport strategy for JSON Web Token (JWT) authentication.
 *
 * @param {object} opts Configuration options
 * @param {(jwt_payload: object, done: function) => void} verifyCallback The callback to verify the JWT payload
 */
passport.use(new JWTStrategy({
  /**
   * Extracts the JWT token from the request.
   *
   * @param {object} req The HTTP request object
   * @returns {string|null} The extracted JWT token or null if not found
   */
  jwtFromRequest: extractJwt,

  /**
   * Secret key for signing and verifying JWT tokens.
   *
   * @type {string}
   */
  secretOrKey: 'your_secret'
}, async (jwt_payload, done) => {
  try {
    const user = await User.findById(jwt_payload.id);
    if (user) return done(null, user);
    return done(null, false);
  } catch (err) {
    return done(err);
  }
}));

/**
 * Login route for issuing JWT tokens.
 *
 * @param {object} req The HTTP request object
 * @param {object} res The HTTP response object
 */
router.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user) return res.status(401).send('Invalid username or password');

  const isValidPassword = await bcrypt.compare(req.body.password, user.password);
  if (!isValidPassword) return res.status(401).send('Invalid username or password');

  // Generate JWT token and set it as response cookie
  const token = jsonwebtoken.sign({ id: user._id }, 'your_secret', { expiresIn: '24h' });
  res.cookie('token', token);
  return res.json({ message: 'Logged in successfully!' });
});

// PATCHED: Add login route and issue JWT
/**
 * Passport configuration for JSON Web Token (JWT) authentication.
 *
 * @author [Your Name]
 */
const passport = require('passport');
const JWTStrategy = require('passport-jwt').Strategy;
const User = require('../models/User');
const jsonwebtoken = require('jsonwebtoken');

/**
 * Extracts the JWT token from the request cookies.
 *
 * @param {object} req The HTTP request object
 * @returns {string|null} The extracted JWT token or null if not found
 */
function extractJwt(req) {
  const token = req?.cookies?.token;
  return token ? token : null;
}

/**
 * Passport strategy for JSON Web Token (JWT) authentication.
 *
 * @param {object} opts Configuration options
 * @param {(jwt_payload: object, done: function) => void} verifyCallback The callback to verify the JWT payload
 */
passport.use(new JWTStrategy({
  /**
   * Extracts the JWT token from the request.
   *
   * @param {object} req The HTTP request object
   * @returns {string|null} The extracted JWT token or null if not found
   */
  jwtFromRequest: extractJwt,

  /**
   * Secret key for signing and verifying JWT tokens.
   *
   * @type {string}
   */
  secretOrKey: 'your_secret'
}, async (jwt_payload, done) => {
  try {
    const user = await User.findById(jwt_payload.id);
    if (user) return done(null, user);
    return done(null, false);
  } catch (err) {
    return done(err);
  }
}));

/**
 * Login route for issuing JWT tokens.
 *
 * @param {object} req The HTTP request object
 * @param {object} res The HTTP response object
 */
router.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user) return res.status(401).send('Invalid username or password');

  const isValidPassword = await bcrypt.compare(req.body.password, user.password);
  if (!isValidPassword) return res.status(401).send('Invalid username or password');

  // Generate JWT token and set it as response cookie
  const token = jsonwebtoken.sign({ id: user._id }, 'your_secret', { expiresIn: '24h' });
  res.cookie('token', token);
  return res.json({ message: 'Logged in successfully!' });
});