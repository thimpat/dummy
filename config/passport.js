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

// PATCHED: Import jwt at the top of passport.js file
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
}));
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