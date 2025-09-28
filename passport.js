const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config');

/**
 * Configure Passport.js for authentication.
 */
passport.use(new LocalStrategy(
  async (username, password, done) => {
    const user = await User.findOne({ username });
    if (!user) return done(null, false);
    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? done(null, user) : done(null, false);
  }
));

/**
 * Serialize the user object to store in the session.  Currently unused with JWT.
 * @param {object} user The user object.
 * @param {function} done Callback function.
 */
passport.serializeUser((user, done) => done(null, user.id));

/**
 * Deserialize the user object from the session. Currently unused with JWT.
 * @param {string} id The user ID.
 * @param {function} done Callback function.
 */
passport.deserializeUser((id, done) => User.findById(id).then(user => done(null, user)));

/**
 * Middleware to authenticate JWT.
 * @param {object} req Express request object.
 * @param {object} res Express response object.
 * @param {function} next Callback function.
 */
passport.use(new JwtStrategy(
  {
    secret: config.jwtSecret,
    jwtFromRequest: (req) => req.headers['authorization'],
    passReqToCallback: true
  },
  (req, payload, done) => {
    User.findById(payload.id)
      .then(user => {
        if (user) {
          req.user = user; // Attach user to request for subsequent middleware
          return done(null, user);
        } else {
          return done(null, false);
        }
      })
      .catch(err => {
        done(err, false);
      });
    }));

const JwtStrategy = require('passport-jwt').Strategy;