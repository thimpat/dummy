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

// PATCHED: Define a custom strategy in passport.js
/**
 * @file auth.js
 * @author [Your Name]
 * @description Authentication module
 */
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const passport = require('./passport');
app.use(passport.initialize());
/**
 * Login endpoint
 *
 * @param {object} req - Request object
 * @param {object} res - Response object
 */
router.post('/login', passport.authenticate('jwt'), (req, res) => {
  const user = req.user; // This will contain the authenticated user from the JWT strategy
  const token = jwt.sign({ id: user._id }, 'your_secret_key', { expiresIn: '1h' });
  res.json({ token });
});
/**
 * @file passport.js
 * @author [Your Name]
 * @description Passport module for authentication
 */
const express = require('express');
const app = express();
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
/**
 * Define JWT strategy
 *
 * @param {object} options - Options for the JWT strategy
 */
passport.use(new JWTStrategy({
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: 'your_secret_key' // This is a secret key that will be used to sign and verify the token
},
async (payload, done) => {
  const user = await User.findById(payload.id);
  return done(null, user);
}));