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

// PATCHED: Update LocalStrategy in passport.js
/**
 * Auth controller for JWT-based authentication
 */
const express = require('express');
const router = express.Router();
const passport = require('../passport');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
// Secret key for JWT signing
const secret = 'your_secret_key'; // Replace this with your own secret key
/**
 * Login route using local strategy and JWT token generation
 */
router.post('/login', (req, res) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return res.status(500).send(err);
    if (!user) return res.status(401).send(info);
    const token = jwt.sign({ id: user.id }, secret, { expiresIn: 86400 }); // Token expiration in seconds (e.g., 24 hours)
    res.json({ token });
  })(req, res);
});
/**
 * Protected route middleware using JWT verification
 */
const protectedRoute = expressJwt({ secret });
/**
 * Home route for authenticated users
 */
router.get('/home', protectedRoute, (req, res) => res.send('Welcome!'));
module.exports = router;
/**
 * Passport configuration for local strategy and JWT serialization/deserialization
 */
const User = require('../models/User'); // Assuming a User model is defined elsewhere
    if (!isValid) return done(null, false);
    return done(null, user);
passport.serializeUser((user, done) => {
  const payload = { id: user.id }; // Include additional data if needed
  done(null, payload);
});
passport.deserializeUser((payload, done) => {
  User.findById(payload.id).then(user => done(null, user));
});