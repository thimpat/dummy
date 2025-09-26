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

// PATCHED: Import jsonwebtoken in auth.js
/**
 * @file auth.js
 * @author [Your Name]
 * @description Authentication module
 */
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
  if (!user) return done(null, false);
  return done(null, user);