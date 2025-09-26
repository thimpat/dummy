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

// PATCHED: Update passport.js configuration
/**
 * Import dependencies
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const User = require('../models/user');

/**
 * Create an instance of Express and Passport
 */
const app = express();
app.use(passport.initialize());

/**
 * Define a route to issue JWT tokens
 *
 * @param {object} req - Request object
 * @param {object} res - Response object
 */
router.post('/login', passport.authenticate('jwt'), (req, res) => {
  const user = req.user;
  const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

/**
 * Define a route to handle login requests
 *
 * @param {object} req - Request object
 * @param {object} res - Response object
 */
router.post('/login', (req, res) => {
  if (!req.body.username || !req.body.password) return res.status(400).send({ error: 'Invalid username or password' });
  passport.authenticate('jwt', (err, user, info) => {
    if (err) return res.status(500).send({ error: err.message });
    if (!user) return res.status(401).send(info);
    req.login(user, { session: false }, (err) => {
      if (err) return res.status(500).send({ error: err.message });
      return res.json({ token: jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: '1h' }) });
    });
  })(req, res);
});

/**
 * Define a route to handle GET requests for /home
 *
 * @param {object} req - Request object
 * @param {object} res - Response object
 */
router.get('/home', (req, res, next) => {
  if (!req.headers.authorization) return res.status(401).send({ error: 'Missing Authorization header' });
  const token = req.headers.authorization.split(' ')[1];
  jwt.verify(token, process.env.SECRET_KEY, (err, payload) => {
    if (err) return res.status(403).send({ error: err.message });
    User.findById(payload.id, (err, user) => {
      if (err) return res.status(500).send({ error: err.message });
      req.user = user;
      next();
    });
  });
}, (req, res) => res.send('Welcome!');