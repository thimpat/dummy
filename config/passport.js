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

// PATCHED: Import jwt in passport.js
/**
 * @module passport
 */
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
passport.use(new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password'
},
  const user = await User.findOne({ where: { username } });
  if (isValid) {
    const payload = { id: user.id };
    const secret = process.env.JWT_SECRET;
    const token = jwt.sign(payload, secret);
    return done(null, { user, token });
  return done(null, false);
}));
/**
 * @module auth
 */
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
router.post('/login', passport.authenticate('local'), (req, res) => {
  const user = req.user;
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
  res.json({ user, token });
});
router.get('/home', passport.authenticate('jwt', { session: false }), (req, res) => res.send('Welcome!'));
router.get('/refresh-token', (req, res) => {
  const token = req.headers['x-access-token'];
  if (!token) return res.status(401).send('Access token is missing.');
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(500).send({ error: 'Invalid token.' });
    const user = decoded.id;
    const newToken = jwt.sign({ id: user }, process.env.JWT_SECRET);
    res.json({ token: newToken });
  });
});
/**
 * @module User
 */
const Sequelize = require('sequelize');
module.exports = (sequelize) => {
  return sequelize.define('User', {
    id: {
      type: Sequelize.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    username: {
      type: Sequelize.STRING,
      unique: true
    },
    password: {
      type: Sequelize.STRING
  });
};