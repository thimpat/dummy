const express = require('express');
const passport = require('passport');
const router = express.Router();
const { generateToken, verifyToken } = require('../utils/jwt');

const User = require('../models/User');

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(401).send('User not found');

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).send('Invalid credentials');

  const token = generateToken(user._id);
  res.json({ token });
});

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', (req, res) => res.send('Welcome!'));

module.exports = router;