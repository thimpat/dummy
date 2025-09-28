const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const jwtSecret = 'your_secret_key'; // Replace with a secure secret key
const bcrypt = require('bcrypt');
const User = require('../models/User');
const router = express.Router();

// Middleware to authenticate JWT tokens
function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err || !user) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    let user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send('Invalid credentials');
    }

    const token = jwt.sign(
      { userId: user.id },
      jwtSecret,
      { expiresIn: '2h' }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

router.get('/home', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  User.findById(userId)
    .then((user) => res.send(user))
    .catch((err) => res.status(400).json('Error: ' + err));
});

module.exports = router;