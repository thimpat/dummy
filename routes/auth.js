const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const config = require('../config/passport');

const router = express.Router();

// Helper function to verify JWT token and return user object if valid
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('You are not authorized!');
  }

  jwt.verify(token, config.secretKey, (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Token is invalid!' });
    }
    req.user = user;
    next();
  });
}

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user) return res.status(401).send('Invalid credentials.');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).send('Invalid credentials.');

    // Generate JWT token
    const token = jwt.sign({ id: user.id }, config.secretKey, {
      expiresIn: '1h'
    });

    res.json({
      token,
      userId: user.id,
      username: user.username
    });
  } catch (err) {
    console.error(err);
    return res.status(500).send('Server error.');
  }
});

// Middleware for authenticated routes to verify JWT
router.use((req, res, next) => {
  verifyToken(req, res, () => {
    next();
  });
});

module.exports = router;