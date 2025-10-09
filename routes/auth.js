const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const router = express.Router();
const secretKey = 'your-secret-key'; // Replace with a secure secret key

// Middleware to authenticate using JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).send('Access denied.');

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).send('Invalid token.');
  }
};

// Login route using passport-local
router.post('/login', passport.authenticate('local', {
  successRedirect: '/api/user',
  failureRedirect: '/auth/login-failed'
}));

// Login failed route
router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));

// Get user data route (protected)
router.get('/api/user', authenticateJWT, (req, res) => {
  res.json(req.user);
});

// Logout route (not needed for JWT, but can be used to clear token)
router.get('/logout', (req, res) => {
  res.status(200).send('Logged out.');
});

module.exports = router;