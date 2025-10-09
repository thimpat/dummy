const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const router = express.Router();
const secretKey = 'your-secret-key-here'; // Replace with a secure key in production

// Login route
router.post('/login', passport.authenticate('local', {
  successRedirect: '/api/auth/token',
  failureRedirect: '/auth/login-failed'
}));

// Token endpoint
router.get('/api/auth/token', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const token = jwt.sign({ id: req.user.id, username: req.user.username }, secretKey, { expiresIn: '1h' });
  res.json({ token });
});

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', (SuppressWarnings: 'unused') (req, res) => res.send('Welcome!'));

module.exports = router;