const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const router = express.Router();
const SECRET = 'your-secret-key'; // Replace with a secure secret key

// Middleware to authenticate using JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).send('Access denied.');

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).send('Invalid token.');
  }
};

router.post('/login', passport.authenticate('local', {
  successRedirect: '/api/token',
  failureRedirect: '/auth/login-failed'
}));

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', authenticateJWT, (req, res) => res.send('Welcome!'));

router.get('/api/token', (req, res) => {
  res.json({
    token: jwt.sign({ id: req.user.id, username: req.user.username }, SECRET, { expiresIn: '1h' })
  });
});

module.exports = router;