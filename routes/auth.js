const express = require('express');
const passport = require('passport');
const router = express.Router();
const jwt = require('jsonwebtoken');

// Login route
router.post('/login', passport.authenticate('local', {
  session: false
}), (req, res) => {
  const token = jwt.sign({ id: req.user._id }, 'your-secret-key-here', {
    expiresIn: '1h'
  });
  res.json({ token });
});

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', (req, res) => res.send('Welcome!'));

module.exports = router;