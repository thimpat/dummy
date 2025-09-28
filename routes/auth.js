const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Secret key for JWT (should be in environment variables in production)
const JWT_SECRET = 'your-secret-key-here';

// Login route using JWT
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Use passport-local strategy to authenticate
  passport.authenticate('local', (err, user, info) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    // Generate JWT token
    const token = jwt.sign({ username: user.username, id: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  })(req, res);
});

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', (req, res) => res.send('Welcome!'));

module.exports = router;