const express = require('express');
const passport = require('passport');
const router = express.Router();

router.post('/login', passport.authenticate('local', {
  successRedirect: '/home',
  failureRedirect: '/auth/login-failed'
}));

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', (req, res) => res.send('Welcome!'));

// New endpoint for getting JWT token
router.post('/token', (req, res) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return res.status(500).send('Authentication failed');
    if (!user) return res.status(401).send('Invalid credentials');
    
    // Generate JWT token
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    res.json({ token });
  })(req, res);
});

module.exports = router;