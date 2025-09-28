const express = require('express');
const router = express.Router();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('../config/jwt');

// Passport setup
require('../config/passport')(LocalStrategy);

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await passport.authenticate('local', {
      failureRedirect: '/auth/login-failed',
      session: false // Disable session for JWT
    })(username, password);
    
    const token = jwt.createToken(user.id);

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    res.status(401).send('Invalid credentials');
  }
});

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', passport.authenticate('jwt', { session: false }), (req, res) => res.send('Welcome!'));

module.exports = router;