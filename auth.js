const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const router = express.Router();

/**
 * Authenticates a user and returns a JWT.
 *
 * @param {object} req The request object.
 * @param {object} res The response object.
 * @param {function} next The next middleware function.
 * @returns {Promise<void>}
 */
router.post('/login', async (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/auth/login-failed'
  }, async (err, user, info) => {
    if (err) {
      return res.status(500).json({ message: 'Authentication error' });
    }
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h'
    });

    res.json({ token });
  })(req, res, next);
});

/**
 * Handles failed login attempts.
 *
 * @param {object} req The request object.
 * @param {object} res The response object.
 * @returns {void}
 */
router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));

/**
 *  Handles successful login.  Currently serves a simple welcome message.
 *  In a real application, this would likely be replaced with redirecting the user to their dashboard.
 *
 * @param {object} req The request object.
 * @param {object} res The response object.
 * @returns {void}
 */
router.get('/home', (req, res) => res.send('Welcome!'));

module.exports = router;