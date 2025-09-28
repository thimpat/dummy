const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const config = require('../config/config'); // Assuming you have a config file
const router = express.Router();

/**
 * Handles user login and returns a JWT token.
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @returns {object} - The response object.
 */
router.post('/login', async (req, res) => {
  try {
    const user = await passport.authenticate('local', {
      onSuccess: (user, info) => {
        const token = jwt.sign({ id: user._id, username: user.username }, config.jwtSecret, {
          expiresIn: '1h' // Token expires in 1 hour
        });
        return res.json({ token });
      },
      onFailure: (err, info) => {
        return res.status(401).json({ message: 'Login failed' });
      }
    })(req, res);

  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

/**
 * Handles login failed attempts.
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @returns {object} - The response object.
 */
router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));

/**
 * Handles successful login and redirects to home.  Not used with JWT.
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @returns {object} - The response object.
 */
router.get('/home', (req, res) => res.send('Welcome!'));

module.exports = router;