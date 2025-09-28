const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const config = require('../config/config');
const User = require('../models/User');

/**
 * Router for authentication-related endpoints.
 * @type {express.Router}
 */
const router = express.Router();

/**
 * Login endpoint that authenticates the user and returns a JWT.
 * @route POST /auth/login
 * @param {object} req Express request object.
 * @param {object} res Express response object.
 * @returns {Promise<void>}
 */
router.post('/login', async (req, res) => {
  try {
    const user = req.user; // The user object is populated by passport

    const token = jwt.sign({ id: user._id, username: user.username }, config.jwtSecret, {
      expiresIn: '1h' // Token expiration time
    });

    res.status(200).json({ token });
  } catch (error) {
    console.error('Error generating token:', error);
    res.status(500).json({ message: 'Failed to generate token' });
  }
});

/**
 * Endpoint to test if the auth is working.
 * @route GET /auth/test
 * @param {object} req Express request object.
 * @param {object} res Express response object.
 * @returns {Promise<void>}
 */
router.get('/test', (req, res) => {
  if (req.user) {
    res.json({ message: 'Authenticated user', user: req.user });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

module.exports = router;