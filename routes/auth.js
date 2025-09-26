const express = require('express');
const passport = require('passport');
const router = express.Router();

/**
 * config/passport.js
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const bcrypt = require('bcrypt');

module.exports = {
  /**
   * @description LocalStrategy for JWT authentication
   * @param {string} username
   * @param {string} password
   * @param {(err, user) => void} done
   * @return {void}
   */
  async localStrategy(username, password, done) {
    const user = await User.findOne({ username });
    if (!user) return done(null, false);

    const isValid = await bcrypt.compare(password, user.password);

    // If the credentials are valid, generate a JWT token and send it as a response
    if (isValid) {
      const payload = { id: user._id };
      jwt.sign(payload, 'your_secret_key', { expiresIn: '1h' }, (err, token) => {
        if (err) return done(err);
        res.json({ token });
        done(null, true); // Indicate successful authentication
      });
    } else {
      done(null, false);
    }
  },
};
/**
 * auth.js
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const authenticate = require('./middleware/authenticate');
const router = express.Router();

router.post('/login', async (req, res) => {
  // Call the modified LocalStrategy function from config/passport.js to handle authentication
});

// Protect routes with the authenticate middleware
router.get('/home', authenticate, (req, res) => res.send('Welcome!'));
/**
 * middleware/authenticate.js
 */

const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
  // Extract the token from the Authorization header
  const token = req.header('x-auth-token');

  if (!token) return res.status(401).send('Access denied. No token provided.');

  try {
    // Verify the JWT token and decode it
    const verified = jwt.verify(token, 'your_secret-key');
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid token.');
  }
};;

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', (req, res) => res.send('Welcome!'));

module.exports = router;