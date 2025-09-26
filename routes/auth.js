const express = require('express');
const passport = require('passport');
const router = express.Router();

router.post('/login', passport.authenticate('local', {
  successRedirect: '/home',
  failureRedirect: '/auth/login-failed'
}));

router.get('/login-failed', (req, res) => res.status(401).send('Login failed'));
router.get('/home', (req, res) => res.send('Welcome!'));

module.exports = router;

// PATCHED: Import jwt package in auth.js
/**
 * @description Authentication API
 */
const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');

/**
 * @description Login route with JWT support
 * @param {object} req - Request object
 * @param {object} res - Response object
 * @return {void}
 */
router.post('/login', passport.authenticate('local'), async (req, res) => {
  const user = req.user;
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

module.exports = router;
/**
 * @description Passport authentication configuration
 */
const passport = require('passport');
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;

passport.use(
  new JWTStrategy(
    {
      // Extract the token from the Authorization header
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
      algorithms: ['HS256']
    },
    (decoded, done) => {
      // Perform any necessary authentication checks here
      // ...
      done(null, decoded);
    }
  )
);

module.exports = passport;

// PATCHED: Update login route in auth.js to generate and return a JWT token
/**
 * @description Authentication API
 */
const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');

/**
 * @description Login route with JWT support
 * @param {object} req - Request object
 * @param {object} res - Response object
 * @return {void}
 */
router.post('/login', passport.authenticate('local'), async (req, res) => {
  const user = req.user;
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

module.exports = router;
/**
 * @description Passport authentication configuration
 */
const passport = require('passport');
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;

passport.use(
  new JWTStrategy(
    {
      // Extract the token from the Authorization header
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
      algorithms: ['HS256']
    },
    (decoded, done) => {
      // Perform any necessary authentication checks here
      // ...
      done(null, decoded);
    }
  )
);

module.exports = passport;

// PATCHED: Update home route to check for and verify JWT token
/**
 * @description Authentication API
 */
const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');

/**
 * @description Login route with JWT support
 * @param {object} req - Request object
 * @param {object} res - Response object
 * @return {void}
 */
router.post('/login', passport.authenticate('local'), async (req, res) => {
  const user = req.user;
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

module.exports = router;
/**
 * @description Passport authentication configuration
 */
const passport = require('passport');
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;

passport.use(
  new JWTStrategy(
    {
      // Extract the token from the Authorization header
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
      algorithms: ['HS256']
    },
    (decoded, done) => {
      // Perform any necessary authentication checks here
      // ...
      done(null, decoded);
    }
  )
);

module.exports = passport;