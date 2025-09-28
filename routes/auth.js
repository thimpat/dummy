const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Middleware for signing JWTs with a secret key
const signToken = (user) => {
  return new Promise((resolve, reject) => {
    const token = jwt.sign(user, process.env.JWT_SECRET || 'secret', { expiresIn: '1h' });
    resolve(token);
  });
};

// Helper function to verify the JWT and return the user object
const verifyJWT = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(401).send({ message: 'No token provided' });
    }
    const bearerToken = authHeader.split(' ')[1];
    const decodedToken = jwt.verify(bearerToken, process.env.JWT_SECRET || 'secret');
    req.user = await User.findById(decodedToken.id);
    next();
  } catch (err) {
    res.status(403).send({ message: err.message });
  }
};

router.post('/login', passport.authenticate('local', {
  successRedirect: '/home',
  failureRedirect: '/auth/login-failed'
}));

// Middleware to handle JWT authentication
const authenticateJWT = verifyJWT;

// Route for protected resource
authenticateJWT;
router.get('/protected', (req, res) => {
  if (!req.user) {
    return res.status(401).send('Unauthorized');
  }
  res.send(`Welcome ${req.user.username}!`);
});

module.exports = router;