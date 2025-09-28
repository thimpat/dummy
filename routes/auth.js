const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken'); // Import JWT module
const router = express.Router();

// Middleware to protect certain routes based on authenticated users
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(403); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

router.post('/login', passport.authenticate('local'), async (req, res) => {
  const token = jwt.sign({ username: req.body.username }, process.env.JWT_SECRET, { expiresIn: '2h' }); // Generate JWT
  res.status(200).send({ token });
});

// Example protected route using the authenticateToken middleware
router.get('/protected', authenticateToken, (req, res) => {
  res.send(`Hello ${req.user.username}! This is a protected route.`);
});

module.exports = router;