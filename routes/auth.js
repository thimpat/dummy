const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken'); // Import JWT package
const router = express.Router();

// Middleware to verify token and ensure auth for protected routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token === null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

router.post('/login', passport.authenticate('local', {
  successRedirect: '/home',
  failureRedirect: '/auth/login-failed'
}));

router.get('/logout', authenticateToken, (req, res) => {
  jwt.sign({ id: req.user.id }, process.env.ACCESS_TOKEN_SECRET, (err, token) => {
    if (err) throw err;
    res.status(200).send(`Logout successful. Here is your JWT: ${token}`);
  });
});

router.get('/home', authenticateToken, (req, res) => res.send('Welcome!'));

module.exports = router;