const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken'); // Import JWT library for token generation and verification

const router = express.Router();

// Helper function to generate a JWT token
function generateToken(user) {
  return new Promise((resolve, reject) => {
    const payload = { id: user.id };
    jwt.sign(payload, 'SECRET_KEY_FOR_JWT', { expiresIn: '1h' }, (err, token) => {
      if (err) reject(err);
      resolve(token);
    });
  });
}

// Helper function to verify JWT token
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, 'SECRET_KEY_FOR_JWT', (err, user) => {
    if (err) return res.status(403).json({ message: 'Token is not valid' });
    req.user = user;
    next();
  });
}

router.post('/login', passport.authenticate('local', { failureRedirect: '/auth/login-failed' }), async (req, res) => {
  const user = await User.findOne({ username: req.body.username }).select('+password'); // Assuming this is the method to authenticate a local login
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) return res.status(401).json({ message: 'Invalid credentials' });

  const token = await generateToken(user);
  res.json({
    success: true,
    token: `Bearer ${token}`
  });
});

router.get('/home', verifyToken, (req, res) => {
  res.send('Welcome! You are now authenticated via JWT.');
});

module.exports = router;