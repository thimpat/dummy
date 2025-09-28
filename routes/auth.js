const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const passport = require('passport');
const router = express.Router();

// Secret key to sign the JWT tokens
const secretKey = 'your_secret_key';

router.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });

  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user._id }, secretKey);

  res.json({ token });
});

router.get('/home', (req, res) => {
  // Check if the request contains a valid JWT
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  jwt.verify(token, secretKey, (err, user) => {
    if (err || !user) {
      return res.status(403).json({ error: 'JWT verification failed' });
    }

    // Assuming the User model has a property `isAuthenticated` indicating whether JWT is used
    const isAuthenticated = req.isAuthenticated();
    if (!isAuthenticated && user.isAuthenticated === true) {
      req.login(user, err => {
        if (err) return res.status(403).json({ error: 'Failed to authenticate' });
        return res.json({ message: 'Welcome back!' });
      });
    } else {
      return res.json({ message: 'Welcome back!' });
    }
  });

  // Normally you would have some logic here, such as checking if the JWT is valid and belongs to this request
});

module.exports = router;