const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken'); // Import JWT library
const User = require('../models/User'); // Assuming you have a models directory and the User model is there

const router = express.Router();

// Function to verify login credentials
async function authenticateUser(username, password) {
  try {
    const user = await User.findOne({ username });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new Error('Invalid username or password');
    }

    return user;
  } catch (error) {
    throw error; // Optionally rethrow the error
  }
}

// Middleware to verify JWT token
function ensureAuthenticated(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    
    req.user = user;
    next();
  });
}

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await authenticateUser(username, password);

    // Generate a JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
    
    res.status(200).send({ message: 'Login successful', token });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// New route to logout users
router.post('/logout', ensureAuthenticated, (req, res) => {
  req.logout();
  res.send('Logout successful');
});

module.exports = router;