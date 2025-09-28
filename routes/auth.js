const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const router = express.Router();
const User = require('../models/User');

router.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    
    if (!user) {
      return res.status(401).send('User not found');
    }

    const isPasswordValid = await bcrypt.compare(req.body.password, user.password);

    if (!isPasswordValid) {
      return res.status(401).send('Invalid password');
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '2h' });

    res.json({
      message: 'Login successful',
      token
    });
  } catch (error) {
    console.error(error);
    return res.status(500).send('Internal server error');
  }
});

router.get('/home', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.send('Welcome! You are authenticated.');
});

module.exports = router;