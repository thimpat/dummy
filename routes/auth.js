const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const router = express.Router();
require('../config/passport'); // Import the Passport configuration file

router.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(401).send('Invalid credentials');
  }

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
  res.cookie('token', token, { httpOnly: true }).json({
    id: user.id,
    username: user.username
  });
});

router.get('/home', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).send('Unauthorized');
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
    if (err || decodedToken.userId !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json({ message: 'Welcome!' });
  });
});

module.exports = router;