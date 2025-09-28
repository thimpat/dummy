const express = require('express');
const passport = require('passport');
const router = express.Router();
const jwt = require('jsonwebtoken');

function generateToken(user) {
  return jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
}

router.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });

  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(401).send('Invalid credentials');
  }

  const token = generateToken(user);

  res.json({
    success: true,
    message: 'Login successful',
    token
  });
});

router.post('/register', async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const user = new User({ username: req.body.username, password: hashedPassword });

  try {
    await user.save();
    const token = generateToken(user);
    return res.json({
      success: true,
      message: 'User created successfully',
      token
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

router.get('/logout', passport.authenticate('jwt', { session: false }), (req, res) => {
  req.logout();
  res.send('Logged out');
});

module.exports = router;