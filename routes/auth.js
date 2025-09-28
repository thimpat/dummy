const express = require('express');
const passport = require('passport');
const router = express.Router();
const jwt = require('jsonwebtoken');

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Authenticate the user using Passport or any other method
  let user;
  if (process.env.NODE_ENV === 'test') {
    user = await User.findOne({ username });
  } else {
    user = await User.findByUsername(username);
  }

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).send('Invalid credentials');
  }
  
  // Generate a JWT
  const token = jwt.sign(user._id.toString(), process.env.JWT_SECRET);

  res.send({ auth: true, token });
});

router.get('/home', (req, res) => {
  if (!req.authToken) {
    return res.status(401).send('Unauthorized');
  }

  // Verify the JWT
  const decoded = jwt.verify(req.authToken, process.env.JWT_SECRET);
  User.findById(decoded.id)
    .then(user => res.send(`Welcome, ${user.username}!`))
    .catch(err => res.status(500).send('Server error'));
});

module.exports = router;