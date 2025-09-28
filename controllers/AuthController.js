const jwt = require('../config/jwt');
const User = require('../models/User');

module.exports = {
  login: async (req, res) => {
    const user = await User.findOne({ username: req.body.username }).select('-password');
    if (!user) return res.status(401).send('Invalid credentials');

    const token = jwt.sign(user.id.toString(), process.env.JWT_SECRET_KEY);
    res.json({ token });
  },

  logout: async (req, res) => {
    await req.user.logout();
    res.sendStatus(200);
  }
};