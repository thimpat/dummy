const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = {
  authMiddleware: (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.sendStatus(403);

    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, process.env.JWT_SECRET_KEY, async (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = await User.findById(user.id).select('-password');
      next();
    });
  }
};