const jwt = require('jsonwebtoken');

module.exports = {
  secret: process.env.JWT_SECRET,
  signToken: (payload) => jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }),
  verifyToken: (token) => jwt.verify(token, process.env.JWT_SECRET)
};