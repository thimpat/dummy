const jwt = require('jsonwebtoken');

// Secret key for JWT (should be in environment variables in production)
const JWT_SECRET = 'your-secret-key-here';

module.exports = {
  JWT_SECRET,
  generateToken: (user) => {
    return jwt.sign({ username: user.username, id: user._id }, JWT_SECRET, { expiresIn: '1h' });
  },
  verifyToken: (token) => {
    return jwt.verify(token, JWT_SECRET);
  }
};