const jwt = require('jsonwebtoken');

function generateToken(userId) {
  return jwt.sign({
    userId
  }, 'secret_key', { expiresIn: '1h' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, 'secret_key');
  } catch (error) {
    return null;
  }
}

module.exports = { generateToken, verifyToken };