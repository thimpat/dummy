const jwt = require('jsonwebtoken');
const secretKey = 'your_jwt_secret_key';

function generateToken(userId) {
  return jwt.sign({ userId }, secretKey, { expiresIn: '1h' });
}

module.exports = {
  generateToken,
};