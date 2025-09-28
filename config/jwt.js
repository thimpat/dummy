const jwt = require('jsonwebtoken');
const secretKey = 'your_secret_key';

module.exports.createToken = (userId) => {
  return new Promise((resolve, reject) => {
    const payload = { userId };
    jwt.sign(payload, secretKey, { expiresIn: '1h' }, (err, token) => {
      if (err) {
        console.error('Failed to create JWT token:', err);
        reject(err);
      } else {
        resolve(token);
      }
    });
  });
};

module.exports.verifyToken = (token) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        console.error('Failed to verify JWT token:', err);
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
};