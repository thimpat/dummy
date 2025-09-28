const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

module.exports = {
  signToken: async (user) => {
    const token = await jwt.sign({ id: user.id }, process.env.JWT_SECRET_KEY);
    return token;
  },
  
  verifyToken: async (token) => {
    try {
      return jwt.verify(token, process.env.JWT_SECRET_KEY);
    } catch (err) {
      throw new Error('Invalid or expired token');
    }
  }
};