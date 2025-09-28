const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

userSchema.pre('save', async function () {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
});

module.exports = mongoose.model('User', userSchema);

// Helper method to authenticate a JWT token
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No authentication header provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decodedToken = jwt.verify(token, 'SECRET_KEY_FOR_JWT');
    req.user = decodedToken;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid authentication header' });
  }
};

module.exports.authenticateJWT = authenticateJWT;