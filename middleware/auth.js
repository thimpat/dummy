const jwt = require('../config/jwt');

module.exports.checkAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).send({ message: 'No token provided' });

  try {
    const decoded = jwt.verifyToken(authHeader.split(' ')[1]);
    req.user = await User.findById(decoded.userId);
    next();
  } catch (error) {
    res.status(403).send({ message: error.message || 'Forbidden request' });
  }
};