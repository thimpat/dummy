const { authenticateJWT } = require('../models/User');

const authMiddleware = (req, res, next) => {
  authenticateJWT(req, res, () => {
    if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
    // Custom middleware logic can be added here
    console.log('Authenticated user:', req.user);
    next();
  });
};

module.exports = authMiddleware;